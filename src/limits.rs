//! Upload rate limiting and concurrency caps.
//!
//! All state lives in memory behind one `Mutex<LimitsInner>` and resets on
//! restart, per the spec. `try_upload` and `try_download` check and
//! increment their counters under a single lock acquisition each, so a
//! racing caller never observes a count between the check and the
//! increment.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::StatusCode;

use crate::client_ip::ClientKey;
use crate::config::Config;
use crate::obs::Outcome;

/// A rejection from a limiter: the status and `Retry-After` to send, and
/// the metric outcome and `throttled` reason to record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Throttle {
    pub status: StatusCode,
    pub outcome: Outcome,
    pub reason: &'static str,
    pub retry_after_secs: u64,
}

/// A per-agent token bucket for the upload rate limit: capacity
/// `upload_rate`, refilling continuously at `upload_rate` per minute.
#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(upload_rate: u32, now: Instant) -> TokenBucket {
        TokenBucket {
            capacity: upload_rate as f64,
            tokens: upload_rate as f64,
            refill_per_sec: upload_rate as f64 / 60.0,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Takes one token if available. On failure, returns the number of
    /// seconds until the next token is available.
    fn try_take(&mut self, now: Instant) -> Result<(), f64> {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err((1.0 - self.tokens) / self.refill_per_sec)
        }
    }
}

#[derive(Debug)]
struct LimitsInner {
    uploads_total: usize,
    uploads_per_agent: HashMap<String, usize>,
    downloads_total: usize,
    downloads_per_key: HashMap<ClientKey, usize>,
    rate_buckets: HashMap<String, TokenBucket>,
}

/// Upload rate and concurrency limiter state, built once from `Config` and
/// shared behind an `Arc` by every handler.
#[derive(Debug)]
pub struct Limits {
    inner: Mutex<LimitsInner>,
    max_concurrent_uploads: usize,
    max_uploads_per_agent: usize,
    max_concurrent_downloads: usize,
    max_downloads_per_ip: usize,
    upload_rate: u32,
}

/// Holds one upload's per-agent and server-wide concurrency slots; releases
/// both on drop.
#[derive(Debug)]
pub struct UploadSlot {
    limits: Arc<Limits>,
    agent: String,
}

impl Drop for UploadSlot {
    fn drop(&mut self) {
        let mut inner = self.limits.inner.lock().expect("Limits mutex poisoned");
        inner.uploads_total = inner.uploads_total.saturating_sub(1);
        if let Some(count) = inner.uploads_per_agent.get_mut(&self.agent) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.uploads_per_agent.remove(&self.agent);
            }
        }
    }
}

/// Holds one download's per-client-key and server-wide concurrency slots;
/// releases both on drop, removing the key's table entry once its count
/// reaches zero.
#[derive(Debug)]
pub struct DownloadSlot {
    limits: Arc<Limits>,
    key: ClientKey,
}

impl Drop for DownloadSlot {
    fn drop(&mut self) {
        let mut inner = self.limits.inner.lock().expect("Limits mutex poisoned");
        inner.downloads_total = inner.downloads_total.saturating_sub(1);
        if let Some(count) = inner.downloads_per_key.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.downloads_per_key.remove(&self.key);
            }
        }
    }
}

impl Limits {
    /// Builds limiter state from the resolved config. Callers wrap this in
    /// an `Arc` so guards can hold a reference back to it.
    pub fn new(cfg: &Config) -> Limits {
        Limits {
            inner: Mutex::new(LimitsInner {
                uploads_total: 0,
                uploads_per_agent: HashMap::new(),
                downloads_total: 0,
                downloads_per_key: HashMap::new(),
                rate_buckets: HashMap::new(),
            }),
            max_concurrent_uploads: cfg.max_concurrent_uploads,
            max_uploads_per_agent: cfg.max_uploads_per_agent,
            max_concurrent_downloads: cfg.max_concurrent_downloads,
            max_downloads_per_ip: cfg.max_downloads_per_ip,
            upload_rate: cfg.upload_rate,
        }
    }

    /// Checks and reserves one upload slot for `agent`: per-agent first
    /// (`429`, `uploads_per_agent`), then server-wide (`503`,
    /// `uploads_total`). Both checks and the increment happen under one
    /// lock acquisition.
    pub fn try_upload(self: &Arc<Self>, agent: &str) -> Result<UploadSlot, Throttle> {
        let mut inner = self.inner.lock().expect("Limits mutex poisoned");

        let per_agent = inner.uploads_per_agent.get(agent).copied().unwrap_or(0);
        if per_agent >= self.max_uploads_per_agent {
            return Err(Throttle {
                status: StatusCode::TOO_MANY_REQUESTS,
                outcome: Outcome::Busy,
                reason: "uploads_per_agent",
                retry_after_secs: 1,
            });
        }
        if inner.uploads_total >= self.max_concurrent_uploads {
            return Err(Throttle {
                status: StatusCode::SERVICE_UNAVAILABLE,
                outcome: Outcome::Busy,
                reason: "uploads_total",
                retry_after_secs: 1,
            });
        }

        inner.uploads_total += 1;
        *inner
            .uploads_per_agent
            .entry(agent.to_string())
            .or_insert(0) += 1;
        drop(inner);

        Ok(UploadSlot {
            limits: Arc::clone(self),
            agent: agent.to_string(),
        })
    }

    /// Spends one token from `agent`'s upload-rate bucket. On empty,
    /// returns `429`/`upload_rate` with `retry_after_secs` set to the
    /// ceiling of the seconds until the next token, minimum 1.
    pub fn try_rate(&self, agent: &str) -> Result<(), Throttle> {
        let mut inner = self.inner.lock().expect("Limits mutex poisoned");
        let now = Instant::now();
        let upload_rate = self.upload_rate;
        let bucket = inner
            .rate_buckets
            .entry(agent.to_string())
            .or_insert_with(|| TokenBucket::new(upload_rate, now));

        match bucket.try_take(now) {
            Ok(()) => Ok(()),
            Err(seconds_to_next) => {
                let retry_after_secs = (seconds_to_next.ceil() as u64).max(1);
                Err(Throttle {
                    status: StatusCode::TOO_MANY_REQUESTS,
                    outcome: Outcome::RateLimited,
                    reason: "upload_rate",
                    retry_after_secs,
                })
            }
        }
    }

    /// Checks and reserves one download slot for `key`: per-key first
    /// (`429`, `downloads_per_ip`), then server-wide (`503`,
    /// `downloads_total`). Both checks and the increment happen under one
    /// lock acquisition; `key` is inserted into the per-key table only when
    /// both checks pass.
    pub fn try_download(self: &Arc<Self>, key: ClientKey) -> Result<DownloadSlot, Throttle> {
        let mut inner = self.inner.lock().expect("Limits mutex poisoned");

        let per_key = inner.downloads_per_key.get(&key).copied().unwrap_or(0);
        if per_key >= self.max_downloads_per_ip {
            return Err(Throttle {
                status: StatusCode::TOO_MANY_REQUESTS,
                outcome: Outcome::Busy,
                reason: "downloads_per_ip",
                retry_after_secs: 1,
            });
        }
        if inner.downloads_total >= self.max_concurrent_downloads {
            return Err(Throttle {
                status: StatusCode::SERVICE_UNAVAILABLE,
                outcome: Outcome::Busy,
                reason: "downloads_total",
                retry_after_secs: 1,
            });
        }

        inner.downloads_total += 1;
        *inner.downloads_per_key.entry(key).or_insert(0) += 1;
        drop(inner);

        Ok(DownloadSlot {
            limits: Arc::clone(self),
            key,
        })
    }

    /// The current number of reserved upload slots, server-wide.
    pub fn uploads_in_flight(&self) -> usize {
        self.inner
            .lock()
            .expect("Limits mutex poisoned")
            .uploads_total
    }

    /// The current number of reserved download slots, server-wide.
    pub fn downloads_in_flight(&self) -> usize {
        self.inner
            .lock()
            .expect("Limits mutex poisoned")
            .downloads_total
    }

    /// The number of distinct client keys currently holding a download
    /// slot. Bounded by `max_concurrent_downloads`, since an entry exists
    /// only while that key has downloads in progress.
    pub fn download_keys(&self) -> usize {
        self.inner
            .lock()
            .expect("Limits mutex poisoned")
            .downloads_per_key
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    fn limits_with(f: impl FnOnce(&mut Config)) -> Arc<Limits> {
        let mut cfg = Config::for_tests(PathBuf::from("/tmp"));
        f(&mut cfg);
        Arc::new(Limits::new(&cfg))
    }

    #[test]
    fn upload_per_agent_then_global() {
        let limits = limits_with(|cfg| {
            cfg.max_uploads_per_agent = 2;
            cfg.max_concurrent_uploads = 3;
        });

        let _a1 = limits.try_upload("a").expect("first a upload ok");
        let _a2 = limits.try_upload("a").expect("second a upload ok");

        let rejected = limits
            .try_upload("a")
            .expect_err("third a upload throttled");
        assert_eq!(rejected.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rejected.outcome, Outcome::Busy);
        assert_eq!(rejected.reason, "uploads_per_agent");

        let _b1 = limits.try_upload("b").expect("b upload ok");

        let rejected = limits
            .try_upload("c")
            .expect_err("c upload hits global cap");
        assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejected.outcome, Outcome::Busy);
        assert_eq!(rejected.reason, "uploads_total");
    }

    #[test]
    fn upload_slot_drop_releases() {
        let limits = limits_with(|_| {});

        let slot = limits.try_upload("a").expect("upload ok");
        assert_eq!(limits.uploads_in_flight(), 1);

        drop(slot);
        assert_eq!(limits.uploads_in_flight(), 0);
    }

    #[test]
    fn rate_bucket_empties_and_reports_retry_after() {
        let limits = limits_with(|cfg| {
            cfg.upload_rate = 2;
        });

        limits.try_rate("a").expect("first token ok");
        limits.try_rate("a").expect("second token ok");

        let rejected = limits.try_rate("a").expect_err("bucket empty");
        assert_eq!(rejected.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rejected.outcome, Outcome::RateLimited);
        assert_eq!(rejected.reason, "upload_rate");
        assert!(
            (1..=30).contains(&rejected.retry_after_secs),
            "retry_after_secs {} not in 1..=30",
            rejected.retry_after_secs
        );
    }

    #[test]
    fn download_key_table_bounded() {
        let limits = limits_with(|cfg| {
            cfg.max_concurrent_downloads = 1;
        });

        let first_key = ClientKey::from_ip("203.0.113.1".parse().unwrap());
        let _first = limits.try_download(first_key).expect("first key ok");

        for i in 0..100u32 {
            let other_ip = format!("203.0.113.{}", 2 + i % 250);
            let other_key = ClientKey::from_ip(other_ip.parse().unwrap());
            let rejected = limits
                .try_download(other_key)
                .expect_err("global cap reached");
            assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(rejected.outcome, Outcome::Busy);
            assert_eq!(rejected.reason, "downloads_total");
        }

        assert_eq!(limits.download_keys(), 1);
    }

    #[test]
    fn download_slot_drop_removes_key() {
        let limits = limits_with(|_| {});

        let key = ClientKey::from_ip("203.0.113.1".parse().unwrap());
        let slot = limits.try_download(key).expect("download ok");
        assert_eq!(limits.download_keys(), 1);

        drop(slot);
        assert_eq!(limits.download_keys(), 0);
    }
}
