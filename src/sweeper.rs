//! The periodic sweeper: expires files past `expires_at`, retries entries
//! stuck `ending`, and deletes old tombstones (`Store::sweep` does the
//! actual work; see its docs for the five-step ending protocol), then
//! emits the Telemetry section's sweep-time metrics.
//!
//! Tests drive real sweeps by calling `run_once` directly against a
//! controlled `TestClock`, rather than waiting on the 60s timer.

use std::time::Duration;

use tokio::task::JoinHandle;

use crate::app::AppState;

/// How often `spawn` runs the sweep, per the spec.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Runs `Store::sweep` on a fixed interval.
pub struct Sweeper {
    state: AppState,
}

impl Sweeper {
    /// Builds a sweeper over `state`'s store.
    pub fn new(state: AppState) -> Sweeper {
        Sweeper { state }
    }

    /// Runs one sweep pass: `Store::sweep`, then the metrics it feeds.
    ///
    /// `expired_undownloaded` fires once per file this sweep expired that
    /// was never downloaded, skipping files startup recovery loaded (their
    /// first-download time is unknown). `tombstones_evicted` fires only
    /// when this sweep evicted any, since links dying early is itself the
    /// signal worth a counter and a warning. Every counter here is paired
    /// with a readable log line (not just the metric event's own `metric`
    /// line); the gauges that follow are not, per the spec.
    pub async fn run_once(&self) {
        let obs = &self.state.obs;
        let report = self.state.store.sweep().await;

        let mut undownloaded = 0usize;
        for file in &report.expired {
            if !file.downloaded && !file.loaded_at_startup {
                obs.counter("expired_undownloaded", &[("agent", &file.uploader)], 1);
                undownloaded += 1;
            }
        }
        if undownloaded > 0 {
            tracing::info!(
                count = undownloaded,
                "sweep expired files that were never downloaded"
            );
        }

        if report.tombstones_evicted > 0 {
            obs.counter("tombstones_evicted", &[], report.tombstones_evicted as u64);
            tracing::warn!(
                count = report.tombstones_evicted,
                "sweep evicted tombstones past max_tombstones; links are dying sooner than promised"
            );
        }

        let stats = self.state.store.stats();
        for (agent, bytes) in &stats.per_agent_bytes {
            obs.gauge("stored_bytes", &[("agent", agent)], *bytes as f64);
        }
        obs.gauge(
            "stored_bytes",
            &[("agent", "total")],
            stats.total_bytes as f64,
        );
        obs.gauge("live_files", &[], stats.live_files as f64);
        obs.gauge("tombstones", &[], stats.tombstones as f64);
        obs.gauge(
            "uploads_in_flight",
            &[],
            self.state.limits.uploads_in_flight() as f64,
        );
        obs.gauge(
            "downloads_in_flight",
            &[],
            self.state.limits.downloads_in_flight() as f64,
        );
    }

    /// Spawns a task that calls `run_once` every 60 seconds.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                interval.tick().await;
                self.run_once().await;
            }
        })
    }
}
