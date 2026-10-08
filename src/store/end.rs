//! Ending a file (revoke and expiry) and the periodic sweep.
//!
//! Both follow the spec's five-step protocol:
//!
//! 1. Under the lock, flip the entry `Live` → `Ending`, record the target
//!    state and `ended_at` in its `Meta`, and release its quota bytes and
//!    file slot (`Index::begin_ending`). Only a `Live` entry can be flipped,
//!    so exactly one of any racing revokes and sweeps wins.
//! 2. Revoke only: fire the cancellation token, aborting downloads.
//! 3. Write the `.json` with the final state and `ended_at`.
//! 4. Unlink the blob (ENOENT counts as success) and fsync `files/`.
//! 5. Under the lock, set the entry to its final state.
//!
//! If step 3 or 4 fails the entry stays `Ending`; the sweep retries steps
//! 3–5 once it has been ending for over 60 seconds.

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use super::{disk, is_valid_id, whole_seconds, End, Index, Meta, State, Store};

/// The sweep retries an entry once it has been `Ending` this long.
const ENDING_RETRY_AFTER: Duration = Duration::from_secs(60);

/// The result of `Store::revoke`, in the order the checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// Malformed or unknown id, or urlname mismatch (`404`).
    NotFound,
    /// The file belongs to another agent (`403`).
    Forbidden,
    /// Already ending, expired, or revoked, or past `expires_at` (`410`).
    Gone,
    /// Revoked, with the final state on disk (`204`).
    Revoked,
    /// Writing the final state or unlinking the blob failed (`500`). The
    /// link is dead in memory; the sweep finishes the job later.
    Failed,
}

/// What one `Store::sweep` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Files this sweep moved from live to expired; each file appears in
    /// exactly one report.
    pub expired: Vec<ExpiredFile>,
    /// Entries stuck `ending` for over 60 s whose steps 3–5 this sweep
    /// retried.
    pub retried: usize,
    /// Tombstones removed because `ended_at + tombstone_ttl` had passed.
    pub tombstones_deleted: usize,
    /// Oldest tombstones removed to get back under `max_tombstones`.
    pub tombstones_evicted: usize,
}

/// A file the sweep expired, for the `expired_undownloaded` metric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredFile {
    pub uploader: String,
    /// True if the file was downloaded since this process loaded it.
    pub downloaded: bool,
    /// True if startup recovery loaded the file, so whether it was ever
    /// downloaded is unknown.
    pub loaded_at_startup: bool,
}

impl Index {
    /// Ending step 1: flips `id` from `Live` to `Ending(end)`, records the
    /// target state and `ended_at` in its `Meta`, and releases its quota.
    /// Returns the metadata to write, or `None` if the entry is not live.
    fn begin_ending(&mut self, id: &str, end: End, ended_at: SystemTime) -> Option<Meta> {
        let entry = self.entries.get_mut(id)?;
        if entry.state != State::Live {
            return None;
        }
        entry.state = State::Ending(end);
        entry.meta.state = end.disk_state();
        entry.meta.ended_at = Some(ended_at);
        entry.ending_since = Some(Instant::now());
        let meta = entry.meta.clone();
        self.release_live(&meta.uploader, meta.size);
        Some(meta)
    }
}

impl Store {
    /// Revokes `id` on behalf of `agent`. Checks run in order: `NotFound`
    /// (malformed or unknown id, or urlname mismatch), `Forbidden` (another
    /// uploader), `Gone` (not live), then the ending protocol. `Revoked`
    /// means the final state is on disk; `Failed` means step 3 or 4 failed
    /// and the entry stays `ending`.
    pub async fn revoke(&self, id: &str, urlname: &str, agent: &str) -> RevokeOutcome {
        if !is_valid_id(id) {
            return RevokeOutcome::NotFound;
        }
        let now = self.clock.now();
        let (meta, cancel) = {
            let mut idx = self.index();
            let Some(entry) = idx.entries.get(id) else {
                return RevokeOutcome::NotFound;
            };
            if entry.meta.urlname != urlname {
                return RevokeOutcome::NotFound;
            }
            if entry.meta.uploader != agent {
                return RevokeOutcome::Forbidden;
            }
            if now >= entry.meta.expires_at {
                return RevokeOutcome::Gone;
            }
            let cancel = entry.cancel.clone();
            let Some(meta) = idx.begin_ending(id, End::Revoked, whole_seconds(now)) else {
                return RevokeOutcome::Gone;
            };
            (meta, cancel)
        };
        cancel.cancel();
        match self.finish_ending(&meta, End::Revoked).await {
            Ok(()) => RevokeOutcome::Revoked,
            Err(e) => {
                tracing::warn!(
                    id = &id[..8],
                    error = %e,
                    "revoke could not finish; the sweep will retry"
                );
                RevokeOutcome::Failed
            }
        }
    }

    /// Ending steps 3–5 for `meta`, which already carries the final state
    /// and `ended_at`. Safe to repeat: the write replaces the `.json`
    /// atomically and a missing blob counts as unlinked.
    async fn finish_ending(&self, meta: &Meta, end: End) -> io::Result<()> {
        self.write_meta(meta).await?;
        let blob = self.blob_path(&meta.id);
        let files_dir = self.files_dir.clone();
        tokio::task::spawn_blocking(move || {
            disk::remove_file_if_exists(&blob)?;
            disk::fsync_dir(&files_dir)
        })
        .await
        .map_err(io::Error::other)??;
        let mut idx = self.index();
        if let Some(entry) = idx.entries.get_mut(&meta.id) {
            if entry.state == State::Ending(end) {
                entry.state = end.final_state();
                entry.ending_since = None;
            }
        }
        Ok(())
    }

    /// One expiry pass, run every 60 seconds by the sweeper:
    ///
    /// 1. retries steps 3–5 for entries `ending` for over 60 s;
    /// 2. ends every live entry past `expires_at` as expired, with
    ///    `ended_at = expires_at` (downloads in progress are not aborted);
    /// 3. deletes tombstones past `ended_at + tombstone_ttl`;
    /// 4. evicts the oldest tombstones (by `ended_at`) beyond
    ///    `max_tombstones`.
    pub async fn sweep(&self) -> SweepReport {
        let mut report = SweepReport::default();
        let now = self.clock.now();
        let (to_retry, to_expire) = {
            let mut idx = self.index();
            let mut to_retry = Vec::new();
            for entry in idx.entries.values_mut() {
                if let (State::Ending(end), Some(since)) = (entry.state, entry.ending_since) {
                    if since.elapsed() > ENDING_RETRY_AFTER {
                        // Claim it, so an overlapping sweep does not retry
                        // it again for another 60 s.
                        entry.ending_since = Some(Instant::now());
                        to_retry.push((entry.meta.clone(), end));
                    }
                }
            }
            let due: Vec<String> = idx
                .entries
                .values()
                .filter(|e| e.state == State::Live && now >= e.meta.expires_at)
                .map(|e| e.meta.id.clone())
                .collect();
            let mut to_expire = Vec::new();
            for id in due {
                let entry = &idx.entries[&id];
                let file = ExpiredFile {
                    uploader: entry.meta.uploader.clone(),
                    downloaded: entry.first_download.is_some(),
                    loaded_at_startup: entry.loaded_at_startup,
                };
                let ended_at = entry.meta.expires_at;
                if let Some(meta) = idx.begin_ending(&id, End::Expired, ended_at) {
                    report.expired.push(file);
                    to_expire.push(meta);
                }
            }
            (to_retry, to_expire)
        };

        for (meta, end) in &to_retry {
            report.retried += 1;
            if let Err(e) = self.finish_ending(meta, *end).await {
                tracing::warn!(id = &meta.id[..8], error = %e, "retrying an ending file failed");
            }
        }
        for meta in &to_expire {
            if let Err(e) = self.finish_ending(meta, End::Expired).await {
                tracing::warn!(id = &meta.id[..8], error = %e, "expiring a file failed; the sweep will retry");
            }
        }

        let ttl = self.cfg.tombstone_ttl;
        let past_window: Vec<String> = self
            .index()
            .entries
            .values()
            .filter(|e| {
                e.state.is_tombstone()
                    && e.meta
                        .ended_at
                        .and_then(|t| t.checked_add(ttl))
                        .is_some_and(|t| now >= t)
            })
            .map(|e| e.meta.id.clone())
            .collect();
        report.tombstones_deleted = self.remove_tombstones(past_window).await;

        let over_cap = {
            let idx = self.index();
            let mut tombstones: Vec<(Option<SystemTime>, &String)> = idx
                .entries
                .values()
                .filter(|e| e.state.is_tombstone())
                .map(|e| (e.meta.ended_at, &e.meta.id))
                .collect();
            let excess = tombstones.len().saturating_sub(self.cfg.max_tombstones);
            if excess > 0 {
                tombstones.sort_unstable();
                tombstones.truncate(excess);
            } else {
                tombstones.clear();
            }
            tombstones
                .into_iter()
                .map(|(_, id)| id.clone())
                .collect::<Vec<_>>()
        };
        report.tombstones_evicted = self.remove_tombstones(over_cap).await;
        report
    }

    /// Deletes the `.json` of each tombstone in `ids`, then drops it from
    /// the index so its id answers `404`. Returns how many it removed; a
    /// failed unlink leaves that tombstone for the next sweep.
    async fn remove_tombstones(&self, ids: Vec<String>) -> usize {
        if ids.is_empty() {
            return 0;
        }
        let paths: Vec<(String, PathBuf)> = ids
            .into_iter()
            .map(|id| {
                let path = self.meta_path(&id);
                (id, path)
            })
            .collect();
        let files_dir = self.files_dir.clone();
        let removed = tokio::task::spawn_blocking(move || {
            let mut removed = Vec::with_capacity(paths.len());
            for (id, path) in paths {
                match disk::remove_file_if_exists(&path) {
                    Ok(()) => removed.push(id),
                    Err(e) => {
                        tracing::warn!(id = &id[..8], error = %e, "failed to delete a tombstone");
                    }
                }
            }
            if let Err(e) = disk::fsync_dir(&files_dir) {
                tracing::warn!(error = %e, "failed to fsync files/ after deleting tombstones");
            }
            removed
        })
        .await
        .unwrap_or_default();

        let mut idx = self.index();
        let mut count = 0;
        for id in &removed {
            if idx.entries.get(id).is_some_and(|e| e.state.is_tombstone()) {
                idx.entries.remove(id);
                count += 1;
            }
        }
        count
    }

    /// Ids of all live entries, sorted.
    #[doc(hidden)]
    pub fn live_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .index()
            .entries
            .values()
            .filter(|e| e.state == State::Live)
            .map(|e| e.meta.id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Test hook: makes every `ending` entry look `by` older, so the sweep
    /// treats it as stuck.
    #[doc(hidden)]
    pub fn age_ending(&self, by: Duration) {
        let mut idx = self.index();
        for entry in idx.entries.values_mut() {
            if let (State::Ending(_), Some(since)) = (entry.state, entry.ending_since) {
                entry.ending_since = since.checked_sub(by).or(Some(since));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::fs;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

    use crate::clock::{Clock, TestClock};
    use crate::store::tests::{dir_entries, harness, upload, Harness};
    use crate::store::{DiskState, Lookup, Meta, Store};

    fn json_path(h: &Harness, id: &str) -> std::path::PathBuf {
        h.dir.path().join("files").join(format!("{id}.json"))
    }

    fn blob_path(h: &Harness, id: &str) -> std::path::PathBuf {
        h.dir.path().join("files").join(id)
    }

    fn on_disk(h: &Harness, id: &str) -> Meta {
        serde_json::from_slice(&fs::read(json_path(h, id)).expect("json exists")).expect("parses")
    }

    fn assert_send<T: Send>(_: &T) {}

    #[test]
    fn revoke_and_sweep_futures_are_send() {
        // The sweeper and handlers run these in spawned tasks, so no index
        // guard may be held across an `.await`.
        let h = harness(|_| {});
        let revoke = h.store.revoke("x", "y", "z");
        assert_send(&revoke);
        let sweep = h.store.sweep();
        assert_send(&sweep);
    }

    #[tokio::test]
    async fn revoke_order() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        let id = meta.id.as_str();
        let s = &h.store;

        assert_eq!(
            s.revoke(&crate::store::new_id(), "my_file.txt", "planner")
                .await,
            RevokeOutcome::NotFound
        );
        assert_eq!(
            s.revoke("XYZ", "my_file.txt", "planner").await,
            RevokeOutcome::NotFound
        );
        assert_eq!(
            s.revoke(id, "other.txt", "planner").await,
            RevokeOutcome::NotFound
        );
        // A urlname mismatch answers 404 before the uploader check.
        assert_eq!(
            s.revoke(id, "other.txt", "builder").await,
            RevokeOutcome::NotFound
        );
        assert_eq!(
            s.revoke(id, "my_file.txt", "builder").await,
            RevokeOutcome::Forbidden
        );

        h.clock.advance(Duration::from_secs(5));
        assert_eq!(
            s.revoke(id, "my_file.txt", "planner").await,
            RevokeOutcome::Revoked
        );
        assert_eq!(
            s.revoke(id, "my_file.txt", "planner").await,
            RevokeOutcome::Gone
        );
        // Another agent is still refused before the state check.
        assert_eq!(
            s.revoke(id, "my_file.txt", "builder").await,
            RevokeOutcome::Forbidden
        );

        assert!(!blob_path(&h, id).exists());
        let disk = on_disk(&h, id);
        assert_eq!(disk.state, DiskState::Revoked);
        assert_eq!(
            disk.ended_at,
            Some(meta.created_at + Duration::from_secs(5))
        );
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(json_path(&h, id)).expect("json")).expect("value");
        assert_eq!(raw["state"], "revoked");
        assert!(matches!(s.lookup(id, "my_file.txt"), Lookup::Gone));
        assert!(dir_entries(&h.dir.path().join("tmp")).is_empty());
    }

    #[tokio::test]
    async fn revoke_past_expires_at_is_gone() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        h.clock.advance(Duration::from_secs(30 * 60));
        assert_eq!(
            h.store.revoke(&meta.id, "my_file.txt", "planner").await,
            RevokeOutcome::Gone
        );
    }

    #[tokio::test]
    async fn revoke_fires_cancel_before_io() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        let cancel = match h.store.lookup(&meta.id, "my_file.txt") {
            Lookup::Live(f) => f.cancel,
            _ => panic!("expected Live"),
        };
        h.store.set_fail_meta_writes(true);
        assert_eq!(
            h.store.revoke(&meta.id, "my_file.txt", "planner").await,
            RevokeOutcome::Failed
        );
        assert!(cancel.is_cancelled());
        assert!(matches!(
            h.store.lookup(&meta.id, "my_file.txt"),
            Lookup::Gone
        ));
        assert_eq!(
            h.store.revoke(&meta.id, "my_file.txt", "planner").await,
            RevokeOutcome::Gone
        );
        // Step 3 failed, so the disk still says live and the blob remains.
        assert_eq!(on_disk(&h, &meta.id).state, DiskState::Live);
        assert!(blob_path(&h, &meta.id).exists());
    }

    #[tokio::test]
    async fn sweep_retries_stuck_ending() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        h.store.set_fail_meta_writes(true);
        assert_eq!(
            h.store.revoke(&meta.id, "my_file.txt", "planner").await,
            RevokeOutcome::Failed
        );
        h.store.set_fail_meta_writes(false);

        // Not yet stuck for 60 s: left alone.
        let report = h.store.sweep().await;
        assert_eq!(report.retried, 0);
        assert_eq!(on_disk(&h, &meta.id).state, DiskState::Live);

        h.store.age_ending(Duration::from_secs(61));
        let report = h.store.sweep().await;
        assert_eq!(report.retried, 1);
        assert!(report.expired.is_empty());
        let disk = on_disk(&h, &meta.id);
        assert_eq!(disk.state, DiskState::Revoked);
        assert_eq!(disk.ended_at, Some(meta.created_at));
        assert!(!blob_path(&h, &meta.id).exists());
        assert!(matches!(
            h.store.lookup(&meta.id, "my_file.txt"),
            Lookup::Gone
        ));
        assert_eq!(h.store.stats().tombstones, 1);

        // Finished: nothing left to retry.
        h.store.age_ending(Duration::from_secs(61));
        assert_eq!(h.store.sweep().await.retried, 0);
    }

    #[tokio::test]
    async fn sweep_retries_failed_expiry() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        h.clock.advance(Duration::from_secs(30 * 60));
        h.store.set_fail_meta_writes(true);
        let report = h.store.sweep().await;
        assert_eq!(report.expired.len(), 1);
        assert_eq!(on_disk(&h, &meta.id).state, DiskState::Live);
        h.store.set_fail_meta_writes(false);

        h.store.age_ending(Duration::from_secs(61));
        let report = h.store.sweep().await;
        // Reported once, when it stopped being live.
        assert!(report.expired.is_empty());
        assert_eq!(report.retried, 1);
        let disk = on_disk(&h, &meta.id);
        assert_eq!(disk.state, DiskState::Expired);
        assert_eq!(disk.ended_at, Some(meta.expires_at));
        assert!(!blob_path(&h, &meta.id).exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_revokes_one_wins() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&h.store);
                let id = meta.id.clone();
                tokio::spawn(async move { store.revoke(&id, "my_file.txt", "planner").await })
            })
            .collect();
        let mut outcomes = Vec::new();
        for t in tasks {
            outcomes.push(t.await.expect("revoke task"));
        }
        let revoked = outcomes
            .iter()
            .filter(|o| **o == RevokeOutcome::Revoked)
            .count();
        let gone = outcomes
            .iter()
            .filter(|o| **o == RevokeOutcome::Gone)
            .count();
        assert_eq!((revoked, gone), (1, 7), "{outcomes:?}");
        assert_eq!(on_disk(&h, &meta.id).state, DiskState::Revoked);
        assert_eq!(h.store.stats().total_bytes, 0);
    }

    /// A `TestClock` whose next `now()` calls can each be held, after the
    /// time is read and before it is returned, until the test releases
    /// them. This pins down the window between a caller reading the clock
    /// and taking the index lock, which a real scheduler interleaves at
    /// random.
    struct GatedClock {
        inner: Arc<TestClock>,
        gates: Mutex<VecDeque<mpsc::Receiver<()>>>,
    }

    impl GatedClock {
        /// Holds the next unheld `now()` call until the returned sender is
        /// used or dropped.
        fn hold_next(&self) -> mpsc::Sender<()> {
            let (tx, rx) = mpsc::channel();
            self.gates.lock().expect("gates").push_back(rx);
            tx
        }

        /// Blocks until every armed gate has been taken by a `now()` call.
        fn wait_until_held(&self) {
            while !self.gates.lock().expect("gates").is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    impl Clock for GatedClock {
        fn now(&self) -> SystemTime {
            let now = self.inner.now();
            let gate = self.gates.lock().expect("gates").pop_front();
            if let Some(gate) = gate {
                let _ = gate.recv();
            }
            now
        }
    }

    /// The spec's "a revoke racing the sweeper", on one file both may end:
    /// the revoke read the clock one second before `expires_at`, the sweep
    /// read it at `expires_at`, and both then race for the index lock.
    /// Whichever takes it first wins; the other answers `Gone` or skips,
    /// and the counters release the file exactly once. `revoke_first`
    /// picks which caller the test lets through first.
    async fn race_revoke_and_sweep(revoke_first: bool) {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        // Reopen the same data_dir on a gated clock; recovery reloads the
        // file as live.
        h.store.unlock_data_dir();
        let clock = Arc::new(GatedClock {
            inner: h.clock.clone(),
            gates: Mutex::new(VecDeque::new()),
        });
        let (store, _report) = Store::open(&h.cfg, clock.clone()).expect("reopen");
        let store = Arc::new(store);
        let cancel = match store.lookup(&meta.id, "my_file.txt") {
            Lookup::Live(f) => f.cancel,
            _ => panic!("expected Live"),
        };

        h.clock.advance(Duration::from_secs(30 * 60 - 1));
        let revoke_now = h.clock.now();
        let release_revoke = clock.hold_next();
        let revoke = {
            let store = Arc::clone(&store);
            let id = meta.id.clone();
            tokio::spawn(async move { store.revoke(&id, "my_file.txt", "planner").await })
        };
        clock.wait_until_held();

        h.clock.advance(Duration::from_secs(1));
        let release_sweep = clock.hold_next();
        let sweep = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.sweep().await })
        };
        clock.wait_until_held();

        let (revoked, report) = if revoke_first {
            drop(release_revoke);
            let revoked = revoke.await.expect("revoke task");
            drop(release_sweep);
            (revoked, sweep.await.expect("sweep task"))
        } else {
            drop(release_sweep);
            let report = sweep.await.expect("sweep task");
            drop(release_revoke);
            (revoke.await.expect("revoke task"), report)
        };

        let disk = on_disk(&h, &meta.id);
        if revoke_first {
            assert_eq!(revoked, RevokeOutcome::Revoked);
            assert!(report.expired.is_empty(), "the sweep must skip it");
            assert_eq!(disk.state, DiskState::Revoked);
            assert_eq!(disk.ended_at, Some(revoke_now));
            assert!(cancel.is_cancelled());
        } else {
            assert_eq!(revoked, RevokeOutcome::Gone);
            assert_eq!(report.expired.len(), 1);
            assert_eq!(disk.state, DiskState::Expired);
            assert_eq!(disk.ended_at, Some(meta.expires_at));
            assert!(!cancel.is_cancelled(), "expiry must not abort downloads");
        }
        assert!(!blob_path(&h, &meta.id).exists());
        assert!(matches!(
            store.lookup(&meta.id, "my_file.txt"),
            Lookup::Gone
        ));
        let stats = store.stats();
        assert_eq!(stats.live_files, 0);
        assert_eq!(stats.tombstones, 1);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.per_agent_bytes.get("planner"), Some(&0));
        // The loser left nothing half-done for a later sweep to redo.
        store.age_ending(Duration::from_secs(61));
        assert_eq!(store.sweep().await, SweepReport::default());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn revoke_racing_sweep_revoke_wins() {
        race_revoke_and_sweep(true).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn revoke_racing_sweep_sweep_wins() {
        race_revoke_and_sweep(false).await;
    }

    #[tokio::test]
    async fn sweep_expires_and_reports_download_state() {
        let h = harness(|_| {});
        let fetched = upload(&h, b"abc").await;
        let untouched = upload(&h, b"defg").await;
        assert!(h.store.record_download(&fetched.id).is_some());
        let cancel = match h.store.lookup(&fetched.id, "my_file.txt") {
            Lookup::Live(f) => f.cancel,
            _ => panic!("expected Live"),
        };

        h.clock.advance(Duration::from_secs(30 * 60 - 1));
        let report = h.store.sweep().await;
        assert!(report.expired.is_empty());
        assert_eq!(h.store.live_ids().len(), 2);

        h.clock.advance(Duration::from_secs(1));
        let report = h.store.sweep().await;
        let mut expired = report.expired.clone();
        expired.sort_by_key(|e| e.downloaded);
        assert_eq!(
            expired,
            vec![
                ExpiredFile {
                    uploader: "planner".to_string(),
                    downloaded: false,
                    loaded_at_startup: false,
                },
                ExpiredFile {
                    uploader: "planner".to_string(),
                    downloaded: true,
                    loaded_at_startup: false,
                },
            ]
        );
        assert_eq!(report.retried, 0);
        // Expiry does not abort downloads in progress; only revoke does.
        assert!(!cancel.is_cancelled());

        for meta in [&fetched, &untouched] {
            let disk = on_disk(&h, &meta.id);
            assert_eq!(disk.state, DiskState::Expired);
            assert_eq!(disk.ended_at, Some(meta.expires_at));
            assert!(!blob_path(&h, &meta.id).exists());
            assert!(matches!(
                h.store.lookup(&meta.id, "my_file.txt"),
                Lookup::Gone
            ));
        }
        assert!(h.store.live_ids().is_empty());
        let stats = h.store.stats();
        assert_eq!(stats.live_files, 0);
        assert_eq!(stats.tombstones, 2);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.per_agent_bytes.get("planner"), Some(&0));

        // Each file is reported once.
        assert!(h.store.sweep().await.expired.is_empty());
    }

    #[tokio::test]
    async fn sweep_deletes_old_tombstones() {
        let h = harness(|_| {});
        let meta = upload(&h, b"abc").await;
        assert_eq!(
            h.store.revoke(&meta.id, "my_file.txt", "planner").await,
            RevokeOutcome::Revoked
        );
        h.clock.advance(Duration::from_secs(48 * 60 * 60 - 1));
        assert_eq!(h.store.sweep().await.tombstones_deleted, 0);
        assert!(matches!(
            h.store.lookup(&meta.id, "my_file.txt"),
            Lookup::Gone
        ));

        h.clock.advance(Duration::from_secs(1));
        let report = h.store.sweep().await;
        assert_eq!(report.tombstones_deleted, 1);
        assert_eq!(report.tombstones_evicted, 0);
        assert!(!json_path(&h, &meta.id).exists());
        assert!(dir_entries(&h.dir.path().join("files")).is_empty());
        assert!(matches!(
            h.store.lookup(&meta.id, "my_file.txt"),
            Lookup::NotFound
        ));
        assert_eq!(h.store.stats().tombstones, 0);
    }

    #[tokio::test]
    async fn sweep_evicts_over_max_tombstones() {
        let h = harness(|c| c.max_tombstones = 2);
        let mut ids = Vec::new();
        for _ in 0..3 {
            let meta = upload(&h, b"abc").await;
            h.clock.advance(Duration::from_secs(1));
            assert_eq!(
                h.store.revoke(&meta.id, "my_file.txt", "planner").await,
                RevokeOutcome::Revoked
            );
            ids.push(meta.id);
        }
        let report = h.store.sweep().await;
        assert_eq!(report.tombstones_evicted, 1);
        assert_eq!(report.tombstones_deleted, 0);
        assert!(matches!(
            h.store.lookup(&ids[0], "my_file.txt"),
            Lookup::NotFound
        ));
        assert!(!json_path(&h, &ids[0]).exists());
        for id in &ids[1..] {
            assert!(matches!(h.store.lookup(id, "my_file.txt"), Lookup::Gone));
        }
        assert_eq!(h.store.stats().tombstones, 2);
        assert_eq!(h.store.sweep().await.tombstones_evicted, 0);
    }

    #[tokio::test]
    async fn revoke_releases_quota_immediately() {
        let h = harness(|c| c.agent_quota = 3);
        let meta = upload(&h, b"abc").await;
        assert_eq!(h.store.stats().per_agent_bytes.get("planner"), Some(&3));
        assert!(h.store.reserve("planner", Some(1)).is_err());

        // Step 1 releases the quota even when the disk write then fails.
        h.store.set_fail_meta_writes(true);
        assert_eq!(
            h.store.revoke(&meta.id, "my_file.txt", "planner").await,
            RevokeOutcome::Failed
        );
        let stats = h.store.stats();
        assert_eq!(stats.per_agent_bytes.get("planner"), Some(&0));
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.live_files, 0);
        // An entry still ending is not a stored tombstone yet.
        assert_eq!(stats.tombstones, 0);
        assert!(h.store.reserve("planner", Some(3)).is_ok());

        // Finishing the protocol does not release it a second time.
        h.store.set_fail_meta_writes(false);
        h.store.age_ending(Duration::from_secs(61));
        assert_eq!(h.store.sweep().await.retried, 1);
        let stats = h.store.stats();
        assert_eq!(stats.per_agent_bytes.get("planner"), Some(&0));
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.tombstones, 1);
    }
}
