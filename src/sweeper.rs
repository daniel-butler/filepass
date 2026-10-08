//! The periodic sweeper: expires files past `expires_at`, retries entries
//! stuck `ending`, and deletes old tombstones (`Store::sweep` does the
//! actual work; see its docs for the five-step ending protocol).
//!
//! Ruling R1 (binding): `run_once` here calls `Store::sweep` and discards
//! the report. Task 10 adds the gauge and counter emissions the spec's
//! Telemetry section requires. Task 9's tests call `run_once` directly, so
//! they drive real sweeps against a controlled `TestClock` rather than
//! waiting on the 60s timer.

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

    /// Runs one sweep pass.
    pub async fn run_once(&self) {
        let _report = self.state.store.sweep().await;
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
