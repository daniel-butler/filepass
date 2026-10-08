//! Metric event helpers: emit through `tracing`, optionally recording events
//! for test assertions.

use std::sync::{Arc, Mutex};

/// A metric event, as pushed to a `Recorder` when the owning `Obs` is
/// recording.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricEvent {
    pub name: &'static str,
    pub labels: Vec<(&'static str, String)>,
    pub value: f64,
}

#[derive(Debug, Default)]
struct RecorderState {
    events: Vec<MetricEvent>,
}

/// Captures every metric event emitted through a recording `Obs`, for test
/// assertions.
#[derive(Debug, Clone)]
pub struct Recorder {
    state: Arc<Mutex<RecorderState>>,
}

impl Recorder {
    fn push(&self, event: MetricEvent) {
        self.state
            .lock()
            .expect("Recorder mutex poisoned")
            .events
            .push(event);
    }

    /// All events recorded so far, in emission order.
    pub fn events(&self) -> Vec<MetricEvent> {
        self.state
            .lock()
            .expect("Recorder mutex poisoned")
            .events
            .clone()
    }

    /// The number of events for `name` that carry the label `label`.
    pub fn count(&self, name: &str, label: (&str, &str)) -> usize {
        self.events()
            .iter()
            .filter(|e| {
                e.name == name && e.labels.iter().any(|(k, v)| *k == label.0 && v == label.1)
            })
            .count()
    }
}

/// Emits metric events through `tracing` on the `metric` target, and,
/// when built via `Obs::recording`, into a paired `Recorder`.
#[derive(Clone)]
pub struct Obs {
    recorder: Option<Recorder>,
}

impl Default for Obs {
    fn default() -> Self {
        Obs::new()
    }
}

impl Obs {
    /// An `Obs` that only logs; nothing is kept in memory.
    pub fn new() -> Self {
        Obs { recorder: None }
    }

    /// An `Obs` paired with a `Recorder` that captures every event emitted
    /// through it.
    pub fn recording() -> (Obs, Recorder) {
        let recorder = Recorder {
            state: Arc::new(Mutex::new(RecorderState::default())),
        };
        (
            Obs {
                recorder: Some(recorder.clone()),
            },
            recorder,
        )
    }

    fn emit(
        &self,
        name: &'static str,
        labels: &[(&'static str, &str)],
        value: f64,
        unit: Option<&'static str>,
    ) {
        log_metric(name, labels, value, unit);
        if let Some(recorder) = &self.recorder {
            recorder.push(MetricEvent {
                name,
                labels: labels.iter().map(|(k, v)| (*k, v.to_string())).collect(),
                value,
            });
        }
    }

    /// A counter event: the increment for plain counters, or the byte count
    /// for `*_bytes` counters.
    pub fn counter(&self, name: &'static str, labels: &[(&'static str, &str)], value: u64) {
        self.emit(name, labels, value as f64, None);
    }

    /// A gauge reading.
    pub fn gauge(&self, name: &'static str, labels: &[(&'static str, &str)], value: f64) {
        self.emit(name, labels, value, None);
    }

    /// A timing in milliseconds.
    pub fn timing_ms(&self, name: &'static str, labels: &[(&'static str, &str)], ms: f64) {
        self.emit(name, labels, ms, Some("ms"));
    }
}

/// Emits the single structured `tracing` event for one metric call. The
/// label shapes handled here are exactly those the spec's metric table
/// uses: none, `agent`, `result`, `reason`, or `agent` with `result`.
/// `tracing`'s field names must be static per call site, so each shape gets
/// its own macro invocation; anything else falls back to a debug-formatted
/// `labels` field rather than panicking.
fn log_metric(
    name: &'static str,
    labels: &[(&'static str, &str)],
    value: f64,
    unit: Option<&'static str>,
) {
    match (labels, unit) {
        ([], None) => tracing::info!(target: "metric", metric = name, value = value),
        ([], Some(u)) => {
            tracing::info!(target: "metric", metric = name, value = value, unit = u)
        }
        ([(k, v)], None) if *k == "agent" => {
            tracing::info!(target: "metric", metric = name, agent = *v, value = value)
        }
        ([(k, v)], Some(u)) if *k == "agent" => {
            tracing::info!(target: "metric", metric = name, agent = *v, value = value, unit = u)
        }
        ([(k, v)], None) if *k == "result" => {
            tracing::info!(target: "metric", metric = name, result = *v, value = value)
        }
        ([(k, v)], None) if *k == "reason" => {
            tracing::info!(target: "metric", metric = name, reason = *v, value = value)
        }
        ([(ka, va), (kb, vb)], None) if *ka == "agent" && *kb == "result" => {
            tracing::info!(target: "metric", metric = name, agent = *va, result = *vb, value = value)
        }
        _ => {
            tracing::info!(target: "metric", metric = name, labels = ?labels, value = value, unit = unit)
        }
    }
}

/// The `result` label value for a metric event, per the spec's telemetry
/// table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Timeout,
    Gone,
    TooLarge,
    RangeNotSatisfiable,
    RateLimited,
    Busy,
    InsufficientStorage,
    Error,
    Revoked,
    ClientAborted,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::BadRequest => "bad_request",
            Outcome::Unauthorized => "unauthorized",
            Outcome::Forbidden => "forbidden",
            Outcome::NotFound => "not_found",
            Outcome::Timeout => "timeout",
            Outcome::Gone => "gone",
            Outcome::TooLarge => "too_large",
            Outcome::RangeNotSatisfiable => "range_not_satisfiable",
            Outcome::RateLimited => "rate_limited",
            Outcome::Busy => "busy",
            Outcome::InsufficientStorage => "insufficient_storage",
            Outcome::Error => "error",
            Outcome::Revoked => "revoked",
            Outcome::ClientAborted => "client_aborted",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_captures_counter_labels_and_value() {
        let (obs, recorder) = Obs::recording();
        obs.counter("upload", &[("agent", "planner"), ("result", "ok")], 1);

        let events = recorder.events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.name, "upload");
        assert_eq!(
            event.labels,
            vec![
                ("agent", "planner".to_string()),
                ("result", "ok".to_string())
            ]
        );
        assert_eq!(event.value, 1.0);

        assert_eq!(
            Outcome::RangeNotSatisfiable.as_str(),
            "range_not_satisfiable"
        );
    }
}
