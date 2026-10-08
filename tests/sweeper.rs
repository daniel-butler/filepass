//! Sweeper tests: the spec's Expiry section and the sweeper's metric
//! events (`expired_undownloaded`, `tombstones_evicted`, and the gauges).

mod common;

use std::time::Duration;

use common::TestServer;
use filepass::obs::Recorder;

/// The number of `name` events carrying every one of `labels`.
fn count_events(recorder: &Recorder, name: &str, labels: &[(&str, &str)]) -> usize {
    recorder
        .events()
        .iter()
        .filter(|e| {
            e.name == name
                && labels
                    .iter()
                    .all(|(k, v)| e.labels.iter().any(|(ek, ev)| ek == k && ev == v))
        })
        .count()
}

/// The value of the most recent `name` event carrying exactly `labels`.
fn value_of(recorder: &Recorder, name: &str, labels: &[(&str, &str)]) -> f64 {
    recorder
        .events()
        .iter()
        .rev()
        .find(|e| {
            e.labels.len() == labels.len()
                && e.name == name
                && labels
                    .iter()
                    .all(|(k, v)| e.labels.iter().any(|(ek, ev)| ek == k && ev == v))
        })
        .unwrap_or_else(|| panic!("no {name} event with labels {labels:?}"))
        .value
}

/// Uploads `body` as `planner` and returns its download URL and size.
async fn upload(server: &TestServer, body: Vec<u8>) -> (String, u64) {
    let size = body.len() as u64;
    let resp = server
        .put("/my_file.txt", body, Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);
    let url = resp.text().await.expect("upload body").trim().to_string();
    (url, size)
}

#[tokio::test]
async fn expired_undownloaded_counts_only_untouched() {
    let server = TestServer::start().await;
    let (fetched, _) = upload(&server, b"abc".to_vec()).await;
    let (_untouched, _) = upload(&server, b"defgh".to_vec()).await;

    let resp = server.get(&fetched).await;
    assert_eq!(resp.status(), 200);
    let _ = resp.bytes().await;

    server.clock.advance(Duration::from_secs(31 * 60));
    server.sweeper.run_once().await;

    assert_eq!(
        count_events(
            &server.metrics,
            "expired_undownloaded",
            &[("agent", "planner")]
        ),
        1
    );
}

#[tokio::test]
async fn gauges_emitted() {
    let server = TestServer::start().await;
    let (_url, size) = upload(&server, b"abcde".to_vec()).await;

    server.sweeper.run_once().await;

    assert_eq!(value_of(&server.metrics, "live_files", &[]), 1.0);
    assert_eq!(
        value_of(&server.metrics, "stored_bytes", &[("agent", "planner")]),
        size as f64
    );
    assert_eq!(
        value_of(&server.metrics, "stored_bytes", &[("agent", "total")]),
        size as f64
    );
}

#[tokio::test]
async fn evicts_tombstones_with_metric() {
    let server = TestServer::start_with(|cfg| cfg.max_tombstones = 1).await;
    let (url1, _) = upload(&server, b"abc".to_vec()).await;
    server.clock.advance(Duration::from_secs(1));
    let (url2, _) = upload(&server, b"defgh".to_vec()).await;

    assert_eq!(server.delete(&url1, Some("planner")).await.status(), 204);
    server.clock.advance(Duration::from_secs(1));
    assert_eq!(server.delete(&url2, Some("planner")).await.status(), 204);

    server.sweeper.run_once().await;

    assert_eq!(value_of(&server.metrics, "tombstones_evicted", &[]), 1.0);
    assert_eq!(value_of(&server.metrics, "tombstones", &[]), 1.0);
}
