//! Log hygiene: the spec's Log hygiene section. Installs its own global
//! `tracing` subscriber (safe because every file directly under `tests/`
//! is already its own test binary) capturing at `trace` level into a
//! shared buffer, then drives upload, a throttled upload, download, a
//! bad-token upload, revoke, a wrong-name GET, and a server error through
//! the real app, and inspects everything that got logged.
//!
//! The route *template* the request span records (e.g.
//! `/d/{id}/{urlname}`, per `app::request_span`) is expected to appear: it
//! never varies per request and carries no real id or filename. What must
//! never appear is anything that could re-identify or re-authenticate a
//! specific file or agent: a token, a token hash, a full 32-character id,
//! or the real, dynamic request path built from one.

mod common;

use std::io;
use std::sync::{Arc, Mutex};

use common::TestServer;
use filepass::auth::hash_token;
use tracing_subscriber::EnvFilter;

/// A `Write` implementation that appends every write to a shared buffer, so
/// the test can inspect everything logged during the run.
#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer mutex poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `PUT <path>` with an arbitrary bearer token, bypassing `TestServer::put`
/// (which only knows the real tokens of its test agents).
async fn put_with_token(server: &TestServer, path: &str, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!("{}{path}", server.url))
        .header("Authorization", format!("Bearer {token}"))
        .body("x")
        .send()
        .await
        .expect("PUT request should complete")
}

#[tokio::test]
async fn logs_never_leak_secrets_or_real_uris() {
    // A process-wide global subscriber, deliberately. A thread-local
    // `tracing::subscriber::with_default` capture is unsafe in this crate's
    // lib tests: while only one dispatcher exists, tracing-core caches each
    // callsite's `Interest` globally, so a sibling test running with no
    // subscriber can cache `Interest::never` for a callsite (such as the
    // `info!` in `Throttle::respond`) and the thread-local subscriber then
    // never sees that event. This file is its own test binary, so a global
    // subscriber here registers before any callsite fires.
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer_buf = buf.clone();
    tracing_subscriber::fmt()
        .with_writer(move || SharedWriter(writer_buf.clone()))
        .with_ansi(false)
        .with_env_filter(EnvFilter::new("trace"))
        .init();

    // `upload_rate = 1` makes the second upload below throttled
    // deterministically, with no need to race the token bucket's refill.
    let server = TestServer::start_with(|cfg| cfg.upload_rate = 1).await;
    let planner_token = server.token("planner").to_string();

    // Upload, then download: both are handled requests that log a line.
    let resp = server
        .put(
            "/secret-report.txt",
            b"hello world".to_vec(),
            Some("planner"),
            None,
        )
        .await;
    assert_eq!(resp.status(), 201);
    let url = resp.text().await.expect("upload body").trim().to_string();
    let rest = url.split("/d/").nth(1).expect("download URL has /d/");
    let (id, _urlname) = rest.split_once('/').expect("id/urlname");
    let full_id = id.to_string();

    // A throttled upload: the bucket has no token left, so this logs
    // `Throttle::respond`'s paired reason line, not just the counter.
    let resp = server
        .put("/second.txt", b"y".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 429);

    let resp = server.get(&url).await;
    assert_eq!(resp.status(), 200);
    let _ = resp.bytes().await;

    // A bad token on upload: rejected, and the bad token itself must never
    // be logged.
    let bogus_token = "fp_this-token-must-never-appear-in-any-log-line";
    let resp = put_with_token(&server, "/other.txt", bogus_token).await;
    assert_eq!(resp.status(), 401);

    // Revoke: a legitimate request that also logs a line.
    let resp = server.delete(&url, Some("planner")).await;
    assert_eq!(resp.status(), 204);

    // The right id, wrong name: 404.
    let wrong_name_url = format!("{}/d/{}/not-the-right-name", server.url, full_id);
    let resp = server.get(&wrong_name_url).await;
    assert_eq!(resp.status(), 404);

    // A `PUT /` with a valid token: the fallback's `400`, which logs a
    // paired line even though no file was named.
    let resp = put_with_token(&server, "/", &planner_token).await;
    assert_eq!(resp.status(), 400);

    // A server error: a commit that fails to write its metadata.
    server.state.store.set_fail_meta_writes(true);
    let resp = server
        .put("/other-file.bin", b"abc".to_vec(), Some("builder"), None)
        .await;
    assert_eq!(resp.status(), 500);
    server.state.store.set_fail_meta_writes(false);

    let captured = String::from_utf8(buf.lock().expect("log buffer mutex poisoned").clone())
        .expect("captured log is UTF-8");

    assert!(
        !captured.contains(&planner_token),
        "a real token leaked into the logs:\n{captured}"
    );
    assert!(
        !captured.contains(bogus_token),
        "the bad token leaked into the logs:\n{captured}"
    );
    assert!(
        !captured.contains(&full_id),
        "a full 32-character id leaked into the logs:\n{captured}"
    );
    assert!(
        !captured.contains(&format!("/d/{full_id}")),
        "the real request path (with its real id) leaked into the logs:\n{captured}"
    );
    let hash_hex = hex::encode(hash_token(&planner_token));
    assert!(
        !captured.contains(&hash_hex),
        "a token hash leaked into the logs:\n{captured}"
    );

    assert!(
        captured.contains(&full_id[..8]),
        "expected the id's first 8 characters to appear in the logs; captured:\n{captured}"
    );
    // Sanity: the upload's and revoke's original filename should be
    // visible too (it is not secret: the spec requires it in the log).
    assert!(
        captured.contains("secret-report.txt"),
        "expected the original filename in the logs; captured:\n{captured}"
    );
    // `Throttle::respond`'s readable log line, paired with its `throttled`
    // counter: the reason must be visible even though nothing else about
    // the throttled request is.
    assert!(
        captured.contains("upload_rate"),
        "expected the throttle's reason in the logs; captured:\n{captured}"
    );
    // Lines logged from spawned tasks (the upload commit, the download
    // producer) still carry their request span, so they name the route.
    let has_line = |needles: &[&str]| {
        captured
            .lines()
            .any(|line| needles.iter().all(|n| line.contains(n)))
    };
    assert!(
        has_line(&[
            "route=/{filename}",
            "upload request handled",
            "result=\"ok\""
        ]),
        "the commit task's log line lost its request span; captured:\n{captured}"
    );
    assert!(
        has_line(&[
            "route=/d/{id}/{urlname}",
            "download request handled",
            "result=\"ok\""
        ]),
        "the producer task's log line lost its request span; captured:\n{captured}"
    );
    // `time_to_first_download_ms` and the fallback's `upload` event each
    // have a readable paired line.
    assert!(
        has_line(&["first download of file", &full_id[..8]]),
        "expected a readable line paired with time_to_first_download_ms; captured:\n{captured}"
    );
    assert!(
        has_line(&["upload request handled", "result=\"bad_request\""]),
        "expected a readable line paired with the fallback's upload event; captured:\n{captured}"
    );
    assert!(
        captured.contains("request throttled"),
        "expected a readable log line paired with the throttled counter; captured:\n{captured}"
    );
}
