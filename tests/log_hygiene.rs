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
}
