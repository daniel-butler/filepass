//! Upload tests: the spec's Upload section and its check order, Space
//! protection (declared and streamed limits, quotas, slots, the free-space
//! floor), upload timeouts, the upload rate, the uncancellable commit, and
//! the `upload`/`throttled` metric events.
//!
//! Behaviour reqwest can't express (a held-open body, a stall, a trickle,
//! a close right after the body) goes over raw TCP via `raw_put`.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use common::{eventually, read_status, TestServer};
use filepass::obs::Recorder;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

const MIB: u64 = 1 << 20;

/// True if `recorder` holds a `name` event carrying every one of `labels`.
fn has_event(recorder: &Recorder, name: &str, labels: &[(&str, &str)]) -> bool {
    recorder.events().iter().any(|e| {
        e.name == name
            && labels
                .iter()
                .all(|(k, v)| e.labels.iter().any(|(ek, ev)| ek == k && ev == v))
    })
}

/// The names of the entries in `data_dir/<sub>`, sorted.
fn dir_entries(server: &TestServer, sub: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(server.dir.path().join(sub))
        .expect("read data dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// True once no upload holds a concurrency slot, a file slot, or bytes,
/// and `tmp/` is empty.
fn counters_zero(server: &TestServer) -> bool {
    server.state.limits.uploads_in_flight() == 0
        && server.state.store.reserved_bytes() == 0
        && server.state.store.reserved_slots() == 0
        && dir_entries(server, "tmp").is_empty()
}

/// `PUT <path>` with an arbitrary `Authorization: Bearer <token>`.
async fn put_with_token(server: &TestServer, path: &str, token: &str) -> reqwest::Response {
    reqwest::Client::new()
        .put(format!("{}{path}", server.url))
        .header("Authorization", format!("Bearer {token}"))
        .body("x")
        .send()
        .await
        .expect("PUT request should complete")
}

fn header<'a>(resp: &'a reqwest::Response, name: &str) -> &'a str {
    resp.headers()
        .get(name)
        .unwrap_or_else(|| panic!("missing {name} header"))
        .to_str()
        .expect("header is ASCII")
}

#[tokio::test]
async fn round_trip_headers() {
    let server = TestServer::start().await;
    let body = b"hello, filepass".to_vec();

    let resp = server
        .put("/hello.txt", body.clone(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);

    let location = header(&resp, "location").to_string();
    let sha = header(&resp, "filepass-sha256").to_string();
    let expires = header(&resp, "filepass-expires").to_string();
    let text = resp.text().await.expect("body");

    assert!(text.ends_with('\n'), "body {text:?} must end in a newline");
    let url = text.trim_end();
    assert_eq!(url, location);
    let prefix = format!("{}/d/", server.url);
    let rest = url.strip_prefix(&prefix).expect("URL under /d/");
    let (id, urlname) = rest.split_once('/').expect("id/urlname");
    assert!(filepass::store::is_valid_id(id), "id {id:?}");
    assert_eq!(urlname, "hello.txt");

    assert_eq!(sha, hex::encode(Sha256::digest(&body)));
    let expires_at = humantime::parse_rfc3339(&expires).expect("RFC 3339 expiry");
    assert_eq!(
        expires_at,
        SystemTime::UNIX_EPOCH + Duration::from_secs(30 * 60)
    );
    assert_eq!(expires, "1970-01-01T00:30:00Z");

    let stored = std::fs::read(server.dir.path().join("files").join(id)).expect("blob");
    assert_eq!(stored, body);
    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "planner"), ("result", "ok")]
    ));
    assert!(has_event(
        &server.metrics,
        "upload_bytes",
        &[("agent", "planner")]
    ));
    assert!(has_event(
        &server.metrics,
        "upload_duration_ms",
        &[("agent", "planner")]
    ));
}

#[tokio::test]
async fn url_name_is_url_safe() {
    let server = TestServer::start().await;

    let resp = server
        .put("/my%20file.zip", b"z".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);
    let text = resp.text().await.expect("body");
    assert!(text.ends_with("/my_file.zip\n"), "body {text:?}");
}

#[tokio::test]
async fn empty_file_uploads() {
    let server = TestServer::start().await;

    let resp = server
        .put("/empty", Vec::new(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);
    assert_eq!(
        header(&resp, "filepass-sha256"),
        hex::encode(Sha256::digest(b""))
    );
    assert_eq!(server.state.store.stats().live_files, 1);
}

#[tokio::test]
async fn ttl_header() {
    let server = TestServer::start().await;

    let resp = server
        .put("/a", b"a".to_vec(), Some("planner"), Some("4h"))
        .await;
    assert_eq!(resp.status(), 201);
    let expires = humantime::parse_rfc3339(header(&resp, "filepass-expires")).expect("expiry");
    assert_eq!(
        expires,
        SystemTime::UNIX_EPOCH + Duration::from_secs(4 * 3600)
    );

    for ttl in ["25h", "0s", "soon"] {
        let resp = server
            .put("/a", b"a".to_vec(), Some("planner"), Some(ttl))
            .await;
        assert_eq!(resp.status(), 400, "Filepass-TTL: {ttl}");
    }
    assert_eq!(server.metrics.count("upload", ("result", "bad_request")), 3);
    assert_eq!(server.state.store.stats().live_files, 1);
}

#[tokio::test]
async fn check_order() {
    let server = TestServer::start_with(|cfg| {
        cfg.max_file_size = MIB;
        cfg.max_uploads_per_agent = 1;
        cfg.max_concurrent_uploads = 1;
    })
    .await;
    let over = MIB + 1;

    // Step 1 beats step 2.
    let mut conn = server.raw_put("/a%01b", None, over).await;
    assert_eq!(read_status(&mut conn).await, 401);

    // Step 2 beats step 5.
    let mut conn = server.raw_put("/a%01b", Some("planner"), over).await;
    assert_eq!(read_status(&mut conn).await, 400);

    // Hold one upload open: a slow body keeps its slot.
    let mut held = server.raw_put("/held", Some("planner"), 10).await;
    held.write_all(b"x").await.expect("write one byte");
    assert!(eventually(|| server.state.limits.uploads_in_flight() == 1).await);

    let resp = server
        .put("/second", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 429);
    assert_eq!(header(&resp, "retry-after"), "1");
    assert_eq!(
        server
            .metrics
            .count("throttled", ("reason", "uploads_per_agent")),
        1
    );
    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "planner"), ("result", "busy")]
    ));

    // Step 3 beats step 5.
    let mut conn = server.raw_put("/big", Some("planner"), over).await;
    assert_eq!(read_status(&mut conn).await, 429);

    let resp = server
        .put("/other", b"x".to_vec(), Some("builder"), None)
        .await;
    assert_eq!(resp.status(), 503);
    assert_eq!(header(&resp, "retry-after"), "1");
    assert_eq!(
        server
            .metrics
            .count("throttled", ("reason", "uploads_total")),
        1
    );
    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "builder"), ("result", "busy")]
    ));

    drop(held);
    assert!(eventually(|| counters_zero(&server)).await);

    // Step 5 alone.
    let mut conn = server.raw_put("/big", Some("planner"), over).await;
    assert_eq!(read_status(&mut conn).await, 413);

    // Step 5 beats step 6.
    server.state.store.set_fs_override(Some((MIB, MIB)));
    let mut conn = server.raw_put("/big", Some("planner"), over).await;
    assert_eq!(read_status(&mut conn).await, 413);
    let resp = server
        .put("/small", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 507);
    server.state.store.set_fs_override(None);

    assert!(eventually(|| counters_zero(&server)).await);
}

#[tokio::test]
async fn exact_boundaries() {
    let server = TestServer::start_with(|cfg| {
        cfg.max_file_size = MIB;
        cfg.agent_quota = 2 * MIB;
    })
    .await;
    let one_mib = vec![7u8; MIB as usize];

    let resp = server
        .put("/one", one_mib.clone(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);

    let mut conn = server.raw_put("/over", Some("planner"), MIB + 1).await;
    assert_eq!(read_status(&mut conn).await, 413);

    let resp = server.put("/two", one_mib, Some("planner"), None).await;
    assert_eq!(resp.status(), 201);

    let resp = server
        .put("/three", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 507);
    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "planner"), ("result", "insufficient_storage")]
    ));
    assert_eq!(
        server.state.store.stats().per_agent_bytes.get("planner"),
        Some(&(2 * MIB))
    );
}

#[tokio::test]
async fn streamed_over_limit_is_413() {
    let server = TestServer::start_with(|cfg| cfg.max_file_size = MIB).await;

    let chunks = (0..32).map(|_| Ok::<_, std::io::Error>(vec![1u8; 64 * 1024]));
    let body = reqwest::Body::wrap_stream(futures_util::stream::iter(chunks));
    let result = reqwest::Client::new()
        .put(format!("{}/stream.bin", server.url))
        .header(
            "Authorization",
            format!("Bearer {}", server.token("planner")),
        )
        .body(body)
        .send()
        .await;
    if let Ok(resp) = result {
        assert_eq!(resp.status(), 413);
    }

    assert!(eventually(|| counters_zero(&server)).await);
    assert!(eventually(|| server.metrics.count("upload", ("result", "too_large")) == 1).await);
    assert!(dir_entries(&server, "files").is_empty());
}

#[tokio::test]
async fn streamed_upload_within_limit_commits() {
    let server = TestServer::start_with(|cfg| cfg.max_file_size = 2 * MIB).await;

    let chunks: Vec<Vec<u8>> = (0..24u8).map(|i| vec![i; 64 * 1024]).collect();
    let expected: Vec<u8> = chunks.concat();
    let stream = futures_util::stream::iter(chunks.into_iter().map(Ok::<_, std::io::Error>));
    let resp = reqwest::Client::new()
        .put(format!("{}/stream.bin", server.url))
        .header(
            "Authorization",
            format!("Bearer {}", server.token("planner")),
        )
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .expect("PUT should complete");
    assert_eq!(resp.status(), 201);
    assert_eq!(
        header(&resp, "filepass-sha256"),
        hex::encode(Sha256::digest(&expected))
    );
    assert_eq!(
        server.state.store.stats().total_bytes,
        expected.len() as u64
    );
    assert!(counters_zero(&server));
}

#[tokio::test]
async fn free_space_floor_is_507() {
    let server = TestServer::start().await;
    server.state.store.set_fs_override(Some((MIB, MIB)));

    let resp = server.put("/a", b"a".to_vec(), Some("planner"), None).await;
    assert_eq!(resp.status(), 507);
    assert!(counters_zero(&server));
}

#[tokio::test]
async fn max_files_is_507() {
    let server = TestServer::start_with(|cfg| cfg.max_files = 1).await;

    let resp = server.put("/a", b"a".to_vec(), Some("planner"), None).await;
    assert_eq!(resp.status(), 201);
    let resp = server.put("/b", b"b".to_vec(), Some("planner"), None).await;
    assert_eq!(resp.status(), 507);
}

#[tokio::test]
async fn concurrent_uploads_cannot_share_last_slot() {
    let server = TestServer::start_with(|cfg| cfg.max_files = 1).await;

    // Hold one upload mid-body so it owns the last slot while the other
    // arrives.
    let mut held = server.raw_put("/held", Some("planner"), 2).await;
    held.write_all(b"x").await.expect("write one byte");
    assert!(eventually(|| server.state.store.reserved_slots() == 1).await);

    let resp = server.put("/b", b"b".to_vec(), Some("planner"), None).await;
    assert_eq!(resp.status(), 507);

    held.write_all(b"y").await.expect("finish body");
    assert_eq!(read_status(&mut held).await, 201);

    // And two truly simultaneous uploads: exactly one wins.
    let server = TestServer::start_with(|cfg| cfg.max_files = 1).await;
    let body = vec![3u8; 256 * 1024];
    let (a, b) = tokio::join!(
        server.put("/a", body.clone(), Some("planner"), None),
        server.put("/b", body.clone(), Some("planner"), None),
    );
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    assert_eq!(statuses, [201, 507]);
    assert_eq!(server.state.store.stats().live_files, 1);
}

#[tokio::test]
async fn idle_upload_is_408() {
    let server = TestServer::start_with(|cfg| {
        cfg.upload_idle_timeout = Duration::from_secs(1);
    })
    .await;

    let mut conn = server.raw_put("/idle", Some("planner"), 10).await;
    conn.write_all(b"x").await.expect("write one byte");
    let started = Instant::now();
    assert_eq!(read_status(&mut conn).await, 408);
    assert!(started.elapsed() >= Duration::from_millis(900));

    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "planner"), ("result", "timeout")]
    ));
    assert!(eventually(|| counters_zero(&server)).await);
    assert!(dir_entries(&server, "files").is_empty());
}

#[tokio::test]
async fn max_duration_is_408() {
    let server = TestServer::start_with(|cfg| {
        cfg.max_upload_duration = Duration::from_secs(1);
        cfg.upload_idle_timeout = Duration::from_secs(10);
    })
    .await;

    let conn = server.raw_put("/trickle", Some("planner"), 100).await;
    let (mut rd, mut wr) = conn.into_split();
    let started = Instant::now();
    // Trickle a byte every 300 ms, well inside the idle timeout. A reader
    // runs concurrently so the response is read before any reset caused
    // by bytes the server no longer reads.
    let trickle = tokio::spawn(async move {
        for _ in 0..20 {
            if wr.write_all(b"x").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });
    assert_eq!(read_status(&mut rd).await, 408);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(5),
        "408 after {elapsed:?}"
    );
    trickle.abort();

    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "planner"), ("result", "timeout")]
    ));
    assert!(eventually(|| counters_zero(&server)).await);
}

#[tokio::test]
async fn rate_limit() {
    let server = TestServer::start_with(|cfg| cfg.upload_rate = 2).await;

    for name in ["/a", "/b"] {
        let resp = server.put(name, b"x".to_vec(), Some("planner"), None).await;
        assert_eq!(resp.status(), 201);
    }

    let resp = server.put("/c", b"x".to_vec(), Some("planner"), None).await;
    assert_eq!(resp.status(), 429);
    let retry: u64 = header(&resp, "retry-after").parse().expect("integer");
    assert!((1..=30).contains(&retry), "Retry-After {retry}");
    assert_eq!(
        server.metrics.count("throttled", ("reason", "upload_rate")),
        1
    );
    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "planner"), ("result", "rate_limited")]
    ));

    // Step 2 precedes step 4.
    let resp = server
        .put("/a%01b", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 400);

    // Buckets are per agent.
    let resp = server.put("/d", b"x".to_vec(), Some("builder"), None).await;
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn rejections_before_rate_spend_nothing() {
    let server = TestServer::start_with(|cfg| cfg.upload_rate = 1).await;

    for _ in 0..3 {
        let resp = server
            .put("/a%01b", b"x".to_vec(), Some("planner"), None)
            .await;
        assert_eq!(resp.status(), 400);
    }
    let resp = put_with_token(&server, "/a", "fp_not-a-real-token").await;
    assert_eq!(resp.status(), 401);

    let resp = server.put("/a", b"x".to_vec(), Some("planner"), None).await;
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn disconnect_after_body_still_commits() {
    let server = TestServer::start().await;

    // Wait until the handler has accepted the upload and is reading the
    // body, then send the whole body and close at once. (If the head, body,
    // and FIN all arrive before hyper first polls the handler, hyper drops
    // the request unseen; no handler code can act on that.) hyper then
    // reads the last chunk and the EOF in one pass and drops the handler
    // before it sees the body end: only a task that outlives the handler
    // commits the file.
    let mut conn = server.raw_put("/gone.bin", Some("planner"), 5).await;
    assert!(eventually(|| server.state.store.reserved_slots() == 1).await);
    conn.write_all(b"hello").await.expect("write body");
    drop(conn);

    assert!(eventually(|| server.state.store.stats().live_files == 1).await);
    let files = dir_entries(&server, "files");
    assert_eq!(files.len(), 2, "files/ holds {files:?}");
    let id = &files[0];
    assert!(filepass::store::is_valid_id(id));
    assert_eq!(files[1], format!("{id}.json"));
    assert_eq!(
        std::fs::read(server.dir.path().join("files").join(id)).expect("blob"),
        b"hello"
    );

    assert!(
        eventually(|| has_event(
            &server.metrics,
            "upload",
            &[("agent", "planner"), ("result", "ok")]
        ))
        .await
    );
    assert_eq!(server.metrics.count("upload", ("agent", "planner")), 1);
    let bytes = server
        .metrics
        .events()
        .into_iter()
        .find(|e| e.name == "upload_bytes")
        .expect("upload_bytes event");
    assert_eq!(bytes.value, 5.0);
    assert!(has_event(
        &server.metrics,
        "upload_duration_ms",
        &[("agent", "planner")]
    ));
    assert!(eventually(|| counters_zero(&server)).await);
}

#[tokio::test]
async fn disconnect_mid_body_releases_everything() {
    let server = TestServer::start().await;

    let mut conn = server.raw_put("/partial", Some("planner"), 10).await;
    conn.write_all(b"hello").await.expect("write half the body");
    assert!(eventually(|| server.state.store.reserved_slots() == 1).await);
    drop(conn);

    assert!(eventually(|| counters_zero(&server)).await);
    assert!(dir_entries(&server, "files").is_empty());
    assert_eq!(server.state.store.stats().live_files, 0);
    assert!(eventually(|| server.metrics.count("upload", ("result", "client_aborted")) == 1).await);
}

#[tokio::test]
async fn json_failure_is_500_and_counters_zero() {
    let server = TestServer::start().await;
    server.state.store.set_fail_meta_writes(true);

    let resp = server
        .put("/a", b"abc".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 500);

    assert!(dir_entries(&server, "files").is_empty());
    assert_eq!(server.state.limits.uploads_in_flight(), 0);
    assert_eq!(server.state.store.reserved_bytes(), 0);
    assert!(counters_zero(&server));
    assert_eq!(server.state.store.stats().live_files, 0);
    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "planner"), ("result", "error")]
    ));
}

#[tokio::test]
async fn unauthorized_emits_metric() {
    let server = TestServer::start().await;

    let resp = put_with_token(&server, "/a", "fp_not-a-real-token").await;
    assert_eq!(resp.status(), 401);
    assert!(has_event(
        &server.metrics,
        "upload",
        &[("agent", "-"), ("result", "unauthorized")]
    ));

    let resp = server.put("/a", b"x".to_vec(), None, None).await;
    assert_eq!(resp.status(), 401);
    assert_eq!(
        server.metrics.count("upload", ("result", "unauthorized")),
        2
    );
}

#[tokio::test]
async fn put_healthz_uploads() {
    let server = TestServer::start().await;

    let resp = server
        .put("/healthz", b"h".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);
    let text = resp.text().await.expect("body");
    assert!(text.trim_end().ends_with("/healthz"), "body {text:?}");
}

#[tokio::test]
async fn percent_ff_without_token_is_401() {
    let server = TestServer::start().await;

    let resp = server.put("/a%FFb", b"x".to_vec(), None, None).await;
    assert_eq!(resp.status(), 401);

    let resp = server
        .put("/a%FFb", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn counters_zero_after_every_outcome() {
    let server = TestServer::start_with(|cfg| cfg.max_file_size = MIB).await;

    let resp = server
        .put("/ok", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);

    let resp = server
        .put("/a%01b", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 400);

    let resp = server.put("/a", b"x".to_vec(), None, None).await;
    assert_eq!(resp.status(), 401);

    let mut conn = server.raw_put("/big", Some("planner"), 2 * MIB).await;
    assert_eq!(read_status(&mut conn).await, 413);

    server.state.store.set_fs_override(Some((MIB, MIB)));
    let resp = server
        .put("/full", b"x".to_vec(), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 507);
    server.state.store.set_fs_override(None);

    assert!(eventually(|| counters_zero(&server)).await);
    assert_eq!(server.state.limits.uploads_in_flight(), 0);
    assert_eq!(server.state.store.reserved_bytes(), 0);
    assert_eq!(server.state.store.reserved_slots(), 0);
    for result in [
        "ok",
        "bad_request",
        "unauthorized",
        "too_large",
        "insufficient_storage",
    ] {
        assert_eq!(
            server.metrics.count("upload", ("result", result)),
            1,
            "result={result}"
        );
    }
}

/// True if a `curl` binary runs.
fn curl_available() -> bool {
    Command::new("curl").arg("--version").output().is_ok()
}

#[tokio::test]
async fn real_curl_upload_forms() {
    if !curl_available() {
        eprintln!("curl not found; skipping real_curl_upload_forms");
        return;
    }
    let server = TestServer::start().await;
    let auth = format!("Authorization: Bearer {}", server.token("planner"));
    let base = format!("{}/", server.url);
    let prefix = format!("{}/d/", server.url);

    let src = tempfile::tempdir().expect("temp dir");
    let file = src.path().join("build.zip");
    std::fs::write(&file, b"zip bytes").expect("write source file");
    let empty = src.path().join("empty.txt");
    std::fs::write(&empty, b"").expect("write empty file");

    // `curl -T file URL/` appends the local filename.
    for (path, name) in [(&file, "build.zip"), (&empty, "empty.txt")] {
        let args = [
            "-sS".to_string(),
            "-T".to_string(),
            path.display().to_string(),
            "-H".to_string(),
            auth.clone(),
            base.clone(),
        ];
        let out = tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            common::curl(&args)
        })
        .await
        .expect("curl task");
        assert!(out.status.success(), "curl -T {name} failed: {out:?}");
        let stdout = String::from_utf8(out.stdout).expect("utf-8");
        assert!(
            stdout.starts_with(&prefix) && stdout.ends_with(&format!("/{name}\n")),
            "curl printed {stdout:?}"
        );
    }

    // `printf x | curl -T - URL/name`.
    let url = format!("{}/piped.txt", server.url);
    let out = tokio::task::spawn_blocking(move || {
        let mut child = Command::new("curl")
            .args(["-sS", "-T", "-", "-H", &auth, &url])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn curl");
        child
            .stdin
            .take()
            .expect("curl stdin")
            .write_all(b"x")
            .expect("write to curl");
        child.wait_with_output().expect("curl output")
    })
    .await
    .expect("curl task");
    assert!(out.status.success(), "curl -T - failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        stdout.starts_with(&prefix) && stdout.ends_with("/piped.txt\n"),
        "curl printed {stdout:?}"
    );
    assert_eq!(server.state.store.stats().live_files, 3);
}
