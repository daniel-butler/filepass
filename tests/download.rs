//! Download tests: the spec's Download section (check order, headers,
//! ranges, slots, timeouts, revoke and expiry mid-transfer) and the
//! `download`, `download_bytes`, `time_to_first_download_ms`, and
//! `throttled` metric events.
//!
//! Revocation goes through `Store::revoke` directly (ruling R2): HTTP
//! `DELETE` is Task 10's. Behaviour reqwest can't express (a reader that
//! never reads) goes over raw TCP; curl's own exit codes come from the real
//! curl binary, and those tests skip when it is absent.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{eventually, read_status, TestServer};
use filepass::obs::Recorder;
use filepass::store::RevokeOutcome;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const MIB: usize = 1 << 20;

/// A file too big to fit in the pipe between the producer and a reader
/// that has stopped or slowed down. On macOS loopback the producer's
/// channel, hyper's write buffer, and the autotuned socket buffers absorb
/// about 3 MiB before a send blocks (up to ~10 MiB on Linux); a test that
/// needs the producer still running when something happens must outlast
/// that.
const BIG: usize = 32 * MIB;

/// True if `recorder` holds a `name` event carrying every one of `labels`.
fn has_event(recorder: &Recorder, name: &str, labels: &[(&str, &str)]) -> bool {
    count_events(recorder, name, labels) > 0
}

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

fn header<'a>(resp: &'a reqwest::Response, name: &str) -> &'a str {
    resp.headers()
        .get(name)
        .unwrap_or_else(|| panic!("missing {name} header"))
        .to_str()
        .expect("header is ASCII")
}

/// `n` bytes of a repeating, position-dependent pattern, so a misplaced
/// slice cannot pass for the right one.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// An uploaded file's download URL and its two path segments.
struct Uploaded {
    url: String,
    id: String,
    urlname: String,
}

/// Uploads `body` as `planner` under the URL-encoded name `path_name` and
/// returns its download URL.
async fn upload(server: &TestServer, path_name: &str, body: Vec<u8>) -> Uploaded {
    let resp = server
        .put(&format!("/{path_name}"), body, Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201, "upload of {path_name}");
    let url = resp.text().await.expect("upload body").trim().to_string();
    let rest = url
        .split("/d/")
        .nth(1)
        .expect("download URL has /d/")
        .to_string();
    let (id, urlname) = rest.split_once('/').expect("id/urlname");
    Uploaded {
        id: id.to_string(),
        urlname: urlname.to_string(),
        url,
    }
}

/// `GET url` with extra request headers, on a fresh client (so it gets its
/// own connection).
async fn get_with(url: &str, headers: &[(&str, &str)]) -> reqwest::Response {
    let mut req = reqwest::Client::new().get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send().await.expect("GET request should complete")
}

/// Polls `cond` every 20 ms for up to `limit`; true once it holds.
async fn eventually_within(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// True once no download holds a slot or a per-key table entry.
fn download_counters_zero(server: &TestServer) -> bool {
    server.state.limits.downloads_in_flight() == 0 && server.state.limits.download_keys() == 0
}

/// True if a `curl` binary runs.
fn curl_available() -> bool {
    Command::new("curl").arg("--version").output().is_ok()
}

/// Starts `curl -sS --limit-rate 1M -o <out> <url>` as a child process.
/// At 1 MiB/s a `BIG` file takes 32 s, so it is mid-transfer when the test
/// acts, and once the producer stops curl drains what the socket buffers
/// still hold within a few seconds (at 64k that drain alone took ~20 s).
fn spawn_slow_curl(out: &std::path::Path, url: &str) -> std::process::Child {
    Command::new("curl")
        .args(["-sS", "--limit-rate", "1M", "-o"])
        .arg(out)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn curl")
}

/// Waits up to 60 s for `child` to exit and returns its exit code.
async fn curl_exit_code(child: std::process::Child) -> i32 {
    let out = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::task::spawn_blocking(move || child.wait_with_output().expect("curl output")),
    )
    .await
    .expect("curl did not exit within 60 s")
    .expect("curl task");
    out.status
        .code()
        .unwrap_or_else(|| panic!("curl killed by a signal: {out:?}"))
}

#[tokio::test]
async fn full_download_headers() {
    let server = TestServer::start().await;
    let body = pattern(1000);
    let file = upload(&server, "my%20file.zip", body.clone()).await;

    let resp = server.get(&file.url).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "content-length"), "1000");
    assert_eq!(header(&resp, "content-type"), "application/octet-stream");
    assert_eq!(
        header(&resp, "content-disposition"),
        "attachment; filename=\"my_file.zip\"; filename*=UTF-8''my%20file.zip"
    );
    assert_eq!(header(&resp, "x-content-type-options"), "nosniff");
    assert_eq!(header(&resp, "cache-control"), "private, no-store");
    assert_eq!(header(&resp, "referrer-policy"), "no-referrer");
    assert_eq!(header(&resp, "filepass-sha256"), sha256_hex(&body));
    let expires = humantime::parse_rfc3339(header(&resp, "filepass-expires"))
        .expect("Filepass-Expires is RFC 3339");
    assert_eq!(
        expires,
        std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(30 * 60)
    );
    assert!(resp.headers().get("content-range").is_none());
    assert!(resp.headers().get("etag").is_none());
    assert!(resp.headers().get("last-modified").is_none());
    assert_eq!(resp.bytes().await.expect("body").as_ref(), &body[..]);

    let metrics = &server.metrics;
    assert!(eventually(|| has_event(metrics, "download", &[("result", "ok")])).await);
    let bytes: Vec<f64> = metrics
        .events()
        .iter()
        .filter(|e| e.name == "download_bytes")
        .map(|e| e.value)
        .collect();
    assert_eq!(bytes, vec![1000.0]);
    assert!(eventually(|| download_counters_zero(&server)).await);
}

#[tokio::test]
async fn ranges() {
    let server = TestServer::start().await;
    let body: Vec<u8> = (0u8..10).collect();
    let file = upload(&server, "ten.bin", body.clone()).await;

    let resp = get_with(&file.url, &[("Range", "bytes=2-5")]).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(header(&resp, "content-range"), "bytes 2-5/10");
    assert_eq!(header(&resp, "content-length"), "4");
    assert_eq!(header(&resp, "content-type"), "application/octet-stream");
    assert_eq!(resp.bytes().await.expect("body").as_ref(), &body[2..=5]);

    // Suffix longer than the file: the whole file, as 206.
    let resp = get_with(&file.url, &[("Range", "bytes=-50")]).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(header(&resp, "content-range"), "bytes 0-9/10");
    assert_eq!(resp.bytes().await.expect("body").as_ref(), &body[..]);

    // End beyond the file is clamped.
    let resp = get_with(&file.url, &[("Range", "bytes=7-100")]).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(header(&resp, "content-range"), "bytes 7-9/10");
    assert_eq!(header(&resp, "content-length"), "3");
    assert_eq!(resp.bytes().await.expect("body").as_ref(), &body[7..]);

    let resp = get_with(&file.url, &[("Range", "bytes=10-")]).await;
    assert_eq!(resp.status(), 416);
    assert_eq!(header(&resp, "content-range"), "bytes */10");
    assert!(
        eventually(|| has_event(
            &server.metrics,
            "download",
            &[("result", "range_not_satisfiable")]
        ))
        .await
    );

    for ignored in ["bytes=x", "bytes=0-1,4-5"] {
        let resp = get_with(&file.url, &[("Range", ignored)]).await;
        assert_eq!(resp.status(), 200, "Range: {ignored}");
        assert_eq!(header(&resp, "content-length"), "10");
        assert!(resp.headers().get("content-range").is_none());
        assert_eq!(resp.bytes().await.expect("body").as_ref(), &body[..]);
    }

    let empty = upload(&server, "empty.bin", Vec::new()).await;
    let resp = get_with(&empty.url, &[("Range", "bytes=0-")]).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "content-length"), "0");
    assert!(resp.bytes().await.expect("body").is_empty());

    assert!(eventually(|| download_counters_zero(&server)).await);
}

#[tokio::test]
async fn not_found_and_gone() {
    let server = TestServer::start().await;
    let file = upload(&server, "a.txt", b"abc".to_vec()).await;
    let other = upload(&server, "b.txt", b"def".to_vec()).await;
    let base = format!("{}/d", server.url);

    let not_found = [
        format!("{base}/XYZ/a.txt"),
        format!("{base}/{}/a.txt", file.id.to_uppercase()),
        format!("{base}/{}/a.txt", filepass::store::new_id()),
        format!("{base}/{}/b.txt", file.id),
        format!("{base}/{}/%FF", file.id),
        format!("{base}/{}/a%2Etxt", file.id),
    ];
    for url in &not_found {
        let resp = server.get(url).await;
        assert_eq!(resp.status(), 404, "{url}");
    }
    assert!(
        eventually(
            || count_events(&server.metrics, "download", &[("result", "not_found")])
                == not_found.len()
        )
        .await
    );

    // Revoked: 410.
    assert_eq!(
        server
            .state
            .store
            .revoke(&other.id, &other.urlname, "planner")
            .await,
        RevokeOutcome::Revoked
    );
    assert_eq!(server.get(&other.url).await.status(), 410);

    // Past expires_at, before any sweep: 410.
    assert_eq!(server.get(&file.url).await.status(), 200);
    server.clock.advance(Duration::from_secs(30 * 60));
    assert_eq!(server.get(&file.url).await.status(), 410);
    // Expired by the sweeper: still 410.
    server.sweeper.run_once().await;
    assert_eq!(server.get(&file.url).await.status(), 410);
    assert!(
        eventually(|| count_events(&server.metrics, "download", &[("result", "gone")]) == 3).await
    );

    // Once the tombstones expire: 404.
    server.clock.advance(Duration::from_secs(48 * 3600 + 1));
    server.sweeper.run_once().await;
    assert_eq!(server.get(&file.url).await.status(), 404);
    assert_eq!(server.get(&other.url).await.status(), 404);

    // No rejected request took a slot or emitted download_bytes: only the
    // one served GET did.
    assert!(download_counters_zero(&server));
    assert_eq!(count_events(&server.metrics, "download_bytes", &[]), 1);
}

#[tokio::test]
async fn head_takes_no_slot_and_no_metric() {
    let server = TestServer::start_with(|cfg| cfg.max_concurrent_downloads = 1).await;
    let body = pattern(BIG);
    let file = upload(&server, "big.bin", body).await;

    // Hold one GET open without reading its body: it keeps the only slot.
    let held = get_with(&file.url, &[]).await;
    assert_eq!(held.status(), 200);
    assert_eq!(server.state.limits.downloads_in_flight(), 1);

    let client = reqwest::Client::new();
    let resp = client.head(&file.url).send().await.expect("HEAD");
    assert_eq!(resp.status(), 200);
    assert_eq!(header(&resp, "content-length"), BIG.to_string());
    assert_eq!(header(&resp, "content-type"), "application/octet-stream");
    assert_eq!(header(&resp, "x-content-type-options"), "nosniff");

    let resp = client
        .head(&file.url)
        .header("Range", "bytes=0-9")
        .send()
        .await
        .expect("ranged HEAD");
    assert_eq!(resp.status(), 206);
    assert_eq!(header(&resp, "content-length"), "10");
    assert_eq!(header(&resp, "content-range"), format!("bytes 0-9/{BIG}"));

    let bogus = format!("{}/d/{}/big.bin", server.url, filepass::store::new_id());
    let resp = client.head(&bogus).send().await.expect("HEAD bogus");
    assert_eq!(resp.status(), 404);

    // The held GET is still running, and no HEAD emitted anything.
    assert_eq!(server.state.limits.downloads_in_flight(), 1);
    assert!(!server.metrics.events().iter().any(|e| e.name == "download"));
    assert!(!server
        .metrics
        .events()
        .iter()
        .any(|e| e.name == "throttled"));

    drop(held);
    assert!(eventually(|| download_counters_zero(&server)).await);
    assert!(
        eventually(|| has_event(&server.metrics, "download", &[("result", "client_aborted")]))
            .await
    );
    assert_eq!(
        count_events(&server.metrics, "download", &[]),
        1,
        "only the GET emits download"
    );
}

#[tokio::test]
async fn download_limits() {
    let server = TestServer::start_with(|cfg| {
        cfg.max_downloads_per_ip = 1;
        cfg.max_concurrent_downloads = 1;
    })
    .await;
    let file = upload(&server, "big.bin", pattern(BIG)).await;

    let held = get_with(&file.url, &[]).await;
    assert_eq!(held.status(), 200);

    // Same client key: per-key limit first.
    let resp = get_with(&file.url, &[]).await;
    assert_eq!(resp.status(), 429);
    assert_eq!(header(&resp, "retry-after"), "1");
    assert!(has_event(
        &server.metrics,
        "throttled",
        &[("reason", "downloads_per_ip")]
    ));

    // Another key (via X-Forwarded-For from the trusted loopback peer):
    // the server-wide limit.
    let resp = get_with(&file.url, &[("X-Forwarded-For", "203.0.113.9")]).await;
    assert_eq!(resp.status(), 503);
    assert_eq!(header(&resp, "retry-after"), "1");
    assert!(has_event(
        &server.metrics,
        "throttled",
        &[("reason", "downloads_total")]
    ));
    assert_eq!(
        count_events(&server.metrics, "download", &[("result", "busy")]),
        2
    );
    // A rejected key never enters the per-key table.
    assert_eq!(server.state.limits.download_keys(), 1);

    // Invalid requests never reach the limiter.
    let bogus = format!("{}/d/{}/big.bin", server.url, filepass::store::new_id());
    for url in [bogus, format!("{}/d/nothex/big.bin", server.url)] {
        let resp = get_with(&url, &[]).await;
        assert_eq!(resp.status(), 404, "{url}");
    }
    let mismatch = format!("{}/d/{}/other.bin", server.url, file.id);
    assert_eq!(get_with(&mismatch, &[]).await.status(), 404);
    let revoked = upload(&server, "gone.bin", b"x".to_vec()).await;
    server
        .state
        .store
        .revoke(&revoked.id, &revoked.urlname, "planner")
        .await;
    assert_eq!(get_with(&revoked.url, &[]).await.status(), 410);
    assert_eq!(
        count_events(&server.metrics, "throttled", &[]),
        2,
        "invalid requests are never throttled"
    );

    drop(held);
    assert!(eventually(|| download_counters_zero(&server)).await);
    let resp = get_with(&file.url, &[("Range", "bytes=0-0")]).await;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.bytes().await.expect("body").as_ref(), &[0u8]);
    assert!(eventually(|| download_counters_zero(&server)).await);
}

#[tokio::test]
async fn revoke_aborts_and_curl_fails() {
    if !curl_available() {
        eprintln!("curl not found; skipping revoke_aborts_and_curl_fails");
        return;
    }
    let server = TestServer::start().await;
    let file = upload(&server, "big.bin", pattern(BIG)).await;
    let dir = tempfile::tempdir().expect("temp dir");
    let out = dir.path().join("out.bin");

    let child = spawn_slow_curl(&out, &file.url);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        server
            .state
            .store
            .revoke(&file.id, &file.urlname, "planner")
            .await,
        RevokeOutcome::Revoked
    );

    assert_eq!(
        curl_exit_code(child).await,
        18,
        "curl must see a short body"
    );
    assert!(
        std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0) < BIG as u64,
        "curl saved the whole file"
    );
    assert!(eventually(|| has_event(&server.metrics, "download", &[("result", "revoked")])).await);
    assert!(eventually(|| download_counters_zero(&server)).await);
}

#[tokio::test]
async fn max_duration_aborts() {
    if !curl_available() {
        eprintln!("curl not found; skipping max_duration_aborts");
        return;
    }
    let server =
        TestServer::start_with(|cfg| cfg.max_download_duration = Duration::from_secs(1)).await;
    let file = upload(&server, "big.bin", pattern(BIG)).await;
    let dir = tempfile::tempdir().expect("temp dir");
    let out = dir.path().join("out.bin");

    let child = spawn_slow_curl(&out, &file.url);
    assert_eq!(
        curl_exit_code(child).await,
        18,
        "curl must see a short body"
    );
    assert!(eventually(|| has_event(&server.metrics, "download", &[("result", "timeout")])).await);
    assert!(eventually(|| download_counters_zero(&server)).await);
}

#[tokio::test]
async fn stalled_reader_releases_slot() {
    let server =
        TestServer::start_with(|cfg| cfg.download_idle_timeout = Duration::from_secs(1)).await;
    let file = upload(&server, "big.bin", pattern(BIG)).await;

    let addr = server.url.trim_start_matches("http://").to_string();
    let path = file.url.trim_start_matches(&server.url).to_string();
    let mut stream = TcpStream::connect(&addr).await.expect("connect");
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    assert_eq!(read_status(&mut stream).await, 200);
    assert_eq!(server.state.limits.downloads_in_flight(), 1);

    // Never read another byte.
    assert!(
        eventually_within(Duration::from_secs(5), || download_counters_zero(&server)).await,
        "a stalled reader kept its slot"
    );
    assert!(has_event(
        &server.metrics,
        "download",
        &[("result", "timeout")]
    ));
    drop(stream);
}

#[tokio::test]
async fn expiry_mid_download_completes() {
    let server = TestServer::start().await;
    let body = pattern(BIG);
    let file = upload(&server, "big.bin", body.clone()).await;

    let mut resp = server.get(&file.url).await;
    assert_eq!(resp.status(), 200);
    let mut received = resp
        .chunk()
        .await
        .expect("first chunk")
        .expect("body not empty")
        .to_vec();

    // The reader pauses; the producer fills the pipe and blocks.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Expire the file and let the sweeper end it (unlinking the blob)
    // while the producer is still reading it.
    server.clock.advance(Duration::from_secs(31 * 60));
    server.sweeper.run_once().await;
    assert!(!server.dir.path().join("files").join(&file.id).exists());
    assert_eq!(server.get(&file.url).await.status(), 410);
    assert_eq!(
        server.state.limits.downloads_in_flight(),
        1,
        "the producer finished before the sweep; the test proves nothing"
    );

    while let Some(chunk) = resp.chunk().await.expect("next chunk") {
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received.len(), body.len());
    assert_eq!(sha256_hex(&received), sha256_hex(&body));
    assert!(eventually(|| has_event(&server.metrics, "download", &[("result", "ok")])).await);
}

#[tokio::test]
async fn first_download_metric_once() {
    let server = TestServer::start().await;
    let file = upload(&server, "a.txt", b"abc".to_vec()).await;

    server.clock.advance(Duration::from_secs(90));
    for _ in 0..2 {
        let resp = server.get(&file.url).await;
        assert_eq!(resp.status(), 200);
        resp.bytes().await.expect("body");
    }
    let ranged = get_with(&file.url, &[("Range", "bytes=1-")]).await;
    assert_eq!(ranged.status(), 206);

    let firsts: Vec<_> = server
        .metrics
        .events()
        .into_iter()
        .filter(|e| e.name == "time_to_first_download_ms")
        .collect();
    assert_eq!(firsts.len(), 1);
    assert_eq!(firsts[0].labels, vec![("agent", "planner".to_string())]);
    assert_eq!(firsts[0].value, 90_000.0);
}

#[tokio::test]
async fn curl_resume() {
    if !curl_available() {
        eprintln!("curl not found; skipping curl_resume");
        return;
    }
    let server = TestServer::start().await;
    let body = pattern(MIB + 12_345);
    let file = upload(&server, "resume.bin", body.clone()).await;

    let dir = tempfile::tempdir().expect("temp dir");
    let out = dir.path().join("resume.bin");
    std::fs::write(&out, &body[..300_000]).expect("write partial file");

    let args = [
        "-sS".to_string(),
        "-f".to_string(),
        "-C".to_string(),
        "-".to_string(),
        "-o".to_string(),
        out.display().to_string(),
        file.url.clone(),
    ];
    let result = tokio::task::spawn_blocking(move || {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        common::curl(&args)
    })
    .await
    .expect("curl task");
    assert!(result.status.success(), "curl -C - failed: {result:?}");
    let saved = std::fs::read(&out).expect("read resumed file");
    assert_eq!(saved.len(), body.len());
    assert_eq!(sha256_hex(&saved), sha256_hex(&body));
    assert!(eventually(|| has_event(&server.metrics, "download", &[("result", "ok")])).await);
    // curl asked for the remainder only.
    let served: Vec<f64> = server
        .metrics
        .events()
        .iter()
        .filter(|e| e.name == "download_bytes")
        .map(|e| e.value)
        .collect();
    assert_eq!(served, vec![(body.len() - 300_000) as f64]);
}
