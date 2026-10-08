//! Shutdown tests: the spec's Shutdown section. SIGTERM/Ctrl-C triggers
//! axum's graceful shutdown, which is raced against `shutdown_grace` so the
//! process exits by that deadline even with an in-flight download.

mod common;

use std::time::Duration;

use common::{read_status, TestServer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const MIB: usize = 1 << 20;
/// Large enough that the download's producer is still sending (not just
/// sitting on an idle, already-finished connection) when shutdown starts.
/// See `tests/download.rs`'s `BIG` for the sizing rationale: on loopback,
/// the producer's channel and the autotuned socket buffers absorb a few
/// MiB before a send blocks.
const BIG: usize = 32 * MIB;

/// `n` bytes of a repeating, position-dependent pattern.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn shutdown_within_grace_during_download() {
    let server = TestServer::start_with(|cfg| cfg.shutdown_grace = Duration::from_secs(1)).await;

    let resp = server
        .put("/big.bin", pattern(BIG), Some("planner"), None)
        .await;
    assert_eq!(resp.status(), 201);
    let url = resp.text().await.expect("upload body").trim().to_string();

    // A raw connection that reads the response status and headers, then
    // never reads another byte: the producer is left mid-transfer, so the
    // connection is genuinely in flight when `shutdown` runs below.
    let addr = server.url.trim_start_matches("http://").to_string();
    let path = url.trim_start_matches(&server.url).to_string();
    let mut stream = TcpStream::connect(&addr).await.expect("connect");
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n\r\n").as_bytes())
        .await
        .expect("write request");
    assert_eq!(read_status(&mut stream).await, 200);

    let elapsed = server.shutdown().await;
    assert!(
        elapsed < Duration::from_secs(3),
        "shutdown took {elapsed:?}, expected well under 3s with a 1s grace"
    );

    drop(stream);
}
