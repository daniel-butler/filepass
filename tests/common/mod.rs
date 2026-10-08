//! Shared integration-test harness: `TestServer` runs the real app against
//! a fresh temp `data_dir` and an ephemeral loopback port, with a
//! controllable clock and a metrics recorder, so tests can assert on both
//! HTTP responses and emitted metric events.

#![allow(dead_code)]

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use filepass::app::{self, AppState};
use filepass::auth::{generate_token, hash_token};
use filepass::clock::TestClock;
use filepass::config::{AgentConfig, Config};
use filepass::obs::{Obs, Recorder};
use filepass::sweeper::Sweeper;

use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// A running instance of the app: a fresh `0700` temp `data_dir`, bound to
/// a real ephemeral loopback port so URLs it returns are fetchable, with
/// `planner` and `builder` test agents, a `TestClock`, and a metrics
/// `Recorder`.
pub struct TestServer {
    pub url: String,
    pub dir: TempDir,
    pub clock: Arc<TestClock>,
    pub metrics: Recorder,
    pub state: AppState,
    pub sweeper: Sweeper,
    pub tokens: HashMap<&'static str, String>,
    http: reqwest::Client,
    shutdown_tx: oneshot::Sender<()>,
    serve_task: JoinHandle<std::io::Result<()>>,
}

impl TestServer {
    /// Starts a server with spec-default config and fresh `planner` and
    /// `builder` tokens.
    pub async fn start() -> TestServer {
        TestServer::start_with(|_| {}).await
    }

    /// Like `start`, but calls `f` to adjust the config before the store
    /// opens and the server starts listening.
    pub async fn start_with(f: impl FnOnce(&mut Config)) -> TestServer {
        let dir = tempfile::Builder::new()
            .prefix("filepass-test-")
            .tempdir()
            .expect("create temp dir");
        // TempDir's own default mode isn't guaranteed to be 0700, and
        // Store::open refuses to run against anything looser.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("set temp dir mode 0700");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("listener local addr");

        let mut cfg = Config::for_tests(dir.path().to_path_buf());
        cfg.public_url = format!("http://{addr}");

        let mut tokens = HashMap::new();
        for name in ["planner", "builder"] {
            let token = generate_token();
            cfg.agents.insert(
                name.to_string(),
                AgentConfig {
                    token_sha256: hash_token(&token),
                },
            );
            tokens.insert(name, token);
        }

        f(&mut cfg);

        let clock = Arc::new(TestClock::new(SystemTime::UNIX_EPOCH));
        let (obs, metrics) = Obs::recording();

        let (state, _recovery) =
            app::build_state(cfg, clock.clone(), obs).expect("build app state");

        let sweeper = Sweeper::new(state.clone());

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let shutdown_signal = async move {
            let _ = shutdown_rx.await;
        };

        let serve_task = tokio::spawn(app::serve(listener, state.clone(), shutdown_signal));

        TestServer {
            url: format!("http://{addr}"),
            dir,
            clock,
            metrics,
            state,
            sweeper,
            tokens,
            http: reqwest::Client::new(),
            shutdown_tx,
            serve_task,
        }
    }

    /// `PUT <self.url><path>`, with `Authorization: Bearer <token>` when
    /// `agent` names a test agent, and `Filepass-TTL: <ttl>` when given.
    pub async fn put(
        &self,
        path: &str,
        body: Vec<u8>,
        agent: Option<&str>,
        ttl: Option<&str>,
    ) -> reqwest::Response {
        let mut req = self.http.put(format!("{}{path}", self.url)).body(body);
        if let Some(agent) = agent {
            req = req.header("Authorization", format!("Bearer {}", self.token(agent)));
        }
        if let Some(ttl) = ttl {
            req = req.header("Filepass-TTL", ttl);
        }
        req.send().await.expect("PUT request should complete")
    }

    /// `GET <url>`, unauthenticated, as a downloader would send it.
    pub async fn get(&self, url: &str) -> reqwest::Response {
        self.http
            .get(url)
            .send()
            .await
            .expect("GET request should complete")
    }

    /// `DELETE <url>`, with `Authorization: Bearer <token>` when `agent`
    /// names a test agent.
    pub async fn delete(&self, url: &str, agent: Option<&str>) -> reqwest::Response {
        let mut req = self.http.delete(url);
        if let Some(agent) = agent {
            req = req.header("Authorization", format!("Bearer {}", self.token(agent)));
        }
        req.send().await.expect("DELETE request should complete")
    }

    /// Sends the shutdown signal and waits for `serve` to return, reporting
    /// how long that took.
    pub async fn shutdown(self) -> Duration {
        let start = Instant::now();
        let _ = self.shutdown_tx.send(());
        let _ = self.serve_task.await;
        start.elapsed()
    }

    /// Opens a raw TCP connection and writes the head of
    /// `PUT <path>` with `Content-Length: <content_length>` (and a bearer
    /// token when `agent` names a test agent), but no body. The caller
    /// controls the body: send it all, trickle it, stall, or close. For
    /// behaviour reqwest can't express.
    pub async fn raw_put(&self, path: &str, agent: Option<&str>, content_length: u64) -> TcpStream {
        let addr = self.url.trim_start_matches("http://");
        let mut stream = TcpStream::connect(addr)
            .await
            .expect("connect to test server");
        let mut head =
            format!("PUT {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {content_length}\r\n");
        if let Some(agent) = agent {
            head.push_str(&format!("Authorization: Bearer {}\r\n", self.token(agent)));
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .await
            .expect("write request head");
        stream
    }

    /// The bearer token of test agent `agent`.
    pub fn token(&self, agent: &str) -> &str {
        self.tokens
            .get(agent)
            .unwrap_or_else(|| panic!("unknown test agent {agent:?}"))
    }
}

/// Reads the status code of the HTTP response arriving on `stream` (a
/// `raw_put` connection or its read half), failing the test if no status
/// line arrives within 5 s.
pub async fn read_status<R: AsyncRead + Unpin>(stream: &mut R) -> u16 {
    let read_line = async {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while !line.ends_with(b"\r\n") {
            let n = stream.read(&mut byte).await.expect("read response");
            assert!(n > 0, "connection closed before a status line arrived");
            line.push(byte[0]);
        }
        line
    };
    let line = tokio::time::timeout(Duration::from_secs(5), read_line)
        .await
        .expect("no response status within 5 s");
    let line = String::from_utf8(line).expect("status line is UTF-8");
    line.split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("malformed status line {line:?}"))
}

/// Polls `cond` every 20 ms for up to 2 s; true once it holds.
pub async fn eventually(mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
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

/// Runs `curl` with `args`, for tests that need curl's own behavior (exit
/// codes on a closed connection, `-T -`, range resumes) rather than
/// reqwest's.
pub fn curl(args: &[&str]) -> std::process::Output {
    std::process::Command::new("curl")
        .args(args)
        .output()
        .expect("failed to execute curl")
}
