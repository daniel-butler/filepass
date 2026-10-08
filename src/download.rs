//! `GET`/`HEAD` and `DELETE` handling on `/d/{id}/{urlname}`.
//!
//! `get` evaluates a download in the spec's check order: id and name
//! (`404`); state and expiry (`410`); `Range` (`416`); for `GET` only, the
//! download slots (`429`/`503`); then it opens the file (`410` if it
//! vanished) and serves it. `HEAD` stops before the slots: it answers the
//! same headers with no body, takes no slot, and emits no metric.
//!
//! A served `GET` spawns a producer task that owns the file descriptor, the
//! `DownloadSlot`, and the `DownloadMetric` guard. It reads 256 KiB chunks
//! into a channel of 4 that the response body drains, and stops when the
//! file is sent, a send stalls for `download_idle_timeout`, the transfer
//! passes `max_download_duration`, a revoke fires the file's cancellation
//! token, or the client disconnects. A timer inside the body could not do
//! this: once the client stops reading, hyper stops polling the body.
//!
//! Every `200`/`206` sets `Content-Length`, so a producer that stops early
//! leaves the body short and the client (curl: exit 18) sees a failure,
//! not a clean end. When it stops early it also tells the body to fail at
//! once, so the client does not first drain the chunks still queued for a
//! file that was revoked.
//!
//! Per "Handlers own every response", `get` reads `id` and `urlname` from
//! the raw `Uri` and uses only infallible extractors, so every `GET`
//! emits exactly one `download` event.
//!
//! `delete` revokes a file on behalf of its uploader, in the spec's Revoke
//! check order: token (`401`); id and name (`404`); uploader (`403`);
//! state (`410`); otherwise `204` and the file is ended via
//! `Store::revoke`. Like `get`, it reads `id` and `urlname` from the raw
//! `Uri`, so every `DELETE` emits exactly one `revoke` event.

use std::io::{self, SeekFrom};
use std::net::IpAddr;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE,
    REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, timeout, Instant};
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::Instrument;

use crate::app::AppState;
use crate::auth::MaybeAgent;
use crate::client_ip::ClientAddr;
use crate::limits::DownloadSlot;
use crate::names;
use crate::obs::{log_size, log_str, Obs, Outcome};
use crate::range::{self, RangeDecision};
use crate::store::{LiveFile, Lookup, RevokeOutcome};

/// Bytes per read, and per chunk sent to the response body.
const CHUNK_SIZE: usize = 256 * 1024;
/// Chunks the producer may queue ahead of the response body.
const CHANNEL_CHUNKS: usize = 4;

const FILEPASS_EXPIRES: HeaderName = HeaderName::from_static("filepass-expires");
const FILEPASS_SHA256: HeaderName = HeaderName::from_static("filepass-sha256");

/// Emits exactly one `download` event when dropped (none for `HEAD`), and
/// `download_bytes` for a request whose body was served. Its outcome
/// starts as `ClientAborted`: a disconnect drops the handler future, and
/// only `Drop` runs then. A served download's guard moves into the
/// producer task, so the event fires when the transfer ends.
struct DownloadMetric {
    /// `None` for `HEAD`, which emits nothing.
    obs: Option<Obs>,
    outcome: Outcome,
    /// True once the producer starts; only then is `download_bytes` sent.
    served: bool,
    /// Bytes handed to the response body.
    bytes: u64,
    client_ip: IpAddr,
    /// The first 8 characters of the requested id, once the path parses.
    id: Option<String>,
    /// The file's uploader, once it is found.
    agent: Option<String>,
    /// The file's original filename, once it is found.
    filename: Option<String>,
}

impl DownloadMetric {
    fn new(obs: Option<Obs>, client_ip: IpAddr) -> DownloadMetric {
        DownloadMetric {
            obs,
            outcome: Outcome::ClientAborted,
            served: false,
            bytes: 0,
            client_ip,
            id: None,
            agent: None,
            filename: None,
        }
    }
}

impl Drop for DownloadMetric {
    fn drop(&mut self) {
        let Some(obs) = &self.obs else {
            return;
        };
        obs.counter("download", &[("result", self.outcome.as_str())], 1);
        if self.served {
            obs.counter("download_bytes", &[], self.bytes);
        }
        let size = self.served.then_some(self.bytes);
        tracing::info!(
            agent = log_str(self.agent.as_deref()),
            id = log_str(self.id.as_deref()),
            filename = log_str(self.filename.as_deref()),
            size = %log_size(size),
            client_ip = %self.client_ip,
            result = self.outcome.as_str(),
            "download request handled"
        );
    }
}

/// Records `outcome` on `metric` and answers the bare `status`.
fn fail(metric: &mut DownloadMetric, status: StatusCode, outcome: Outcome) -> Response {
    metric.outcome = outcome;
    status.into_response()
}

/// The raw `id` and `urlname` segments of a `/d/{id}/{urlname}` path, or
/// `None` if the path has another shape. Nothing is percent-decoded: the
/// id must be lowercase hex and the stored urlname contains nothing to
/// decode, so any encoded byte is simply a mismatch (`404`).
fn segments(path: &str) -> Option<(&str, &str)> {
    let (id, urlname) = path.strip_prefix("/d/")?.split_once('/')?;
    (!urlname.contains('/')).then_some((id, urlname))
}

/// The first 8 bytes of `s`, or all of it if shorter: a safe log prefix for
/// an id that has not yet been validated as 32 hex characters. `s` is
/// always ASCII here (a raw, still-encoded path segment from the URI), so
/// slicing by byte count never splits a multi-byte character.
fn short(s: &str) -> &str {
    &s[..s.len().min(8)]
}

/// What a satisfiable request serves: the status, the first byte, and the
/// number of bytes.
struct Span {
    status: StatusCode,
    start: u64,
    len: u64,
}

/// The response headers for serving `span` of `file`, per the spec.
fn file_headers(file: &LiveFile, span: &Span) -> Result<HeaderMap, axum::http::Error> {
    let expires = humantime::format_rfc3339_seconds(file.expires_at).to_string();
    let mut headers = HeaderMap::new();
    let mut set = |name: HeaderName, value: String| -> Result<(), axum::http::Error> {
        headers.insert(name, HeaderValue::try_from(value)?);
        Ok(())
    };
    set(CONTENT_TYPE, "application/octet-stream".to_string())?;
    set(
        CONTENT_DISPOSITION,
        names::content_disposition(&file.name, &file.urlname),
    )?;
    set(X_CONTENT_TYPE_OPTIONS, "nosniff".to_string())?;
    set(CACHE_CONTROL, "private, no-store".to_string())?;
    set(REFERRER_POLICY, "no-referrer".to_string())?;
    set(FILEPASS_SHA256, file.sha256.clone())?;
    set(FILEPASS_EXPIRES, expires)?;
    set(CONTENT_LENGTH, span.len.to_string())?;
    if span.status == StatusCode::PARTIAL_CONTENT {
        let end = span.start + span.len - 1;
        set(
            CONTENT_RANGE,
            format!("bytes {}-{end}/{}", span.start, file.size),
        )?;
    }
    Ok(headers)
}

/// A response body that yields the producer's chunks until the channel
/// closes, or fails as soon as `abort` fires (the producer stopped early)
/// or `revoked` fires (the file's own cancellation token). Failing (rather
/// than ending) makes hyper close the connection short of
/// `Content-Length`, and both take priority over chunks still queued.
/// Watching `revoked` here, not only in the producer, matters once the
/// producer has queued its last chunk and returned `Ok`: up to
/// `CHANNEL_CHUNKS` chunks may still be waiting, and a revoke must stop
/// them too.
fn body_from(
    rx: mpsc::Receiver<Bytes>,
    abort: CancellationToken,
    revoked: CancellationToken,
) -> Body {
    let stream = futures_util::stream::unfold(Some((rx, abort, revoked)), |state| async move {
        let (mut rx, abort, revoked) = state?;
        let stopped = || Some((Err(io::Error::other("download stopped early")), None));
        tokio::select! {
            biased;
            () = abort.cancelled() => stopped(),
            () = revoked.cancelled() => stopped(),
            chunk = rx.recv() => chunk.map(|chunk| (Ok(chunk), Some((rx, abort, revoked)))),
        }
    });
    Body::from_stream(stream)
}

/// Everything the producer task owns.
struct Producer {
    file: File,
    /// Bytes left to send.
    len: u64,
    tx: mpsc::Sender<Bytes>,
    /// The file's revocation token.
    cancel: CancellationToken,
    /// Fires the body's abort unless disarmed; disarmed only when the whole
    /// span was sent.
    abort: DropGuard,
    idle_timeout: Duration,
    deadline: Instant,
    id_prefix: String,
    metric: DownloadMetric,
    _slot: DownloadSlot,
}

impl Producer {
    /// Runs the transfer and records how it ended. Dropping `self` at the
    /// end closes the file and releases the slot.
    async fn run(mut self) {
        // Until the transfer resolves, the guard reports an error, so a
        // panic unwinds through it as `error`, not `client_aborted`.
        self.metric.outcome = Outcome::Error;
        let outcome = tokio::select! {
            biased;
            () = self.cancel.cancelled() => Outcome::Revoked,
            () = sleep_until(self.deadline) => Outcome::Timeout,
            outcome = send_file(
                &mut self.file,
                self.len,
                &self.tx,
                self.idle_timeout,
                &self.id_prefix,
                &mut self.metric.bytes,
            ) => outcome,
        };
        self.metric.outcome = outcome;
        if outcome == Outcome::Ok {
            self.abort.disarm();
        }
    }
}

/// Sends `len` bytes of `file`, from its current position, into `tx` in
/// `CHUNK_SIZE` chunks, counting them into `sent`. Each send must be
/// accepted within `idle_timeout`.
async fn send_file(
    file: &mut File,
    len: u64,
    tx: &mpsc::Sender<Bytes>,
    idle_timeout: Duration,
    id_prefix: &str,
    sent: &mut u64,
) -> Outcome {
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(CHUNK_SIZE as u64) as usize;
        let mut chunk = vec![0; n];
        if let Err(e) = file.read_exact(&mut chunk).await {
            tracing::error!(id = id_prefix, error = %e, "reading download failed");
            return Outcome::Error;
        }
        match timeout(idle_timeout, tx.send(Bytes::from(chunk))).await {
            Err(_elapsed) => return Outcome::Timeout,
            // The receiver is gone: the client disconnected.
            Ok(Err(_)) => return Outcome::ClientAborted,
            Ok(Ok(())) => {}
        }
        *sent += n as u64;
        remaining -= n as u64;
    }
    Outcome::Ok
}

/// `GET`/`HEAD /d/{id}/{urlname}`: a download, evaluated in the spec's
/// check order. For `GET`, the `download` metric guard is built first, so
/// every exit emits exactly one `download` event.
pub async fn get(
    State(state): State<AppState>,
    client: ClientAddr,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let started = Instant::now();
    let is_get = method == Method::GET;
    let mut metric = DownloadMetric::new(is_get.then(|| state.obs.clone()), client.ip);

    // Steps 1-2: id, name, state, and expiry, in one lock acquisition.
    let Some((id, urlname)) = segments(uri.path()) else {
        return fail(&mut metric, StatusCode::NOT_FOUND, Outcome::NotFound);
    };
    metric.id = Some(short(id).to_string());
    let file = match state.store.lookup(id, urlname) {
        Lookup::NotFound => return fail(&mut metric, StatusCode::NOT_FOUND, Outcome::NotFound),
        Lookup::Gone => return fail(&mut metric, StatusCode::GONE, Outcome::Gone),
        Lookup::Live(file) => file,
    };
    metric.agent = Some(file.uploader.clone());
    metric.filename = Some(file.name.clone());
    // `lookup` accepted `id`, so it is 32 hex characters.
    let id_prefix = &id[..8];

    // Step 3: range. A header that is not visible ASCII is malformed, and
    // a malformed `Range` is ignored.
    let range = headers.get(RANGE).and_then(|v| v.to_str().ok());
    let span = match range::decide(range, file.size) {
        RangeDecision::Full => Span {
            status: StatusCode::OK,
            start: 0,
            len: file.size,
        },
        RangeDecision::Partial { start, end } => Span {
            status: StatusCode::PARTIAL_CONTENT,
            start,
            len: end - start + 1,
        },
        RangeDecision::Unsatisfiable => {
            metric.outcome = Outcome::RangeNotSatisfiable;
            return (
                StatusCode::RANGE_NOT_SATISFIABLE,
                [(CONTENT_RANGE, format!("bytes */{}", file.size))],
            )
                .into_response();
        }
    };
    let response_headers = match file_headers(&file, &span) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(id = id_prefix, error = %e, "building download headers failed");
            return fail(
                &mut metric,
                StatusCode::INTERNAL_SERVER_ERROR,
                Outcome::Error,
            );
        }
    };
    if !is_get {
        return (span.status, response_headers, Body::empty()).into_response();
    }

    // Step 4: download slots.
    let slot = match state.limits.try_download(client.key) {
        Ok(slot) => slot,
        Err(throttle) => {
            metric.outcome = throttle.outcome;
            return throttle.respond(&state.obs);
        }
    };

    // Step 5: open the file. It may have been ended since the lookup.
    let mut fd = match File::open(&file.path).await {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return fail(&mut metric, StatusCode::GONE, Outcome::Gone)
        }
        Err(e) => {
            tracing::error!(id = id_prefix, error = %e, "opening download failed");
            return fail(
                &mut metric,
                StatusCode::INTERNAL_SERVER_ERROR,
                Outcome::Error,
            );
        }
    };
    if span.start > 0 {
        if let Err(e) = fd.seek(SeekFrom::Start(span.start)).await {
            tracing::error!(id = id_prefix, error = %e, "seeking download failed");
            return fail(
                &mut metric,
                StatusCode::INTERNAL_SERVER_ERROR,
                Outcome::Error,
            );
        }
    }

    if let Some(first) = state.store.record_download(id) {
        let ms = first.since_upload.as_secs_f64() * 1000.0;
        state.obs.timing_ms(
            "time_to_first_download_ms",
            &[("agent", &first.uploader)],
            ms,
        );
        tracing::info!(
            agent = first.uploader.as_str(),
            id = id_prefix,
            ms,
            "first download of file"
        );
    }

    let (tx, rx) = mpsc::channel(CHANNEL_CHUNKS);
    let abort = CancellationToken::new();
    let body = body_from(rx, abort.clone(), file.cancel.clone());
    metric.served = true;
    let producer = Producer {
        file: fd,
        len: span.len,
        tx,
        cancel: file.cancel,
        abort: abort.drop_guard(),
        idle_timeout: state.cfg.download_idle_timeout,
        deadline: started + state.cfg.max_download_duration,
        id_prefix: id_prefix.to_string(),
        metric,
        _slot: slot,
    };
    // The producer keeps the request span, so its log lines (and the
    // metric guard's, which drops inside it) still carry the route.
    tokio::spawn(producer.run().in_current_span());
    (span.status, response_headers, body).into_response()
}

/// Emits exactly one `revoke` event when dropped: `agent` (`-` when no
/// valid token was presented) and `result` per the spec's result table.
/// Its outcome starts as `ClientAborted`, the same convention as
/// `DownloadMetric` and `upload`'s `UploadMetric`, so a disconnect before
/// the response is ready still emits one event.
struct RevokeMetric {
    obs: Obs,
    agent: Option<String>,
    outcome: Outcome,
    client_ip: IpAddr,
    /// The first 8 characters of the requested id, once the path parses.
    id: Option<String>,
    /// The file's original filename and size, when a lookup found it live
    /// just before the revoke.
    filename: Option<String>,
    size: Option<u64>,
}

impl RevokeMetric {
    fn new(obs: Obs, agent: Option<String>, client_ip: IpAddr) -> RevokeMetric {
        RevokeMetric {
            obs,
            agent,
            outcome: Outcome::ClientAborted,
            client_ip,
            id: None,
            filename: None,
            size: None,
        }
    }
}

impl Drop for RevokeMetric {
    fn drop(&mut self) {
        self.obs.counter(
            "revoke",
            &[
                ("agent", self.agent.as_deref().unwrap_or("-")),
                ("result", self.outcome.as_str()),
            ],
            1,
        );
        tracing::info!(
            agent = log_str(self.agent.as_deref()),
            id = log_str(self.id.as_deref()),
            filename = log_str(self.filename.as_deref()),
            size = %log_size(self.size),
            client_ip = %self.client_ip,
            result = self.outcome.as_str(),
            "revoke request handled"
        );
    }
}

/// Records `outcome` on `metric` and answers the bare `status`.
fn finish(metric: &mut RevokeMetric, status: StatusCode, outcome: Outcome) -> Response {
    metric.outcome = outcome;
    status.into_response()
}

/// `DELETE /d/{id}/{urlname}`: revokes a file, evaluated in the spec's
/// check order. The `revoke` metric guard is built first, so every exit
/// emits exactly one `revoke` event.
pub async fn delete(
    State(state): State<AppState>,
    MaybeAgent(agent): MaybeAgent,
    client: ClientAddr,
    uri: Uri,
) -> Response {
    let mut metric = RevokeMetric::new(
        state.obs.clone(),
        agent.as_ref().map(|a| a.name.clone()),
        client.ip,
    );

    // Step 1: token.
    let Some(agent) = agent else {
        return finish(&mut metric, StatusCode::UNAUTHORIZED, Outcome::Unauthorized);
    };

    // Steps 2-4 (id and name, uploader, state) all run inside
    // `Store::revoke`, in that order.
    let Some((id, urlname)) = segments(uri.path()) else {
        return finish(&mut metric, StatusCode::NOT_FOUND, Outcome::NotFound);
    };
    metric.id = Some(short(id).to_string());
    // Best-effort, for the log line only: `revoke` re-derives everything
    // it needs itself, so a file ended between this lookup and that call
    // just means the log line falls back to "-".
    if let Lookup::Live(file) = state.store.lookup(id, urlname) {
        metric.filename = Some(file.name.clone());
        metric.size = Some(file.size);
    }
    let (status, outcome) = match state.store.revoke(id, urlname, &agent.name).await {
        RevokeOutcome::NotFound => (StatusCode::NOT_FOUND, Outcome::NotFound),
        RevokeOutcome::Forbidden => (StatusCode::FORBIDDEN, Outcome::Forbidden),
        RevokeOutcome::Gone => (StatusCode::GONE, Outcome::Gone),
        RevokeOutcome::Revoked => (StatusCode::NO_CONTENT, Outcome::Ok),
        RevokeOutcome::Failed => (StatusCode::INTERNAL_SERVER_ERROR, Outcome::Error),
    };
    finish(&mut metric, status, outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    /// Chunks the producer queued before returning `Ok` (so `abort` was
    /// disarmed and will never fire) must still stop once the file is
    /// revoked, rather than reaching the client.
    #[tokio::test]
    async fn revoke_stops_chunks_queued_after_producer_finished() {
        let (tx, rx) = mpsc::channel(CHANNEL_CHUNKS);
        let abort = CancellationToken::new();
        let revoked = CancellationToken::new();
        let body = body_from(rx, abort.clone(), revoked.clone());

        // The producer queues everything, disarms `abort`, and is gone.
        for _ in 0..CHANNEL_CHUNKS {
            tx.send(Bytes::from_static(b"chunk")).await.expect("send");
        }
        drop(tx);
        abort.drop_guard().disarm();

        revoked.cancel();
        let mut stream = body.into_data_stream();
        let first = stream.next().await.expect("the body yields an item");
        assert!(
            first.is_err(),
            "a revoked file's queued chunk reached the client"
        );
        assert!(stream.next().await.is_none(), "the body ends after failing");
    }

    /// Without a revoke, a finished producer's queued chunks all arrive and
    /// the body ends cleanly.
    #[tokio::test]
    async fn queued_chunks_drain_without_revoke() {
        let (tx, rx) = mpsc::channel(CHANNEL_CHUNKS);
        let body = body_from(rx, CancellationToken::new(), CancellationToken::new());
        for _ in 0..CHANNEL_CHUNKS {
            tx.send(Bytes::from_static(b"chunk")).await.expect("send");
        }
        drop(tx);

        let chunks: Vec<_> = body.into_data_stream().collect().await;
        assert_eq!(chunks.len(), CHANNEL_CHUNKS);
        assert!(chunks
            .iter()
            .all(|c| c.as_ref().is_ok_and(|b| b == "chunk")));
    }
}
