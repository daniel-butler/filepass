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
//! `delete` is a stub until Task 10 implements revocation.

use std::io::{self, SeekFrom};
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

use crate::app::AppState;
use crate::client_ip::ClientAddr;
use crate::limits::DownloadSlot;
use crate::names;
use crate::obs::{Obs, Outcome};
use crate::range::{self, RangeDecision};
use crate::store::{LiveFile, Lookup};

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
}

impl DownloadMetric {
    fn new(obs: Option<Obs>) -> DownloadMetric {
        DownloadMetric {
            obs,
            outcome: Outcome::ClientAborted,
            served: false,
            bytes: 0,
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
/// closes, or fails as soon as `abort` fires. Failing (rather than ending)
/// makes hyper close the connection short of `Content-Length`, and the
/// abort takes priority over chunks still queued.
fn body_from(rx: mpsc::Receiver<Bytes>, abort: CancellationToken) -> Body {
    let stream = futures_util::stream::unfold(Some((rx, abort)), |state| async move {
        let (mut rx, abort) = state?;
        tokio::select! {
            biased;
            () = abort.cancelled() => Some((Err(io::Error::other("download stopped early")), None)),
            chunk = rx.recv() => chunk.map(|chunk| (Ok(chunk), Some((rx, abort)))),
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
    let mut metric = DownloadMetric::new(is_get.then(|| state.obs.clone()));

    // Steps 1-2: id, name, state, and expiry, in one lock acquisition.
    let Some((id, urlname)) = segments(uri.path()) else {
        return fail(&mut metric, StatusCode::NOT_FOUND, Outcome::NotFound);
    };
    let file = match state.store.lookup(id, urlname) {
        Lookup::NotFound => return fail(&mut metric, StatusCode::NOT_FOUND, Outcome::NotFound),
        Lookup::Gone => return fail(&mut metric, StatusCode::GONE, Outcome::Gone),
        Lookup::Live(file) => file,
    };
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
    }

    let (tx, rx) = mpsc::channel(CHANNEL_CHUNKS);
    let abort = CancellationToken::new();
    let body = body_from(rx, abort.clone());
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
    tokio::spawn(producer.run());
    (span.status, response_headers, body).into_response()
}

/// `DELETE /d/{id}/{urlname}`: stub. Task 10 implements revocation.
pub async fn delete(State(_state): State<AppState>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}
