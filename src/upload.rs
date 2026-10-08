//! `PUT` handling: uploads, and the `400`/`401` responses for malformed or
//! unauthorized paths.
//!
//! `put` evaluates an upload in the spec's check order: token (`401`);
//! filename and `Filepass-TTL` (`400`); concurrency (`429`/`503`); upload
//! rate (`429`); declared size and space (`413`/`507`); then the body,
//! streamed into a temp file with limits re-checked as bytes arrive. Every
//! counter it takes is an RAII guard, so each exit releases them.
//!
//! `put_bad_path` and `fallback` handle the `PUT /d/{id}/{urlname}` route
//! and the router's `PUT` fallback, which are always a multi-segment path
//! (the `d`-route can't match fewer than three segments; the fallback only
//! reaches a `PUT` here when no other route matched), so they have nothing
//! to check beyond the token.
//!
//! Every handler here records its `upload` metric before deciding a
//! response, per "Handlers own every response": `MaybeAgent` and
//! `ClientAddr` never reject a request, and no handler uses axum's `Path`
//! extractor, so no request skips its metric.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, LOCATION};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout_at, Instant};

use crate::app::AppState;
use crate::auth::{Agent, MaybeAgent};
use crate::client_ip::ClientAddr;
use crate::config::Config;
use crate::limits::UploadSlot;
use crate::names;
use crate::obs::{Obs, Outcome};
use crate::store::{self, Meta, NewFile, Reservation, ReserveError, Store, TempFile};

/// The spec's exact hint body for `PUT /`.
const ROOT_HINT: &str = "name the file: PUT /<filename> (curl -T - needs an explicit name)";

const FILEPASS_TTL: HeaderName = HeaderName::from_static("filepass-ttl");
const FILEPASS_EXPIRES: HeaderName = HeaderName::from_static("filepass-expires");
const FILEPASS_SHA256: HeaderName = HeaderName::from_static("filepass-sha256");

/// Emits the `upload` metric with `agent` (`-` when no valid token was
/// presented) and `result` labels.
pub(crate) fn record_upload(obs: &Obs, agent: Option<&str>, outcome: Outcome) {
    obs.counter(
        "upload",
        &[
            ("agent", agent.unwrap_or("-")),
            ("result", outcome.as_str()),
        ],
        1,
    );
}

/// Emits exactly one `upload` event when dropped, plus `upload_bytes` and
/// `upload_duration_ms` for a stored file. Its outcome starts as
/// `ClientAborted`: a disconnect drops the handler future, and only `Drop`
/// runs then. Once the upload passes the checks, it moves into the task
/// that receives and commits the body, so the event reflects what was
/// stored even if the client has gone.
struct UploadMetric {
    obs: Obs,
    agent: Option<String>,
    outcome: Outcome,
    /// When the request arrived: the start of `upload_duration_ms`, and of
    /// `max_upload_duration`.
    started: Instant,
    /// Bytes stored; reported only for `Ok`.
    bytes: u64,
}

impl UploadMetric {
    fn new(obs: Obs, agent: Option<String>) -> UploadMetric {
        UploadMetric {
            obs,
            agent,
            outcome: Outcome::ClientAborted,
            started: Instant::now(),
            bytes: 0,
        }
    }
}

impl Drop for UploadMetric {
    fn drop(&mut self) {
        let agent = self.agent.as_deref();
        record_upload(&self.obs, agent, self.outcome);
        if let (Outcome::Ok, Some(agent)) = (self.outcome, agent) {
            let labels = [("agent", agent)];
            self.obs.counter("upload_bytes", &labels, self.bytes);
            let ms = self.started.elapsed().as_secs_f64() * 1000.0;
            self.obs.timing_ms("upload_duration_ms", &labels, ms);
        }
    }
}

/// A failed upload: the status to answer and the `result` to record.
type Failure = (StatusCode, Outcome);

/// Records `failure` on `metric` and answers its bare status.
fn fail(metric: &mut UploadMetric, (status, outcome): Failure) -> Response {
    metric.outcome = outcome;
    status.into_response()
}

/// The status and `result` for a reservation that cannot be made or grown.
fn reserve_failure(e: ReserveError) -> Failure {
    match e {
        ReserveError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, Outcome::TooLarge),
        ReserveError::Insufficient => (
            StatusCode::INSUFFICIENT_STORAGE,
            Outcome::InsufficientStorage,
        ),
    }
}

const BAD_REQUEST: Failure = (StatusCode::BAD_REQUEST, Outcome::BadRequest);
const SERVER_ERROR: Failure = (StatusCode::INTERNAL_SERVER_ERROR, Outcome::Error);
/// A body that ended in an error or short of its declared length. The
/// client has almost always gone, so nobody reads the `400`.
const CUT_OFF: Failure = (StatusCode::BAD_REQUEST, Outcome::ClientAborted);

/// The `Filepass-TTL` header as a duration, `default_ttl` when absent.
/// `None` (a `400`) for a value that is not a humantime duration, is zero,
/// or exceeds `max_ttl`.
fn parse_ttl(headers: &HeaderMap, cfg: &Config) -> Option<Duration> {
    let Some(value) = headers.get(FILEPASS_TTL) else {
        return Some(cfg.default_ttl);
    };
    let ttl = humantime::parse_duration(value.to_str().ok()?).ok()?;
    (!ttl.is_zero() && ttl <= cfg.max_ttl).then_some(ttl)
}

/// The request's declared `Content-Length`, if it has one (a chunked body
/// does not). hyper has already rejected a malformed one.
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers.get(CONTENT_LENGTH)?.to_str().ok()?.parse().ok()
}

/// An upload that has passed steps 1-6 of the check order: it holds its
/// concurrency slot, its reservation, and its temp file.
struct Accepted {
    id: String,
    name: String,
    uploader: String,
    ttl: Duration,
    declared: Option<u64>,
    /// When the request arrived; `max_upload_duration` counts from here.
    started: Instant,
    temp: TempFile,
    reservation: Reservation,
    _slot: UploadSlot,
}

/// What `receive` stored in the temp file.
struct Received {
    size: u64,
    sha256: String,
}

/// Streams `body` into the upload's temp file, hashing it. Before writing
/// each chunk it grows the reservation to the running total, which
/// re-checks every limit (`413`/`507`). Each chunk must arrive within
/// `upload_idle_timeout`, and the whole body within `max_upload_duration`
/// of the request (`408`).
async fn receive(cfg: &Config, upload: &mut Accepted, body: Body) -> Result<Received, Failure> {
    let deadline = upload.started + cfg.max_upload_duration;
    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    loop {
        let wait_until = (Instant::now() + cfg.upload_idle_timeout).min(deadline);
        let chunk = match timeout_at(wait_until, stream.next()).await {
            Err(_elapsed) => return Err((StatusCode::REQUEST_TIMEOUT, Outcome::Timeout)),
            Ok(None) => break,
            // The connection failed mid-body: the client went away, or sent
            // a body hyper could not decode.
            Ok(Some(Err(_))) => return Err(CUT_OFF),
            Ok(Some(Ok(chunk))) => chunk,
        };
        written += chunk.len() as u64;
        upload.reservation.grow(written).map_err(reserve_failure)?;
        hasher.update(&chunk);
        if let Err(e) = upload.temp.file.write_all(&chunk).await {
            tracing::error!(id = &upload.id[..8], error = %e, "writing upload temp file failed");
            return Err(SERVER_ERROR);
        }
    }
    // hyper ends the body stream cleanly if its connection is torn down
    // mid-body, so a body short of its declared length was cut off, not
    // finished: never commit it.
    if upload.declared.is_some_and(|declared| declared != written) {
        return Err(CUT_OFF);
    }
    Ok(Received {
        size: written,
        sha256: hex::encode(hasher.finalize()),
    })
}

/// Step 7 and the commit: receives the body, then stores it. Runs in its
/// own task (see `put`), so it finishes even if the client disconnects
/// once the body is in.
async fn store_upload(
    store: &Arc<Store>,
    cfg: &Config,
    mut upload: Accepted,
    body: Body,
) -> Result<Meta, Failure> {
    let received = receive(cfg, &mut upload, body).await?;
    let new = NewFile {
        urlname: names::url_name(&upload.name),
        id: upload.id,
        name: upload.name,
        sha256: received.sha256,
        size: received.size,
        uploader: upload.uploader,
        ttl: upload.ttl,
    };
    let id_prefix = new.id[..8].to_string();
    store
        .commit(upload.temp, upload.reservation, new)
        .await
        .map_err(|e| {
            tracing::error!(id = %id_prefix, error = %e, "committing upload failed");
            SERVER_ERROR
        })
}

/// The `201` for a committed file: the download URL plus a newline as the
/// body, and `Location`, `Filepass-Expires`, and `Filepass-SHA256`.
fn created(public_url: &str, meta: &Meta) -> Response {
    let url = format!("{public_url}/d/{}/{}", meta.id, meta.urlname);
    let expires = humantime::format_rfc3339_seconds(meta.expires_at).to_string();
    (
        StatusCode::CREATED,
        [
            (LOCATION, url.clone()),
            (FILEPASS_EXPIRES, expires),
            (FILEPASS_SHA256, meta.sha256.clone()),
        ],
        format!("{url}\n"),
    )
        .into_response()
}

/// `PUT /healthz` and `PUT /{filename}`: an upload, evaluated in the
/// spec's check order. The `upload` metric guard is built first, so every
/// exit emits exactly one `upload` event.
///
/// Once steps 1-6 pass, the rest runs in a spawned task that owns the body
/// and every guard (slot, reservation, temp file, metric), and the handler
/// awaits it. hyper drops the handler as soon as it reads EOF after a
/// complete body, often before the handler has seen the body's last
/// chunk, so only a task that outlives the handler can honour "the commit
/// cannot be cancelled". If the client vanishes mid-body, the body stream
/// fails (or stalls into the idle timeout), and the task drops its guards.
pub async fn put(
    State(state): State<AppState>,
    MaybeAgent(agent): MaybeAgent,
    _client: ClientAddr,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let mut metric = UploadMetric::new(state.obs.clone(), agent.as_ref().map(|a| a.name.clone()));

    // Step 1: token.
    let Some(agent) = agent else {
        return fail(
            &mut metric,
            (StatusCode::UNAUTHORIZED, Outcome::Unauthorized),
        );
    };

    // Step 2: filename and TTL. The router sends only single-segment paths
    // here, so the segment is the path without its leading `/`.
    let segment = uri.path().strip_prefix('/').unwrap_or(uri.path());
    let Ok(name) = names::decode_filename(segment) else {
        return fail(&mut metric, BAD_REQUEST);
    };
    let Some(ttl) = parse_ttl(&headers, &state.cfg) else {
        return fail(&mut metric, BAD_REQUEST);
    };

    // Step 3: concurrency.
    let slot = match state.limits.try_upload(&agent.name) {
        Ok(slot) => slot,
        Err(throttle) => {
            metric.outcome = throttle.outcome;
            return throttle.respond(&state.obs);
        }
    };

    // Step 4: upload rate. Only requests that get this far spend a token.
    if let Err(throttle) = state.limits.try_rate(&agent.name) {
        metric.outcome = throttle.outcome;
        return throttle.respond(&state.obs);
    }

    // Steps 5-6: size and space. A declared length is reserved up front.
    let declared = declared_length(&headers);
    let reservation = match state.store.reserve(&agent.name, declared) {
        Ok(reservation) => reservation,
        Err(e) => return fail(&mut metric, reserve_failure(e)),
    };

    let id = store::new_id();
    let temp = match state.store.temp_file(&id) {
        Ok(temp) => temp,
        Err(e) => {
            tracing::error!(id = &id[..8], error = %e, "creating upload temp file failed");
            return fail(&mut metric, SERVER_ERROR);
        }
    };

    let upload = Accepted {
        id: id.clone(),
        name,
        uploader: agent.name,
        ttl,
        declared,
        started: metric.started,
        temp,
        reservation,
        _slot: slot,
    };
    let store = Arc::clone(&state.store);
    let cfg = Arc::clone(&state.cfg);
    let task = tokio::spawn(async move {
        // Rebind so the task owns the whole guard; assigning its `Copy`
        // fields alone would capture only copies of them.
        let mut metric = metric;
        // Until the upload resolves, the guard reports an error, so a
        // panic unwinds through it as `error`, not `client_aborted`.
        metric.outcome = Outcome::Error;
        let result = store_upload(&store, &cfg, upload, body).await;
        match &result {
            Ok(meta) => {
                metric.outcome = Outcome::Ok;
                metric.bytes = meta.size;
            }
            Err((_, outcome)) => metric.outcome = *outcome,
        }
        result
    });
    match task.await {
        Ok(Ok(meta)) => created(&state.cfg.public_url, &meta),
        Ok(Err((status, _))) => status.into_response(),
        Err(e) => {
            tracing::error!(id = &id[..8], error = %e, "upload task failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// The shared response for a path that is final at step 1-2 of the upload
/// check order: `401` with no valid token, else `400` with `body` (plain
/// when `body` is `None`). Emits the `upload` metric either way.
fn bad_path_response(obs: &Obs, agent: Option<Agent>, body: Option<&'static str>) -> Response {
    match agent {
        None => {
            record_upload(obs, None, Outcome::Unauthorized);
            StatusCode::UNAUTHORIZED.into_response()
        }
        Some(agent) => {
            record_upload(obs, Some(&agent.name), Outcome::BadRequest);
            match body {
                Some(body) => (StatusCode::BAD_REQUEST, body).into_response(),
                None => StatusCode::BAD_REQUEST.into_response(),
            }
        }
    }
}

/// `PUT /d/{id}/{urlname}`: always a multi-segment path, so this is final
/// and plain `400` (never the root hint).
pub async fn put_bad_path(
    State(state): State<AppState>,
    MaybeAgent(agent): MaybeAgent,
) -> Response {
    bad_path_response(&state.obs, agent, None)
}

/// The router's fallback. Any method other than `PUT` on an unmatched path
/// is `404`. A `PUT` here is `PUT /` (the spec's hint body) or a deeper
/// unmatched path (plain `400`).
pub async fn fallback(
    State(state): State<AppState>,
    MaybeAgent(agent): MaybeAgent,
    method: Method,
    uri: Uri,
) -> Response {
    if method != Method::PUT {
        return StatusCode::NOT_FOUND.into_response();
    }
    let body = (uri.path() == "/").then_some(ROOT_HINT);
    bad_path_response(&state.obs, agent, body)
}
