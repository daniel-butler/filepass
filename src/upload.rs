//! `PUT` handling: uploads, and the `400`/`401` responses for malformed or
//! unauthorized paths.
//!
//! Tasks 8-10 fill in `put`'s real check order (auth, path, TTL, limits,
//! streaming, commit). This task wires the route, and `put_bad_path` /
//! `fallback`, which are already final: the `PUT /d/{id}/{urlname}` route
//! and the router's `PUT` fallback are always a multi-segment path (the
//! `d`-route can't match fewer than three segments; the fallback only
//! reaches a `PUT` here when no other route matched), so neither has more
//! checking to do. Both build their `upload` metric guard before deciding
//! `401` or `400`, per "Handlers own every response": `MaybeAgent` never
//! rejects a request, so the metric is never skipped.

use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::app::AppState;
use crate::auth::{Agent, MaybeAgent};
use crate::obs::{Obs, Outcome};

/// The spec's exact hint body for `PUT /`.
const ROOT_HINT: &str = "name the file: PUT /<filename> (curl -T - needs an explicit name)";

/// Emits the `upload` metric with `agent` (`-` when no valid token was
/// presented) and `result` labels. Task 8 reuses this for every upload
/// outcome, not only the bad-path ones handled in this file.
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

/// `PUT /healthz` and `PUT /{filename}`: stub. Task 8 implements the real
/// upload check order, streaming, and commit.
pub async fn put(State(_state): State<AppState>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
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
