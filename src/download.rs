//! `GET`/`HEAD` and `DELETE` handling on `/d/{id}/{urlname}`.
//!
//! Task 9 implements `get` (range-aware, producer-task downloads) and
//! Task 10 implements `delete` (revocation). This task only wires the
//! route to stub `501` responses so the router compiles and routing tests
//! can exercise everything around them.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::app::AppState;

/// `GET`/`HEAD /d/{id}/{urlname}`: stub. Task 9 implements lookup, range
/// handling, and the producer-task download.
pub async fn get(State(_state): State<AppState>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}

/// `DELETE /d/{id}/{urlname}`: stub. Task 10 implements revocation.
pub async fn delete(State(_state): State<AppState>) -> impl IntoResponse {
    StatusCode::NOT_IMPLEMENTED
}
