//! Application state and router assembly.
//!
//! `AppState` bundles every shared service a handler needs; `router` wires
//! the routes per the spec's Routing table. See the module doc on
//! `upload` and `download` for why handlers never use axum's `Path`
//! extractor: a rejecting extractor would skip the handler, and with it
//! the handler's metric guard.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{FromRef, MatchedPath, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, put, Router};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tracing::Instrument;

use crate::auth::Tokens;
use crate::client_ip::TrustedProxies;
use crate::clock::Clock;
use crate::config::Config;
use crate::limits::Limits;
use crate::obs::Obs;
use crate::store::{RecoveryReport, Store, StoreError};
use crate::{download, upload};

/// Every shared service a handler needs, cheaply cloneable per request.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub limits: Arc<Limits>,
    pub tokens: Arc<Tokens>,
    pub obs: Obs,
    pub clock: Arc<dyn Clock>,
}

impl FromRef<AppState> for Arc<Tokens> {
    fn from_ref(state: &AppState) -> Arc<Tokens> {
        state.tokens.clone()
    }
}

impl FromRef<AppState> for TrustedProxies {
    fn from_ref(state: &AppState) -> TrustedProxies {
        TrustedProxies(Arc::new(state.cfg.trusted_proxies.clone()))
    }
}

/// Builds `AppState` from a validated `Config`: opens the store (running
/// startup recovery) and builds the token table and limiter state.
pub fn build_state(
    cfg: Config,
    clock: Arc<dyn Clock>,
    obs: Obs,
) -> Result<(AppState, RecoveryReport), StoreError> {
    let cfg = Arc::new(cfg);
    let (store, report) = Store::open(&cfg, clock.clone())?;
    let limits = Arc::new(Limits::new(&cfg));
    let tokens = Arc::new(Tokens::from_config(&cfg));
    let state = AppState {
        cfg,
        store: Arc::new(store),
        limits,
        tokens,
        obs,
        clock,
    };
    Ok((state, report))
}

/// `GET /healthz`: no auth, always `200 ok`.
async fn health() -> &'static str {
    "ok"
}

/// Wraps every request in `info_span!("request", method, route)`, entered
/// for the whole handling of the request, so every log line it produces
/// (and, under `log_format = "json"`, every JSON line's `span` object)
/// carries both fields. `route` is the matched route *template* from
/// `MatchedPath` (e.g. `/d/{id}/{urlname}`), never the real path with its
/// id and filename; a request nothing matched (the router's `fallback`)
/// has no `MatchedPath`, so `route` is `"fallback"`.
pub async fn request_span(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "fallback".to_string());
    let span = tracing::info_span!("request", %method, %route);
    next.run(req).instrument(span).await
}

/// Builds the router per the spec's Routing table. axum matches the path
/// before the method, so a method mismatch on a matched path yields its
/// own `405` automatically; only `fallback` needs to distinguish `PUT`
/// from everything else.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health).put(upload::put))
        .route("/{filename}", put(upload::put))
        .route(
            "/d/{id}/{urlname}",
            get(download::get)
                .delete(download::delete)
                .put(upload::put_bad_path),
        )
        .fallback(upload::fallback)
        .layer(middleware::from_fn(request_span))
        .with_state(state)
}

/// Serves `state`'s app on `listener` until `shutdown` resolves, then races
/// the serve future against `sleep(cfg.shutdown_grace)`: axum's own
/// graceful shutdown waits indefinitely for in-flight connections, so this
/// is what makes the server exit by the grace deadline regardless.
pub async fn serve(
    listener: TcpListener,
    state: AppState,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    let grace = state.cfg.shutdown_grace;
    let make_service = router(state).into_make_service_with_connect_info::<SocketAddr>();

    // `with_graceful_shutdown` only starts axum's own (unbounded) grace
    // wait once `shutdown` resolves; we fan that same moment out to a
    // second branch that times the race out after `grace`.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let signal = async move {
        shutdown.await;
        let _ = tx.send(());
    };

    let serving = axum::serve(listener, make_service).with_graceful_shutdown(signal);

    tokio::select! {
        result = serving => result,
        _ = async move {
            let _ = rx.await;
            sleep(grace).await;
        } => Ok(()),
    }
}
