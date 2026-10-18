//! The HTTP application: health, the OAuth routes and every service behind its bearer guard.

use crate::oauth::{AuthState, oauth_router, require_bearer};
use axum::Router;
use axum::extract::{DefaultBodyLimit, MatchedPath, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// Largest request body accepted, in bytes.
pub const BODY_LIMIT: usize = 1024 * 1024;

/// Counts requests by matched route and status in `http_requests_total`.
pub async fn http_metrics(req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    let res = next.run(req).await;
    metrics::counter!("http_requests_total", "route" => route, "status" => res.status().as_u16().to_string()).increment(1);
    res
}

/// `GET /healthz`, the OAuth routes and each service nested at `/<name>` behind its own bearer
/// guard, with the body limit, request metrics and a tracing span per request.
///
/// # Panics
///
/// If a name is not one of the services `auth` was created with.
pub fn build_app(auth: Arc<AuthState>, services: Vec<(&'static str, Router)>) -> Router {
    let mut app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(oauth_router(auth.clone()));
    for (name, router) in services {
        assert!(
            auth.has_service(name),
            "service {name} is not registered with AuthState"
        );
        let guard =
            middleware::from_fn_with_state((auth.clone(), name.to_string()), require_bearer);
        app = app.nest_service(&format!("/{name}"), router.layer(guard));
    }
    app
        .layer(middleware::from_fn(http_metrics))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(TraceLayer::new_for_http().make_span_with(|req: &Request| {
            tracing::info_span!("request", method = %req.method(), path = req.uri().path())
        }))
}
