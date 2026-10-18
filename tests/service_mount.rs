//! Host and origin checks of a mounted MCP service.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_server_core::service::{HttpSettings, ServiceContext, mcp_service};
use rmcp::ServerHandler;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[derive(Clone)]
struct Empty;

impl ServerHandler for Empty {}

fn app() -> axum::Router {
    let ctx = ServiceContext {
        http: HttpSettings {
            public_url: "https://icloud.example.com".into(),
            public_host: "icloud.example.com".into(),
            allowed_origins: Vec::new(),
        },
        shutdown: CancellationToken::new(),
    };
    axum::Router::new().nest_service("/svc", mcp_service(&ctx, || Ok(Empty)))
}

fn initialize(host: &str, origin: Option<&str>) -> Request<Body> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}
    }});
    let mut b = Request::post("/svc")
        .header("host", host)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(o) = origin {
        b = b.header("origin", o);
    }
    b.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test]
async fn initialize_is_served_at_the_mount_point() {
    let res = app()
        .oneshot(initialize("icloud.example.com", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().contains_key("mcp-session-id"));
}

#[tokio::test]
async fn own_origin_and_localhost_are_accepted() {
    let res = app()
        .oneshot(initialize(
            "icloud.example.com",
            Some("https://icloud.example.com"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app().oneshot(initialize("localhost", None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn foreign_host_and_origin_are_rejected() {
    let res = app()
        .oneshot(initialize("attacker.example.net", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let res = app()
        .oneshot(initialize(
            "icloud.example.com",
            Some("https://evil.example.net"),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}
