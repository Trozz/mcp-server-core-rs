//! MCP sessions are bound to the credential that opened them.
mod oauth_support;
use axum::body::Body;
use axum::http::{Request, StatusCode};

use mcp_server_core::server::build_app;
use mcp_server_core::service::{HttpSettings, ServiceContext, mcp_service};
use oauth_support::*;
use rmcp::ServerHandler;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const ALICE: &str = "alice-key-0123456789";
const BOB: &str = "bob-key-0123456789";

#[derive(Clone)]
struct Empty;

impl ServerHandler for Empty {}

fn app() -> axum::Router {
    let st = state_for(TestVerifier::accepting(&[ALICE, BOB]), &["mail"]);
    let ctx = ServiceContext {
        http: HttpSettings {
            public_url: PUBLIC_URL.into(),
            public_host: "mail.example.com".into(),
            allowed_origins: Vec::new(),
        },
        shutdown: CancellationToken::new(),
    };
    build_app(st, vec![("mail", mcp_service(&ctx, || Ok(Empty)))])
}

fn req(method: &str, key: &str, session: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri("/mail")
        .header("host", "mail.example.com")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-06-18");
    if let Some(s) = session {
        b = b.header("mcp-session-id", s);
    }
    b.body(body.map_or(Body::empty(), |v| Body::from(v.to_string())))
        .unwrap()
}

async fn open_session(app: &axum::Router, key: &str) -> String {
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}
    }});
    let res = app
        .clone()
        .oneshot(req("POST", key, None, Some(init)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let id = res.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            key,
            Some(&id),
            Some(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    id
}

#[tokio::test]
async fn a_session_works_only_with_the_key_that_opened_it() {
    let app = app();
    let alice = open_session(&app, ALICE).await;
    let ping = || Some(json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}));
    for (method, body) in [("POST", ping()), ("GET", None), ("DELETE", None)] {
        let mut r = req(method, BOB, Some(&alice), body);
        if method == "GET" {
            r.headers_mut()
                .insert("last-event-id", "0/0".parse().unwrap());
        }
        let res = app.clone().oneshot(r).await.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "Bob's {method}");
    }
    let res = app
        .clone()
        .oneshot(req("POST", ALICE, Some(&alice), ping()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "Alice's session survives");
    let res = app
        .clone()
        .oneshot(req("DELETE", ALICE, Some(&alice), None))
        .await
        .unwrap();
    assert!(res.status().is_success(), "{}", res.status());
    let res = app
        .oneshot(req("POST", ALICE, Some(&alice), ping()))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "ended sessions stay ended"
    );
}

#[tokio::test]
async fn one_key_opening_many_sessions_cannot_push_out_anyone_elses() {
    let app = app();
    let alice = open_session(&app, ALICE).await;
    let first_of_bobs = open_session(&app, BOB).await;
    for _ in 0..60 {
        open_session(&app, BOB).await;
    }
    let ping = || Some(json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}));
    let res = app
        .clone()
        .oneshot(req("POST", ALICE, Some(&alice), ping()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "Alice's session is untouched");
    let res = app
        .oneshot(req("POST", BOB, Some(&first_of_bobs), ping()))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "Bob's own oldest session made room"
    );
}

#[tokio::test]
async fn each_person_gets_their_own_session() {
    let app = app();
    let alice = open_session(&app, ALICE).await;
    let bob = open_session(&app, BOB).await;
    assert_ne!(alice, bob);
    for (key, id) in [(ALICE, &alice), (BOB, &bob)] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                key,
                Some(id),
                Some(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
