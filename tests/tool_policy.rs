//! The read-only rule and the audit log, through the same HTTP stack the binary serves.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mcp_server_core::credential::Credential;
use mcp_server_core::jwt::{Claims, Payload, TokenKind};
use mcp_server_core::policy::{AuditLog, Guarded, ToolPolicy};
use mcp_server_core::service::{HttpSettings, ServiceContext, mcp_service};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[derive(Clone)]
struct Tools {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Tools {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Reads.", annotations(read_only_hint = true))]
    async fn look(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("looked")]))
    }

    #[tool(description = "Writes.", annotations(read_only_hint = false))]
    async fn change(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("changed")]))
    }

    #[tool(description = "Fails.", annotations(read_only_hint = false))]
    async fn fail(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::error(vec![ContentBlock::text(
            "conflict: precondition failed",
        )]))
    }

    #[tool(description = "No annotations.")]
    async fn unmarked(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("done")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Tools {}

fn ctx() -> ServiceContext {
    ServiceContext {
        http: HttpSettings {
            public_url: "https://icloud.example.com".into(),
            public_host: "icloud.example.com".into(),
            allowed_origins: Vec::new(),
        },
        shutdown: CancellationToken::new(),
    }
}

/// The service mounted at `/svc` with an optional policy and an optional caller claim.
fn app(policy: Option<ToolPolicy>, claims: Option<Claims>) -> axum::Router {
    let mut router = mcp_service(&ctx(), || Ok(Tools::new()));
    if let Some(p) = policy {
        router = router.layer(axum::Extension(p));
    }
    if let Some(c) = claims {
        router = router.layer(axum::Extension(c));
    }
    axum::Router::new().nest_service("/svc", router)
}

fn policy(read_only: bool, audit: Arc<AuditLog>) -> ToolPolicy {
    ToolPolicy {
        service: "svc".into(),
        endpoint: "/svc".into(),
        read_only,
        audit,
    }
}

fn claims(client_id: Option<&str>) -> Claims {
    Claims {
        iss: "https://icloud.example.com".into(),
        aud: "https://icloud.example.com/svc".into(),
        sub: "owner".into(),
        typ: TokenKind::Access,
        jti: "jti-1".into(),
        iat: 0,
        exp: None,
        payload: Payload {
            client_id: client_id.map(str::to_string),
            ..Payload::default()
        },
    }
}

fn rpc(body: Value, session: Option<&str>) -> Request<Body> {
    let mut b = Request::post("/svc")
        .header("host", "icloud.example.com")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(s) = session {
        b = b
            .header("mcp-session-id", s)
            .header("mcp-protocol-version", "2025-06-18");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// Reads an SSE (or plain JSON) response until the first complete JSON-RPC message.
async fn message(res: axum::response::Response) -> Value {
    let mut body = res.into_body();
    let mut buf = String::new();
    loop {
        for line in buf.lines() {
            if let Some(data) = line.strip_prefix("data:")
                && let Ok(v) = serde_json::from_str::<Value>(data.trim())
                && v.get("jsonrpc").is_some()
            {
                return v;
            }
        }
        if let Ok(v) = serde_json::from_str::<Value>(buf.trim()) {
            return v;
        }
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("response within 5 s")
            .expect("a message before the end of the body")
            .expect("body frame");
        if let Ok(data) = frame.into_data() {
            buf.push_str(&String::from_utf8_lossy(&data));
        }
    }
}

/// Initializes a session and returns its id.
async fn session(app: &axum::Router) -> String {
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}
    }});
    let res = app.clone().oneshot(rpc(init, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let id = res.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    message(res).await;
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let res = app.clone().oneshot(rpc(note, Some(&id))).await.unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    id
}

async fn tool_names(app: &axum::Router, session: &str) -> Vec<String> {
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
    let res = app.clone().oneshot(rpc(list, Some(session))).await.unwrap();
    let v = message(res).await;
    let mut names: Vec<String> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

/// Calls a tool; returns (isError, first text).
async fn call(app: &axum::Router, session: &str, name: &str, args: Value) -> (bool, String) {
    let body = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": name, "arguments": args}});
    let res = app.clone().oneshot(rpc(body, Some(session))).await.unwrap();
    let v = message(res).await;
    let result = &v["result"];
    (
        result["isError"].as_bool().unwrap_or(false),
        result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

fn lines(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[tokio::test]
async fn without_a_policy_nothing_changes() {
    let app = app(None, None);
    let s = session(&app).await;
    assert_eq!(
        tool_names(&app, &s).await,
        ["change", "fail", "look", "unmarked"]
    );
    assert_eq!(
        call(&app, &s, "change", json!({})).await,
        (false, "changed".into())
    );
}

#[tokio::test]
async fn a_read_only_service_hides_and_refuses_write_tools() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::new(Some(path.clone())));
    let app = app(Some(policy(true, audit)), None);
    let s = session(&app).await;
    assert_eq!(tool_names(&app, &s).await, ["look"]);
    assert_eq!(
        call(&app, &s, "look", json!({})).await,
        (false, "looked".into())
    );
    for name in ["change", "unmarked"] {
        assert_eq!(
            call(&app, &s, name, json!({})).await,
            (
                true,
                "read_only: the svc service is read-only on this server".into()
            ),
            "{name}"
        );
    }
    let audit = lines(&path);
    assert_eq!(audit.len(), 2, "{audit:?}");
    assert_eq!(audit[0]["tool"], "change");
    assert_eq!(audit[0]["outcome"], "refused");
    assert_eq!(audit[0]["error_kind"], "read_only");
    assert_eq!(audit[1]["tool"], "unmarked");
}

#[tokio::test]
async fn writes_are_audited_without_arguments_and_reads_are_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::new(Some(path.clone())));
    let app = app(Some(policy(false, audit)), Some(claims(Some("client-1"))));
    let s = session(&app).await;
    call(&app, &s, "look", json!({})).await;
    call(&app, &s, "change", json!({"secret": "SENTINEL-ARGUMENT"})).await;
    assert_eq!(
        call(&app, &s, "fail", json!({})).await,
        (true, "conflict: precondition failed".into())
    );

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(!text.contains("SENTINEL-ARGUMENT"), "{text}");
    let audit = lines(&path);
    assert_eq!(audit.len(), 2, "{audit:?}");
    let keys: Vec<&String> = audit[0].as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "caller",
            "elapsed_ms",
            "endpoint",
            "error_kind",
            "outcome",
            "service",
            "subject",
            "tool",
            "ts"
        ]
    );
    assert_eq!(audit[0]["service"], "svc");
    assert_eq!(audit[0]["endpoint"], "/svc");
    assert_eq!(audit[0]["tool"], "change");
    assert_eq!(audit[0]["outcome"], "ok");
    assert_eq!(audit[0]["error_kind"], Value::Null);
    assert_eq!(audit[0]["caller"], "oauth:client-1");
    assert!(audit[0]["ts"].as_str().unwrap().ends_with('Z'));
    assert_eq!(audit[1]["outcome"], "error");
    assert_eq!(audit[1]["error_kind"], "conflict");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[tokio::test]
async fn the_caller_is_static_without_claims_and_oauth_without_a_client_id() {
    let dir = tempfile::tempdir().unwrap();
    for (claims, want) in [(None, "static"), (Some(claims(None)), "oauth")] {
        let path = dir.path().join(format!("{want}.jsonl"));
        let audit = Arc::new(AuditLog::new(Some(path.clone())));
        let app = app(Some(policy(false, audit)), claims);
        let s = session(&app).await;
        call(&app, &s, "change", json!({})).await;
        assert_eq!(lines(&path)[0]["caller"], want);
    }
}

#[tokio::test]
async fn a_credential_sent_as_the_bearer_is_recorded_as_such_never_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::new(Some(path.clone())));
    let router = mcp_service(&ctx(), || Ok(Tools::new()))
        .layer(axum::Extension(policy(false, audit)))
        .layer(axum::Extension(Credential::new("SENTINEL-KEY")));
    let app = axum::Router::new().nest_service("/svc", router);
    let s = session(&app).await;
    call(&app, &s, "change", json!({})).await;
    assert_eq!(lines(&path)[0]["caller"], "credential");
    assert!(!std::fs::read_to_string(&path).unwrap().contains("SENTINEL"));
}

#[tokio::test]
async fn an_unwritable_audit_file_never_fails_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-dir").join("audit.jsonl");
    let audit = Arc::new(AuditLog::new(Some(path.clone())));
    let app = app(Some(policy(false, audit)), None);
    let s = session(&app).await;
    for _ in 0..2 {
        assert_eq!(
            call(&app, &s, "change", json!({})).await,
            (false, "changed".into())
        );
    }
    assert!(!path.exists());
}

#[tokio::test]
async fn an_explicit_policy_applies_without_a_request_extension() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let audit = Arc::new(AuditLog::new(Some(path.clone())));
    let explicit = ToolPolicy {
        service: "svc".into(),
        endpoint: "/combined".into(),
        read_only: true,
        audit,
    };
    let router = mcp_service(&ctx(), move || {
        Ok(Guarded::with_policy(Tools::new(), explicit.clone()))
    });
    let app = axum::Router::new().nest_service("/svc", router);
    let s = session(&app).await;
    assert_eq!(tool_names(&app, &s).await, ["look"]);
    assert!(call(&app, &s, "change", json!({})).await.0);
    let audit = lines(&path);
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0]["endpoint"], "/combined");
    assert_eq!(audit[0]["outcome"], "refused");
}
