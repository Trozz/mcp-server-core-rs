//! A whole server built with `app::Server` from environment variables, as `main` would build it.
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::axum::http::request::Parts;
use mcp_server_core::combined::DynHandler;
use mcp_server_core::credential::{CheckFuture, Credential, CredentialCheck, CredentialVerifier};
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::handler::server::tool::Extension;
use mcp_server_core::rmcp::model::{
    CallToolResult, ContentBlock, ServerCapabilities, ServerConfig,
};
use mcp_server_core::rmcp::{
    ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router,
};
use mcp_server_core::service::{HttpSettings, Service, ServiceContext, ServiceEnv};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const HOST: &str = "mcp.example.com";
const TOKEN: &str = "static-token-0123456789abcdef0123456789";
const KEY: &str = "demo-key-0001";

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
    async fn look(&self, Extension(parts): Extension<Parts>) -> Result<CallToolResult, McpError> {
        let key = parts
            .extensions
            .get::<Credential>()
            .map_or("none", Credential::expose)
            .to_string();
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "looked with {key}"
        ))]))
    }

    #[tool(description = "Writes.", annotations(read_only_hint = false))]
    async fn change(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("changed")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Tools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Test tools.")
    }
}

struct Keys;

impl CredentialVerifier for Keys {
    fn label(&self) -> &str {
        "demo key"
    }
    fn check<'a>(&'a self, key: &'a str) -> CheckFuture<'a> {
        let ok = key == KEY;
        Box::pin(async move {
            if ok {
                CredentialCheck::Valid
            } else {
                CredentialCheck::Invalid(None)
            }
        })
    }
}

struct Svc(&'static str, bool);

impl Service for Svc {
    fn name(&self) -> &'static str {
        self.0
    }
    fn handler(&self) -> DynHandler {
        DynHandler::new(Tools::new())
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["change".into(), "look".into()]
    }
    fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
        self.1
            .then(|| Arc::new(Keys) as Arc<dyn CredentialVerifier>)
    }
}

fn alpha(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(Svc("alpha", false)))
}

fn beta(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(Svc("beta", false)))
}

fn keyed(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(Svc("keyed", true)))
}

fn owner_server() -> Server {
    Server::new("mcp-e2e", "9.9.9")
        .env_prefix("E2E")
        .service("alpha", alpha)
        .service("beta", beta)
        .icon(b"png-bytes", "<svg/>")
}

/// The application `server` builds from `vars` plus the core settings.
fn build(server: &Server, vars: &[(&str, &str)]) -> axum::Router {
    let mut map: HashMap<String, String> = [
        ("PUBLIC_URL", "https://mcp.example.com"),
        ("OAUTH_SIGNING_KEY", "0123456789abcdef0123456789abcdef"),
        ("INSECURE_HTTP", "true"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    for (k, v) in vars {
        map.insert(k.to_string(), v.to_string());
    }
    let mut env = ServiceEnv::new(Box::new(move |k: &str| map.get(k).cloned()));
    let loaded = server
        .load(&mut env)
        .unwrap_or_else(|| panic!("{:?}", env.errors));
    let ctx = ServiceContext {
        http: HttpSettings::from_core(&loaded.core),
        shutdown: CancellationToken::new(),
    };
    server.router(&loaded, &ctx)
}

fn rpc(path: &str, body: Value, token: &str, session: Option<&str>) -> Request<Body> {
    let mut b = Request::post(path)
        .header("host", HOST)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(s) = session {
        b = b
            .header("mcp-session-id", s)
            .header("mcp-protocol-version", "2025-06-18");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// The first JSON-RPC message of an SSE or JSON response.
async fn message(res: Response<Body>) -> Value {
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

/// Opens a session on `path`; returns its id and the `initialize` result.
async fn open(app: &axum::Router, path: &str, token: &str) -> (String, Value) {
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}
    }});
    let res = app
        .clone()
        .oneshot(rpc(path, init, token, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "{path}");
    let id = res.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    let result = message(res).await["result"].clone();
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    let res = app
        .clone()
        .oneshot(rpc(path, note, token, Some(&id)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    (id, result)
}

async fn tools(app: &axum::Router, path: &str, token: &str, session: &str) -> Vec<String> {
    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
    let res = app
        .clone()
        .oneshot(rpc(path, list, token, Some(session)))
        .await
        .unwrap();
    message(res).await["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

async fn call(app: &axum::Router, path: &str, token: &str, session: &str, tool: &str) -> String {
    let body = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": tool, "arguments": {}}});
    let res = app
        .clone()
        .oneshot(rpc(path, body, token, Some(session)))
        .await
        .unwrap();
    message(res).await["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test]
async fn each_service_is_served_at_its_own_path() {
    let server = owner_server();
    let app = build(
        &server,
        &[
            ("OAUTH_ADMIN_PASSWORD", "a long password"),
            ("MCP_AUTH_TOKEN", TOKEN),
        ],
    );
    for path in ["/alpha", "/beta"] {
        let (s, info) = open(&app, path, TOKEN).await;
        assert_eq!(info["instructions"], "Test tools.");
        assert_eq!(tools(&app, path, TOKEN, &s).await, ["change", "look"]);
        assert_eq!(
            call(&app, path, TOKEN, &s, "look").await,
            "looked with none"
        );
    }
    let res = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app
        .oneshot(Request::get("/favicon.ico").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.headers()["content-type"], "image/png");
    assert_eq!(
        res.into_body().collect().await.unwrap().to_bytes().as_ref(),
        b"png-bytes"
    );
}

#[tokio::test]
async fn the_combined_endpoint_serves_every_service_under_its_own_policy() {
    let server = owner_server();
    let app = build(
        &server,
        &[
            ("OAUTH_ADMIN_PASSWORD", "a long password"),
            ("MCP_AUTH_TOKEN", TOKEN),
            ("E2E_READ_ONLY", "beta"),
        ],
    );
    let (s, info) = open(&app, "/mcp", TOKEN).await;
    assert_eq!(info["serverInfo"]["name"], "mcp-e2e");
    assert_eq!(info["serverInfo"]["version"], "9.9.9");
    assert_eq!(info["serverInfo"]["icons"].as_array().unwrap().len(), 2);
    assert!(
        info["instructions"]
            .as_str()
            .unwrap()
            .starts_with("This server combines several services."),
        "{info}"
    );
    assert_eq!(
        tools(&app, "/mcp", TOKEN, &s).await,
        ["alpha_change", "alpha_look", "beta_look"]
    );
    assert_eq!(
        call(&app, "/mcp", TOKEN, &s, "alpha_change").await,
        "changed"
    );
    assert_eq!(
        call(&app, "/mcp", TOKEN, &s, "beta_change").await,
        "read_only: the beta service is read-only on this server"
    );
    let (s, _) = open(&app, "/beta", TOKEN).await;
    assert_eq!(tools(&app, "/beta", TOKEN, &s).await, ["look"]);
}

#[tokio::test]
async fn selected_services_only_and_the_combined_endpoint_can_be_turned_off() {
    let server = owner_server();
    let app = build(
        &server,
        &[
            ("OAUTH_ADMIN_PASSWORD", "a long password"),
            ("MCP_AUTH_TOKEN", TOKEN),
            ("E2E_SERVICES", "beta"),
            ("E2E_COMBINED", "false"),
        ],
    );
    for (path, want) in [
        ("/alpha", StatusCode::NOT_FOUND),
        ("/mcp", StatusCode::NOT_FOUND),
        ("/beta", StatusCode::OK),
    ] {
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}
        }});
        let res = app
            .clone()
            .oneshot(rpc(path, init, TOKEN, None))
            .await
            .unwrap();
        assert_eq!(res.status(), want, "{path}");
    }
}

#[tokio::test]
async fn people_signing_in_with_their_own_key_reach_tools_with_it() {
    let server = Server::new("mcp-e2e", "1")
        .service("alpha", alpha)
        .service("keyed", keyed)
        .sign_in(SignIn::ServiceCredential);
    let app = build(&server, &[]);
    for path in ["/keyed", "/alpha", "/mcp"] {
        let (s, _) = open(&app, path, KEY).await;
        let tool = if path == "/mcp" { "keyed_look" } else { "look" };
        assert_eq!(
            call(&app, path, KEY, &s, tool).await,
            format!("looked with {KEY}"),
            "{path}"
        );
    }
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let res = app
        .oneshot(rpc("/keyed", init, "demo-key-wrong", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hsts_is_sent_only_with_certificate_files() {
    let server = owner_server();
    let password = ("OAUTH_ADMIN_PASSWORD", "a long password");
    let files = [
        ("INSECURE_HTTP", "false"),
        ("TLS_CERT_PATH", "/etc/ssl/mcp/cert.pem"),
        ("TLS_KEY_PATH", "/etc/ssl/mcp/key.pem"),
        password,
    ];
    for (vars, want) in [
        (&[password, ("INSECURE_HTTP", "true")][..], false),
        (&[password, ("INSECURE_HTTP", "false")][..], false),
        (&files[..], true),
    ] {
        let res = build(&server, vars)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            res.headers().contains_key("strict-transport-security"),
            want,
            "{vars:?}"
        );
        assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    }
}

#[tokio::test]
async fn security_headers_reach_every_response() {
    let server = owner_server()
        .wrap_router(|app| app.route("/version", axum::routing::get(|| async { "9.9.9" })));
    let app = build(
        &server,
        &[
            ("OAUTH_ADMIN_PASSWORD", "a long password"),
            ("INSECURE_HTTP", "false"),
            ("TLS_CERT_PATH", "/etc/ssl/mcp/cert.pem"),
            ("TLS_KEY_PATH", "/etc/ssl/mcp/key.pem"),
        ],
    );
    let too_big = Request::post("/register")
        .header("content-type", "application/json")
        .body(Body::from(vec![b' '; 2 * 1024 * 1024]))
        .unwrap();
    for req in [
        Request::get("/favicon.ico").body(Body::empty()).unwrap(),
        Request::get("/version").body(Body::empty()).unwrap(),
        too_big,
    ] {
        let uri = req.uri().clone();
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.headers()["x-content-type-options"], "nosniff", "{uri}");
        assert!(
            res.headers().contains_key("strict-transport-security"),
            "{uri}"
        );
    }
}
