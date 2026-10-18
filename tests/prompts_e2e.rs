//! Prompts on a service's own endpoint and on the combined endpoint, through `app::Server`.
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mcp_server_core::app::Server;
use mcp_server_core::combined::DynHandler;
use mcp_server_core::prompt::{argument, not_found, tool_prefix, user_prompt};
use mcp_server_core::rmcp::model::{
    GetPromptRequestParams, GetPromptResponse, ListPromptsResult, PaginatedRequestParams, Prompt,
    PromptArgument, PromptsCapability, ServerCapabilities, ServerConfig,
};
use mcp_server_core::rmcp::service::{RequestContext, RoleServer};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler};
use mcp_server_core::service::{HttpSettings, Service, ServiceContext, ServiceEnv};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const TOKEN: &str = "static-token-0123456789abcdef0123456789";

#[derive(Clone)]
struct Prompts;

impl ServerHandler for Prompts {
    fn get_info(&self) -> ServerConfig {
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        capabilities.prompts = Some(PromptsCapability::default());
        ServerConfig::new(capabilities)
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        let arg = PromptArgument::new("topic");
        Ok(ListPromptsResult::with_all_items(vec![Prompt::new(
            "summarise",
            Some("Summarise the notes."),
            Some(vec![arg]),
        )]))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        if request.name != "summarise" {
            return Err(not_found(&request.name));
        }
        let topic = argument(request.arguments.as_ref(), "topic")?.unwrap_or("all".into());
        let p = tool_prefix(&context);
        Ok(user_prompt(
            "Summarise the notes.",
            format!("Call {p}list_notes about {topic}."),
        )
        .into())
    }
}

struct Notes;

impl Service for Notes {
    fn name(&self) -> &'static str {
        "notes"
    }
    fn handler(&self) -> DynHandler {
        DynHandler::new(Prompts)
    }
}

fn notes(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(Notes))
}

fn app() -> axum::Router {
    let vars: HashMap<String, String> = [
        ("PUBLIC_URL", "https://mcp.example.com"),
        ("OAUTH_SIGNING_KEY", "0123456789abcdef0123456789abcdef"),
        ("OAUTH_ADMIN_PASSWORD", "a long password"),
        ("MCP_AUTH_TOKEN", TOKEN),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let server = Server::new("mcp-prompts", "1").service("notes", notes);
    let mut env = ServiceEnv::new(Box::new(move |k: &str| vars.get(k).cloned()));
    let loaded = server.load(&mut env).expect("loads");
    let ctx = ServiceContext {
        http: HttpSettings::from_core(&loaded.core),
        shutdown: CancellationToken::new(),
    };
    server.router(&loaded, &ctx)
}

fn rpc(path: &str, body: Value, session: Option<&str>) -> Request<Body> {
    let mut b = Request::post(path)
        .header("host", "mcp.example.com")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(s) = session {
        b = b
            .header("mcp-session-id", s)
            .header("mcp-protocol-version", "2025-06-18");
    }
    b.body(Body::from(body.to_string())).unwrap()
}

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
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("response within 5 s")
            .expect("a message")
            .expect("frame");
        if let Ok(data) = frame.into_data() {
            buf.push_str(&String::from_utf8_lossy(&data));
        }
    }
}

async fn session(app: &axum::Router, path: &str) -> (String, Value) {
    let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}
    }});
    let res = app.clone().oneshot(rpc(path, init, None)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let id = res.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_string();
    let info = message(res).await["result"].clone();
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    app.clone()
        .oneshot(rpc(path, note, Some(&id)))
        .await
        .unwrap();
    (id, info)
}

async fn call(app: &axum::Router, path: &str, s: &str, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": params});
    message(app.clone().oneshot(rpc(path, body, Some(s))).await.unwrap()).await
}

#[tokio::test]
async fn prompts_name_tools_as_each_endpoint_calls_them() {
    let app = app();
    for (path, name, tool) in [
        ("/notes", "summarise", "list_notes"),
        ("/mcp", "notes_summarise", "notes_list_notes"),
    ] {
        let (s, info) = session(&app, path).await;
        assert!(
            info["capabilities"]["prompts"].is_object(),
            "{path}: {info}"
        );
        let listed = call(&app, path, &s, "prompts/list", json!({})).await;
        assert_eq!(listed["result"]["prompts"][0]["name"], name, "{path}");
        let got = call(
            &app,
            path,
            &s,
            "prompts/get",
            json!({"name": name, "arguments": {"topic": " work "}}),
        )
        .await;
        assert_eq!(
            got["result"]["messages"][0]["content"]["text"],
            format!("Call {tool} about work."),
            "{path}"
        );
    }
}

#[tokio::test]
async fn an_unknown_prompt_is_reported_with_the_name_the_client_sent() {
    let app = app();
    let (s, _) = session(&app, "/mcp").await;
    let got = call(
        &app,
        "/mcp",
        &s,
        "prompts/get",
        json!({"name": "notes_nope"}),
    )
    .await;
    assert_eq!(got["error"]["message"], "prompt 'notes_nope' not found");
}
