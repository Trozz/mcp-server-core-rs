//! A server shared by many people, each signing in with their own key for an upstream API.
//!
//! The key is checked when the person signs in, then travels sealed inside their OAuth tokens;
//! tools read it from the request and call the upstream API with it. Clients that can set a
//! header may also send the key itself as their bearer token. Here the "upstream API" accepts any
//! key starting `demo-`.
//!
//! ```sh
//! PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
//! OAUTH_SIGNING_KEY=$(openssl rand -hex 32) LOG_FORMAT=pretty \
//! cargo run --example api_keys
//! ```
//!
//! Then add `http://localhost:8443/account` to an MCP client and sign in with `demo-1234`.

use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::axum::http::request::Parts;
use mcp_server_core::combined::DynHandler;
use mcp_server_core::credential::{CheckFuture, Credential, CredentialCheck, CredentialVerifier};
use mcp_server_core::rmcp; // rmcp's macros need `rmcp` in scope
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::handler::server::tool::Extension;
use mcp_server_core::rmcp::model::{
    CallToolResult, ContentBlock, ServerCapabilities, ServerConfig,
};
use mcp_server_core::rmcp::{
    ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router,
};
use mcp_server_core::service::{Service, ServiceEnv};
use std::process::ExitCode;
use std::sync::Arc;

/// Checks keys with the upstream API.
struct DemoKeys;

impl CredentialVerifier for DemoKeys {
    fn label(&self) -> &str {
        "Demo API key"
    }

    fn help(&self) -> &str {
        "Any key starting demo- works, such as demo-1234."
    }

    /// Keys have a known shape, so other tokens are refused without asking upstream.
    fn plausible(&self, key: &str) -> bool {
        key.starts_with("demo-") && key.len() <= 64
    }

    fn check<'a>(&'a self, key: &'a str) -> CheckFuture<'a> {
        Box::pin(async move {
            // A real verifier makes one cheap authenticated request upstream, answering
            // `Unavailable` when the upstream service cannot be reached.
            if key.len() > "demo-".len() {
                CredentialCheck::Valid
            } else {
                CredentialCheck::Invalid(Some("That key is empty after demo-.".into()))
            }
        })
    }
}

#[derive(Clone)]
struct AccountTools {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl AccountTools {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Show which key this connection uses.",
        annotations(read_only_hint = true)
    )]
    async fn whoami(&self, Extension(parts): Extension<Parts>) -> Result<CallToolResult, McpError> {
        // The bearer guard put the caller's key in the request.
        let Some(key) = parts.extensions.get::<Credential>() else {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "unauthenticated: no key",
            )]));
        };
        let shown = &key.expose()[key.expose().len().saturating_sub(4)..];
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "You are using the key ending {shown}."
        ))]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AccountTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

struct AccountService;

impl Service for AccountService {
    fn name(&self) -> &'static str {
        "account"
    }

    fn handler(&self) -> DynHandler {
        DynHandler::new(AccountTools::new())
    }

    fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
        Some(Arc::new(DemoKeys))
    }
}

fn account(_env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(AccountService))
}

#[tokio::main]
async fn main() -> ExitCode {
    Server::new("mcp-demo-keys", env!("CARGO_PKG_VERSION"))
        .env_prefix("DEMO")
        .service("account", account)
        .sign_in(SignIn::ServiceCredential)
        .main()
        .await
}
