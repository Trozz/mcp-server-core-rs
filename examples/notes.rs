//! A notes server for one person: the owner signs in with a password.
//!
//! ```sh
//! PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
//! OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
//! LOG_FORMAT=pretty cargo run --example notes
//! ```
//!
//! Then add `http://localhost:8443/notes` to an MCP client, or try it with
//! `npx @modelcontextprotocol/inspector`. Set `NOTES_READ_ONLY=notes` to hide `add_note`, and
//! `MCP_AUTH_TOKEN` to connect with a fixed bearer token instead of signing in.

use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::combined::DynHandler;
use mcp_server_core::rmcp; // rmcp's macros need `rmcp` in scope
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::handler::server::wrapper::Parameters;
use mcp_server_core::rmcp::model::{
    CallToolResult, ContentBlock, ServerCapabilities, ServerConfig,
};
use mcp_server_core::rmcp::schemars::{self, JsonSchema};
use mcp_server_core::rmcp::{
    ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router,
};
use mcp_server_core::service::{Service, ServiceEnv};
use serde::Deserialize;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

/// The notes, shared by every MCP session.
type Notes = Arc<Mutex<Vec<String>>>;

/// The MCP server: one instance per session, sharing the notes.
#[derive(Clone)]
struct NotesTools {
    notes: Notes,
    tool_router: ToolRouter<Self>,
}

#[derive(Deserialize, JsonSchema)]
struct AddNote {
    /// The note's text.
    text: String,
}

#[tool_router]
impl NotesTools {
    fn new(notes: Notes) -> Self {
        Self {
            notes,
            tool_router: Self::tool_router(),
        }
    }

    // `read_only_hint = true` marks a tool that only reads: it stays available on a read-only
    // service and is not audited.
    #[tool(description = "List every note.", annotations(read_only_hint = true))]
    async fn list_notes(&self) -> Result<CallToolResult, McpError> {
        let notes = self.notes.lock().unwrap().join("\n");
        Ok(CallToolResult::success(vec![ContentBlock::text(notes)]))
    }

    #[tool(description = "Add a note.", annotations(read_only_hint = false))]
    async fn add_note(
        &self,
        Parameters(AddNote { text }): Parameters<AddNote>,
    ) -> Result<CallToolResult, McpError> {
        if text.trim().is_empty() {
            // Tool errors start with a kind, which the audit log records.
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "invalid_argument: text is empty",
            )]));
        }
        self.notes.lock().unwrap().push(text);
        Ok(CallToolResult::success(vec![ContentBlock::text("added")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for NotesTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Keeps short notes.")
    }
}

/// The service mounted at `/notes`.
struct NotesService {
    notes: Notes,
}

impl Service for NotesService {
    fn name(&self) -> &'static str {
        "notes"
    }

    fn handler(&self) -> DynHandler {
        DynHandler::new(NotesTools::new(self.notes.clone()))
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["add_note".into(), "list_notes".into()]
    }
}

/// Reads the service's own configuration (none here) and builds it.
fn notes(_env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(NotesService {
        notes: Arc::default(),
    }))
}

#[tokio::main]
async fn main() -> ExitCode {
    Server::new("mcp-notes", env!("CARGO_PKG_VERSION"))
        .env_prefix("NOTES")
        .service("notes", notes)
        .sign_in(SignIn::OwnerPassword)
        .main()
        .await
}
