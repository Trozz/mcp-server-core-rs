# Quick start

This page takes you from an empty crate to an MCP server running on your machine, with Claude Code connected to it.

## Add the crate

In a new binary crate (`cargo new mcp-hello`), add the crate, Tokio and serde:

```sh
cargo add mcp-server-core
cargo add tokio --features macros,rt-multi-thread
cargo add serde --features derive
```

The serde crate is not needed by the server below, but every tool with arguments derives `Deserialize`, so you will want it soon. Use rmcp through the crate's re-export, `mcp_server_core::rmcp`, rather than adding it yourself: its types appear in this crate's API, so the versions must match.

rmcp's macros (`#[tool_router]`, `#[tool_handler]`, `#[prompt_router]` and the rest) generate code that names the crate `rmcp`. Without rmcp in your own `Cargo.toml`, that name only resolves if you bring the re-export into scope under it, so every file that uses the macros has `use mcp_server_core::rmcp;` among its `use` lines, as below.

## The smallest server

A service is a name and an rmcp handler; the [`Server`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html) builder does the rest. Put this in `src/main.rs`:

```rust,no_run
// rmcp's macros name the crate `rmcp`: this makes that name the re-export.
use mcp_server_core::rmcp;
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::combined::DynHandler;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use mcp_server_core::service::{Service, ServiceEnv};
use std::sync::Arc;

/// The MCP handler: one per MCP session.
#[derive(Clone)]
struct Hello {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Hello {
    fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }

    #[tool(description = "Say hello.", annotations(read_only_hint = true))]
    async fn hello(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![ContentBlock::text("Hello from mcp-hello.")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Hello {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// The service, mounted at `/hello`.
struct HelloService;

impl Service for HelloService {
    fn name(&self) -> &'static str {
        "hello"
    }
    fn handler(&self) -> DynHandler {
        DynHandler::new(Hello::new())
    }
    // Only used for the startup log.
    fn tool_names(&self) -> Vec<String> {
        vec!["hello".into()]
    }
}

/// Reads the service's own configuration (none here) and builds it.
fn hello(_env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(HelloService))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    Server::new("mcp-hello", env!("CARGO_PKG_VERSION"))
        .env_prefix("HELLO")
        .service("hello", hello)
        .sign_in(SignIn::OwnerPassword)
        .main()
        .await
}
```

The pieces, from the top:

| Piece | What it is |
|---|---|
| `Hello` | An ordinary rmcp handler. `#[tool_router]` collects the `#[tool]` methods and `#[tool_handler]` answers `tools/list` and `tools/call` from them. |
| `read_only_hint = true` | Marks `hello` as a tool that only reads. The server uses it for [read-only mode and the audit log](read-only-and-audit.md); a tool without it counts as a write. |
| `HelloService` | Implements [`Service`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/trait.Service.html): a name, which becomes the path `/hello`, and a handler for each MCP session. |
| `hello` | A service factory. It receives the environment reader so a service can read its own variables, and returns `None` when it cannot start. |
| `Server` | Builds the binary: `--version`, `--help` and `--healthcheck`, configuration, logging, OAuth, TLS and serving. `env_prefix("HELLO")` names this server's own variables `HELLO_SERVICES`, `HELLO_READ_ONLY` and `HELLO_COMBINED`. |

[Writing a service](writing-a-service.md) covers each of these in full.

## Run it locally

Everything is configured with environment variables. For a first run on your own machine:

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
LOG_FORMAT=pretty cargo run
```

| Variable | Why |
|---|---|
| `PUBLIC_URL` | The URL clients use, without a path. It must be `https://`, except for `localhost`, `127.0.0.1` and `[::1]`, where `http://` is allowed. |
| `INSECURE_HTTP=true` | Serve plain HTTP, to match the `http://` URL. Without it the server serves HTTPS with a self-signed certificate it generates at startup. |
| `OAUTH_SIGNING_KEY` | Signs every token; at least 32 bytes. A new key signs everyone out, so the `$(openssl rand -hex 32)` above signs clients out on each restart. For longer use, generate one once and keep it, for example in a file named by `OAUTH_SIGNING_KEY_FILE`. |
| `OAUTH_ADMIN_PASSWORD` | The owner's password for the sign-in page: at least 12 characters, and not only spaces. Shorter than 15 gets a warning at startup. |
| `LOG_FORMAT=pretty` | Readable logs instead of JSON. |

The server listens on `0.0.0.0:8443` (change it with `BIND_ADDR`). The startup log says what it is serving, in this order:

| Message | Fields |
|---|---|
| `starting mcp-hello` | `version` |
| `service enabled`, once per service | `service`, `url` (`http://localhost:8443/hello`), `read_only`, `tools` (from `tool_names`) |
| `combined endpoint enabled` | `url` (`http://localhost:8443/mcp`), `tools` (how many) |
| `listening` | `addr` |
| `INSECURE_HTTP=true: serving plaintext HTTP without TLS` (a warning) | `addr` |

Any warnings about weak settings, such as a short password, come straight after `starting`.

The service is at `http://localhost:8443/hello`, and every service's tools together are at `http://localhost:8443/mcp`, where `hello` is called `hello_hello` (see [Several services and /mcp](combined.md)).

If something is missing or wrong, the server prints every problem at once and exits with status 1, without starting:

```text
configuration error: PUBLIC_URL is required
configuration error: OAUTH_SIGNING_KEY must be at least 32 bytes
configuration error: OAUTH_ADMIN_PASSWORD is required
```

The [configuration reference](configuration.md) lists every variable, and [Troubleshooting](troubleshooting.md) every startup error.

## Check it is running

`/healthz` needs no authentication and answers `ok`:

```sh
curl http://localhost:8443/healthz
```

The binary checks itself the same way, which is what a container `HEALTHCHECK` runs. Run it with the same environment as the server, since it reads `BIND_ADDR` and `INSECURE_HTTP`:

```sh
INSECURE_HTTP=true cargo run -- --healthcheck && echo healthy
cargo run -- --version
```

`--healthcheck` requests `/healthz` on `127.0.0.1` at the `BIND_ADDR` port, over TLS unless `INSECURE_HTTP` is set, and exits 0 on a `200`. `--version` prints `mcp-hello 0.1.0`.

## Connect Claude Code

Claude Code can sign in with OAuth, but the quickest way on your own machine is the static token, `MCP_AUTH_TOKEN`: a fixed bearer token accepted on every path. Stop the server, choose a token and start it again with the token set:

```sh
export MCP_AUTH_TOKEN=$(openssl rand -hex 32)
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
LOG_FORMAT=pretty cargo run
```

Then, in another terminal with the same `MCP_AUTH_TOKEN`:

```sh
claude mcp add --transport http hello http://localhost:8443/hello \
  --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

Start `claude` and ask it to say hello with the `hello` tool. The [static token](sign-in.md#the-static-token) has rules of its own:

- It must not have the shape of a JWT (three dot-separated parts), or the server refuses to start.
- One shorter than 32 characters gets a warning at startup. `openssl rand -hex 32` gives 64.
- It cannot be used when people sign in with their own credential, as with `SignIn::ServiceCredential`: the server refuses to start.
- Wrong tokens count towards the sign-in limits, which bounds how fast anyone can guess it.

Leave out `--header` and Claude Code signs in with OAuth instead: it registers itself, opens the sign-in page in your browser, and you enter `OAUTH_ADMIN_PASSWORD`. [Sign-in modes](sign-in.md) explains the other ways to sign in, and [Connecting clients](connecting-clients.md#claude-code) covers Claude Code and other clients in full.

You can also talk to the server with curl. An `initialize` request answers with an `mcp-session-id` header and a short server-sent event stream whose last `data:` line holds the result:

```sh
curl -i http://localhost:8443/hello \
  -H "Authorization: Bearer $MCP_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

Without the `Authorization` header the answer is `401` with a `WWW-Authenticate` header naming `http://localhost:8443/.well-known/oauth-protected-resource/hello`, which is how MCP clients find the sign-in flow.

## Why claude.ai needs more

claude.ai connects from Anthropic's servers, not from your machine, so it cannot reach `localhost`, and it only accepts a certificate it trusts. To add the server as a claude.ai custom connector, run it at a public `https://` address: with a certificate from files (Let's Encrypt works), or with `INSECURE_HTTP=true` behind a reverse proxy or tunnel that terminates TLS, with `TRUSTED_PROXIES` set to the proxy's address. A self-signed certificate is not enough: claude.ai does not trust it. [TLS and deployment](deployment.md) shows both setups.

## Next steps

- [Writing a service](writing-a-service.md): tools with arguments, reading configuration, the caller's credential, and the rest of the `Server` builder.
- [Examples](examples.md): two complete servers in the repository, one for the owner and one shared by many people.
- [Sign-in modes](sign-in.md): let each person sign in with their own API key for the upstream service.
- [TLS and deployment](deployment.md): put the server on the internet.
