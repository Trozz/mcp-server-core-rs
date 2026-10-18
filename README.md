# mcp-server-core

[![crates.io](https://img.shields.io/crates/v/mcp-server-core.svg)](https://crates.io/crates/mcp-server-core)
[![docs.rs](https://img.shields.io/docsrs/mcp-server-core)](https://docs.rs/mcp-server-core)
[![CI](https://github.com/Trozz/mcp-server-core-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Trozz/mcp-server-core-rs/actions/workflows/ci.yml)
[![licence](https://img.shields.io/crates/l/mcp-server-core.svg)](#licence)

A batteries-included base for [Model Context Protocol](https://modelcontextprotocol.io) servers
over Streamable HTTP, built on the official Rust SDK, [rmcp](https://crates.io/crates/rmcp).

You write the tools. `mcp-server-core` puts them on the internet the way hosted MCP clients such
as claude.ai expect, with sign-in, TLS and the hardening a server shared by many people needs.

- **OAuth 2.1 built in**: dynamic client registration, PKCE (S256), resource indicators
  (RFC 8707) and protected-resource metadata (RFC 9728). Nothing to store: every token is a signed
  JWT, so restarts and extra replicas sign nobody out.
- **Two ways to sign in**: the owner's password, for a personal server; or each person's own key
  for the upstream API your tools call, checked on sign-in, sealed into their tokens and handed to
  your tools, so one deployment serves many people. Or bring your own check.
- **Several services on one server**: each at `/<name>` and its own OAuth resource, and all their
  tools together at `/mcp`.
- **Hardened**: sign-in limits per address, per network and overall, capped and shared upstream
  credential checks, grants that end when the password changes and 90 days after sign-in, MCP sessions bound
  to the credential that opened them, host and origin checks against DNS rebinding, capped client
  registration, body limits, constant-time comparisons, secrets kept out of logs. See
  [SECURITY.md](SECURITY.md) for what it does not do.
- **Read-only mode and an audit log** for every service, from each tool's `read_only_hint`.
- **Ready to deploy**: TLS from files (hot reloaded) or self-signed, or plain HTTP behind a proxy;
  a `--healthcheck` for containers; graceful shutdown; JSON logs; Prometheus metrics; OpenTelemetry
  traces.
- **Configured by environment variables**, with `_FILE` variants for secrets and every error
  reported at once.

## Quick start

```sh
cargo add mcp-server-core
cargo add tokio --features macros,rt-multi-thread
cargo add serde --features derive
```

A service is a name and an rmcp handler; the `Server` builder does the rest.

```rust,no_run
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::combined::DynHandler;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use mcp_server_core::service::{Service, ServiceEnv};
use std::sync::Arc;

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
        Ok(CallToolResult::success(vec![ContentBlock::text("Hello!")]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Hello {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

struct HelloService;

impl Service for HelloService {
    fn name(&self) -> &'static str {
        "hello"
    }
    fn handler(&self) -> DynHandler {
        DynHandler::new(Hello::new())
    }
}

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

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
LOG_FORMAT=pretty cargo run
```

The service is now at `http://localhost:8443/hello`. Point an MCP client (or
`npx @modelcontextprotocol/inspector`) at it, sign in with the password, and call `hello`.

The [`examples/`](examples) directory has two complete servers:
[`notes`](examples/notes.rs) (owner password, read and write tools) and
[`api_keys`](examples/api_keys.rs) (each person signs in with their own API key). Run them with
`cargo run --example notes`.

## How people sign in

Choose with `Server::sign_in`:

| | Who signs in | What tools get |
|---|---|---|
| `SignIn::OwnerPassword` | One person, with `OAUTH_ADMIN_PASSWORD`. `MCP_AUTH_TOKEN` can also be set for clients that cannot do OAuth. | Nothing: tools act with the server's own upstream configuration, say an API key in the environment. |
| `SignIn::ServiceCredential` | Anyone with a credential the upstream service accepts, checked by the `CredentialVerifier` your service returns from `Service::credential_verifier`. | The caller's credential, as a `Credential` in the request extensions. Clients may also send it directly as their bearer token. |
| `SignIn::Custom(fn)` | Whoever your own `CredentialVerifier` accepts. | Either, depending on its `carried()`. |

Every request a service receives carries a `caller::Caller`: who signed in (`owner`,
`key:<short hash>` for a person's own credential, `static`) and how. The audit log records it.

Why only these? Every way to sign in is code on the one page that guards everything, and the
[MCP authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)
expects single sign-on to come from an authorization server built for it. For single sign-on, MFA
or many named users, put an identity-aware gateway (Cloudflare Access, oauth2-proxy and the like)
in front of `/authorize`, the only page a person's browser opens.

With `ServiceCredential` the server stores no credential: it is checked once, then encrypted
(ChaCha20-Poly1305, under a key derived from `OAUTH_SIGNING_KEY`) inside the person's tokens.
A tool reads it from the request:

```rust
use mcp_server_core::axum::http::request::Parts;
use mcp_server_core::credential::Credential;

/// The caller's key. A `#[tool]` method gets `parts` by taking an
/// `Extension(parts): Extension<Parts>` argument (`rmcp::handler::server::tool::Extension`).
fn api_key(parts: &Parts) -> Option<&str> {
    parts.extensions.get::<Credential>().map(Credential::expose)
}
```

A verifier says what the credential is called on the sign-in page and checks it, typically with
one cheap authenticated request upstream:

```rust
use mcp_server_core::credential::{CheckFuture, CredentialCheck, CredentialVerifier};

struct ApiKeys { /* an HTTP client */ }

impl CredentialVerifier for ApiKeys {
    fn label(&self) -> &str { "Example API key" }
    fn help(&self) -> &str { "Create one under Settings, API keys at example.com." }
    fn check<'a>(&'a self, key: &'a str) -> CheckFuture<'a> {
        Box::pin(async move {
            // Valid, Invalid(reason) on a 401, Unavailable(why) when upstream is down.
            CredentialCheck::Valid
        })
    }
}
```

Checks run with a timeout, at most 16 at once, and once at a time per credential. Each check counts
towards the sign-in limits (5 a minute per address, 25 per IPv4 /24 or IPv6 /48) while it runs; a
rejection keeps counting, while `Valid` and `Unavailable` are given back.

## Endpoints

| Path | |
|---|---|
| `/<service>` | Each service's MCP endpoint (Streamable HTTP). |
| `/mcp` | Every service's tools together, as `<service>_<tool>` (turn off with `<PREFIX>_COMBINED=false`). |
| `/.well-known/oauth-protected-resource/<service>` | Protected-resource metadata. |
| `/.well-known/oauth-authorization-server` | Authorization-server metadata. |
| `/register`, `/authorize`, `/token` | OAuth: registration, the sign-in page, tokens. |
| `/healthz` | Liveness, no authentication. |
| `/favicon.ico` | The icon given to `Server::icon`. |

## Configuration

All configuration is read from environment variables. Any variable can be given as a file
instead: `OAUTH_SIGNING_KEY_FILE=/run/secrets/key`.

| Variable | Default | |
|---|---|---|
| `PUBLIC_URL` | required | The external URL clients use, without a path: `https://mcp.example.com`. `http://` only for `localhost`. |
| `OAUTH_SIGNING_KEY` | required | At least 32 bytes (`openssl rand -hex 32`). Changing it signs everyone out. |
| `OAUTH_ADMIN_PASSWORD` | required for `OwnerPassword` | The owner's password, at least 12 characters. |
| `MCP_AUTH_TOKEN` | none | A fixed bearer token, for clients that cannot do OAuth. Not with a verifier that takes people's own credentials or accepts them as bearer tokens, and not shaped like a JWT (three dot-separated parts). Use a long random value (`openssl rand -hex 32`). |
| `<PREFIX>_SERVICES` | all | Comma-separated services to run. |
| `<PREFIX>_COMBINED` | `true` | Serve every service's tools together at `/mcp`. |
| `<PREFIX>_READ_ONLY` | none | Comma-separated services, or `all`, whose write tools are hidden and refused. |
| `AUDIT_LOG_PATH` | none | Append a JSON line for every write tool call. |
| `BIND_ADDR` | `0.0.0.0:8443` | Listen address. |
| `TLS_CERT_PATH`, `TLS_KEY_PATH` | none | PEM certificate chain and key, reloaded when they change. Without them, a self-signed certificate. |
| `INSECURE_HTTP` | `false` | Plain HTTP, behind a proxy that terminates TLS. |
| `TRUSTED_PROXIES` | none | Proxy IPs whose `X-Forwarded-For` is believed for rate limiting. |
| `ALLOWED_ORIGINS` | none | Extra browser origins allowed to call the MCP endpoints. |
| `LOG_LEVEL` | `info` | A `tracing` filter. |
| `LOG_FORMAT` | `json` | `json` or `pretty`. |
| `DEBUG` | `false` | Debug logs for your crates and this one. |
| `DEBUG_UNSAFE_LOG_CONTENT` | `false` | Let services log content. Never in production. |
| `METRICS_ADDR` | none | Serve Prometheus metrics, e.g. `0.0.0.0:9090`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | none | Export traces over OTLP/HTTP; the standard `OTEL_*` variables apply. |

`<PREFIX>` is set with `Server::env_prefix` (default `MCP`). Your services read their own variables
from the `ServiceEnv` they are given, recording problems in `env.errors` so every mistake is
reported together.

## Connecting clients

- **claude.ai** (Settings, Connectors, Add custom connector): the URL of a service,
  `https://mcp.example.com/hello`, or `https://mcp.example.com/mcp` for every service. Claude
  registers itself and opens the sign-in page.
- **Claude Code**: `claude mcp add --transport http hello https://mcp.example.com/hello`, adding
  `--header "Authorization: Bearer $MCP_AUTH_TOKEN"` (or the person's own key with
  `ServiceCredential`) to skip OAuth.
- **Any other client** that speaks Streamable HTTP and MCP authorization.

claude.ai needs a certificate it trusts: use `TLS_CERT_PATH`/`TLS_KEY_PATH` (Let's Encrypt
works) or run with `INSECURE_HTTP=true` behind a proxy that terminates TLS, setting
`TRUSTED_PROXIES` to its address.

## Deploying

The binary is configured entirely by its environment, so it fits any container platform. A
container healthcheck:

```dockerfile
HEALTHCHECK CMD ["/usr/local/bin/my-server", "--healthcheck"]
```

`SIGTERM` drains open connections for up to ten seconds. All state that matters lives in tokens,
so replicas need only share `OAUTH_SIGNING_KEY`; sign-in limits and one-time codes are kept per
replica.

Metrics include `http_requests_total`, `oauth_requests_total`, `oauth_login_failures_total` and
`bearer_credential_checks_total`.

### Rate limiting requests

The crate limits sign-in guesses and upstream credential checks itself. Limit request rates in
front of it, at your reverse proxy, or with your own tower layer through `Server::wrap_router`.
Hosted clients such as claude.ai reach the server from a few shared addresses, so do not limit
`/mcp`, `/<service>`, `/token` or `/register` per client address: one busy person would block
everyone. Limit per bearer token instead, and per address only on `/authorize`, the page a
person's browser opens. With nginx:

```nginx
limit_req_zone $http_authorization zone=per_token:10m rate=20r/s;
limit_req_zone $binary_remote_addr zone=sign_in:10m rate=10r/m;

# Keep the public host (the MCP endpoints check it) and pass the client's address on.
proxy_set_header Host $host;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

location /authorize { limit_req zone=sign_in burst=10; proxy_pass https://mcp; }
location /          { limit_req zone=per_token burst=40; proxy_pass https://mcp; }
```

Set `TRUSTED_PROXIES` to nginx's address, or every client shares nginx's sign-in limits. Requests
without an `Authorization` header, such as `/token` and `/register`, are not limited by the
per-token zone.

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability. In short:
keep `OAUTH_SIGNING_KEY` secret (it signs every token and seals every credential), serve over TLS,
and set `TRUSTED_PROXIES` only to proxies you run.

## Lower-level use

`app::Server` is a thin layer. For a different shape, use the pieces directly:
`server::build_app` mounts services behind the OAuth routes and bearer guards,
`service::mcp_service` serves any rmcp handler with the hardened transport, `oauth::AuthState`
holds the authorization server, and `tls::serve` serves the result. See the
[API documentation](https://docs.rs/mcp-server-core).

## Feature flags

| Feature | Default | |
|---|---|---|
| `otel` | yes | OpenTelemetry trace export. |
| `prometheus` | yes | The Prometheus metrics endpoint. |

Without them the crate builds noticeably faster; setting `OTEL_EXPORTER_OTLP_ENDPOINT` or
`METRICS_ADDR` then only logs a warning.

## Versions

The minimum supported Rust version is 1.88. rmcp types appear in the public API, so this crate
follows rmcp's minor versions (it is re-exported as `mcp_server_core::rmcp`; use that rather than
depending on a different rmcp yourself). Until 1.0, minor versions may change the API; see the
[changelog](CHANGELOG.md).

Used by [mcp-icloud](https://github.com/Trozz/mcp-icloud).

## Licence

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT licence](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate by you, as defined in the Apache-2.0 licence, shall be dual licensed as above, without
any additional terms or conditions.
