//! A batteries-included base for [Model Context Protocol](https://modelcontextprotocol.io) servers
//! served over Streamable HTTP.
//!
//! You write the tools, as an [`rmcp`] `ServerHandler`. This crate puts them on the network the way
//! hosted MCP clients such as claude.ai expect:
//!
//! - **OAuth 2.1 sign-in** with dynamic client registration, PKCE (S256), resource indicators
//!   (RFC 8707) and protected-resource metadata (RFC 9728). It is stateless: every token is a
//!   signed JWT, so nothing needs storing and restarts sign nobody out.
//! - **Two ways for people to sign in**, chosen with [`app::SignIn`]: the owner's password (one
//!   person, with the server's own upstream access) or each person's own credential for the
//!   upstream service, such as an API key, which is checked upstream, sealed into their tokens
//!   and handed to your tools. You can also supply your own check.
//! - **Several services on one server**, each at `/<name>` and its own OAuth protected resource,
//!   plus every service's tools together at `/mcp`.
//! - **Hardening for servers shared by many people**: sign-in limits per address, per network
//!   and overall, capped and shared upstream credential checks, MCP sessions bound to the
//!   credential that opened them, host and origin checks, body limits and constant-time
//!   comparisons.
//! - **Read-only mode and a write audit log** for every service, driven by each tool's
//!   `read_only_hint` annotation.
//! - **TLS** from certificate files (hot reloaded) or a self-signed certificate, or plain HTTP
//!   behind a proxy, a container healthcheck, graceful shutdown, JSON logs, Prometheus metrics
//!   and OpenTelemetry traces.
//! - **Configuration from environment variables**, with `<NAME>_FILE` variants for secrets and
//!   every error reported at once.
//!
//! # Quick start
//!
//! A service is a name and an MCP handler. The [`app::Server`] builder does the rest:
//!
//! ```no_run
//! use mcp_server_core::app::{Server, SignIn};
//! use mcp_server_core::combined::DynHandler;
//! use mcp_server_core::rmcp::ServerHandler;
//! use mcp_server_core::service::{Service, ServiceEnv};
//! use std::sync::Arc;
//!
//! // Your MCP server: in practice a `#[tool_router]` with your tools.
//! #[derive(Clone)]
//! struct Hello;
//!
//! impl ServerHandler for Hello {}
//!
//! struct HelloService;
//!
//! impl Service for HelloService {
//!     fn name(&self) -> &'static str {
//!         "hello"
//!     }
//!     fn handler(&self) -> DynHandler {
//!         DynHandler::new(Hello)
//!     }
//! }
//!
//! fn hello(_env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
//!     Some(Arc::new(HelloService))
//! }
//!
//! #[tokio::main]
//! async fn main() -> std::process::ExitCode {
//!     Server::new("mcp-hello", env!("CARGO_PKG_VERSION"))
//!         .env_prefix("HELLO")
//!         .service("hello", hello)
//!         .sign_in(SignIn::OwnerPassword)
//!         .main()
//!         .await
//! }
//! ```
//!
//! Run it with `PUBLIC_URL`, `OAUTH_SIGNING_KEY` and `OAUTH_ADMIN_PASSWORD` set and the service is
//! at `https://<host>/hello`. See the repository's `examples/` for a complete tool server and for
//! signing people in with their own API keys.
//!
//! # Lower-level pieces
//!
//! [`app::Server`] is a thin layer over the modules below; use them directly when you need a
//! different shape: [`server::build_app`] mounts services behind the OAuth routes,
//! [`service::mcp_service`] wraps any rmcp handler in the hardened Streamable HTTP transport and
//! [`tls::serve`] serves the result.
//!
//! # Feature flags
//!
//! - `otel` (default): export traces over OTLP/HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
//! - `prometheus` (default): serve Prometheus metrics on `METRICS_ADDR`.
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod app;
pub mod caller;
pub mod combined;
pub mod config;
pub mod credential;
pub mod guards;
pub mod jwt;
pub mod oauth;
pub mod observability;
pub mod pkce;
pub mod policy;
pub mod prompt;
pub mod server;
pub mod service;
pub mod tls;

pub use axum;
pub use rmcp;

/// The README's examples, compiled as doctests so they stay correct.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// The documentation site's pages (`docs/src`), compiled as doctests so their examples stay
/// correct.
#[cfg(doctest)]
mod book {
    #[doc = include_str!("../docs/src/introduction.md")]
    struct Introduction;
    #[doc = include_str!("../docs/src/quick-start.md")]
    struct QuickStart;
    #[doc = include_str!("../docs/src/writing-a-service.md")]
    struct WritingAService;
    #[doc = include_str!("../docs/src/combined.md")]
    struct Combined;
    #[doc = include_str!("../docs/src/prompts.md")]
    struct Prompts;
    #[doc = include_str!("../docs/src/examples.md")]
    struct Examples;
    #[doc = include_str!("../docs/src/sign-in.md")]
    struct SignIn;
    #[doc = include_str!("../docs/src/oauth.md")]
    struct Oauth;
    #[doc = include_str!("../docs/src/connecting-clients.md")]
    struct ConnectingClients;
    #[doc = include_str!("../docs/src/configuration.md")]
    struct Configuration;
    #[doc = include_str!("../docs/src/deployment.md")]
    struct Deployment;
    #[doc = include_str!("../docs/src/read-only-and-audit.md")]
    struct ReadOnlyAndAudit;
    #[doc = include_str!("../docs/src/observability.md")]
    struct Observability;
    #[doc = include_str!("../docs/src/troubleshooting.md")]
    struct Troubleshooting;
    #[doc = include_str!("../docs/src/security.md")]
    struct Security;
    #[doc = include_str!("../docs/src/limits.md")]
    struct Limits;
    #[doc = include_str!("../docs/src/endpoints.md")]
    struct Endpoints;
    #[doc = include_str!("../docs/src/lower-level-api.md")]
    struct LowerLevelApi;
    #[doc = include_str!("../docs/src/changelog.md")]
    struct Changelog;
    #[doc = include_str!("../docs/src/architecture.md")]
    struct Architecture;
    #[doc = include_str!("../docs/src/contributing.md")]
    struct Contributing;
    #[doc = include_str!("../docs/src/releases.md")]
    struct Releases;
}

/// Installs rustls' `ring` crypto provider as the process default. Call it once before serving
/// TLS or making TLS requests; later calls do nothing. [`app::Server::main`] calls it for you.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A token cancelled on Ctrl-C, or on SIGTERM on Unix, for graceful shutdown. Must be called
/// inside a Tokio runtime.
pub fn shutdown_signal() -> tokio_util::sync::CancellationToken {
    let ct = tokio_util::sync::CancellationToken::new();
    let trigger = ct.clone();
    tokio::spawn(async move {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let term = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut s) => {
                    s.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        };
        #[cfg(not(unix))]
        let term = std::future::pending::<()>();
        tokio::select! { _ = ctrl_c => {}, _ = term => {} }
        tracing::info!("shutdown signal received");
        trigger.cancel();
    });
    ct
}
