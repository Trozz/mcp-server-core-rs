# Lower-level API

`app::Server` is a thin layer over public modules. This page maps those modules, shows how to build and serve a server from them without `app::Server`, and explains the re-exports, feature flags and what the crate's version numbers promise. Every item is documented in full on [docs.rs](https://docs.rs/mcp-server-core).

## When to use it

Most servers need only [`app::Server`](writing-a-service.md#the-server-builder). Reach for the modules below when you need a different shape:

- your configuration comes from somewhere other than environment variables;
- you serve with your own listener, or alongside routes of an existing axum application;
- you want one piece on its own, such as the hardened MCP transport, the token issuer in a test, or the sign-in limiter.

There is a middle way too: [`Server::load`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.load) and [`Server::router`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.router) give you the whole application as an `axum::Router` without serving it, as [Testing a whole server](writing-a-service.md#testing-a-whole-server) shows. Serve that router however you like, as long as handlers see the peer address (see [Serving with your own listener](#serving-with-your-own-listener)).

## Module map

| Module | What it holds |
|---|---|
| [`app`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/index.html) | `Server`, the builder for a whole binary; `SignIn`; `Loaded`, a checked configuration with its services built; `Safety`, the read-only services and the audit log; `healthcheck()`, the `--healthcheck` probe; `MIN_ADMIN_PASSWORD_CHARS`, `RECOMMENDED_ADMIN_PASSWORD_CHARS`, `RECOMMENDED_STATIC_TOKEN_CHARS` |
| [`caller`](https://docs.rs/mcp-server-core/latest/mcp_server_core/caller/index.html) | `Caller` and `Via`: who made a request and how they proved it; `STATIC_SUBJECT` |
| [`combined`](https://docs.rs/mcp-server-core/latest/mcp_server_core/combined/index.html) | `Combined`, several handlers served as one MCP server (`/mcp`); `DynHandler`, a type-erased handler; `ToolHandler`, the trait behind it; `prefixed_name`; `COMBINED` (`"mcp"`) |
| [`config`](https://docs.rs/mcp-server-core/latest/mcp_server_core/config/index.html) | `EnvReader`, which reads variables and collects every error; `CoreConfig`, the settings every server shares |
| [`credential`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/index.html) | `CredentialVerifier`, `CredentialCheck` and `CheckFuture`; `PasswordVerifier`; `Credential`, the caller's credential in the request extensions; `Sealer` and `SealError`; `fingerprint`, `plausible`, `MAX_CREDENTIAL_LEN`, `MAX_PASSWORD_LEN` |
| [`guards`](https://docs.rs/mcp-server-core/latest/mcp_server_core/guards/index.html) | `LoginLimiter`, `Ceiling`, `Refusal` and `Reservation`: the sign-in limits; `ReplayGuard`, one-time use of codes; `GLOBAL_MAX_FAILURES`, `BLOCK_MAX_ATTEMPTS` |
| [`jwt`](https://docs.rs/mcp-server-core/latest/mcp_server_core/jwt/index.html) | `Jwt`, which issues and verifies the server's tokens; `Claims`, `Payload`, `TokenKind`, `JwtError`; `LEEWAY_SECS`, `SERVER_SUBJECT` |
| [`oauth`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/index.html) | `AuthState`, the authorization server's state; `OAuthSettings`; `oauth_router`, its routes; `require_bearer`, the bearer guard; `client_ip`; `validate_redirect_uri`; `sign_in_version`; the limit and lifetime constants |
| [`observability`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/index.html) | `init`, `ObservabilityConfig`, `ObservabilityGuard` and `LogFormat`; `log_filter` and `build_filter`; `debug_enabled` and `content_logging_enabled` |
| [`pkce`](https://docs.rs/mcp-server-core/latest/mcp_server_core/pkce/index.html) | `s256`, `verify` and `ct_eq`, the constant-time comparison every secret goes through |
| [`policy`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/index.html) | `Guarded`, the wrapper that applies read-only mode and the audit log; `ToolPolicy`; `AuditLog` and `AuditLine`; `is_read_only`, `visible_tools`; `AUDIT_TARGET` |
| [`prompt`](https://docs.rs/mcp-server-core/latest/mcp_server_core/prompt/index.html) | `tool_prefix` and `ToolPrefix`; `UNAVAILABLE`; `argument`, `number_argument`, `user_prompt`, `not_found` |
| [`server`](https://docs.rs/mcp-server-core/latest/mcp_server_core/server/index.html) | `build_app`, the HTTP application; `http_metrics`; `BODY_LIMIT` |
| [`service`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/index.html) | `Service`, `ServiceFactory` and `ServiceEnv`; `ServiceContext` and `HttpSettings`; `mcp_service`, the hardened Streamable HTTP transport; `icons`; `QUIET_LOG_TARGETS` |
| [`tls`](https://docs.rs/mcp-server-core/latest/mcp_server_core/tls/index.html) | `serve`; `TlsMode`; `generate_self_signed` and `SelfSigned`; `healthcheck` |

At the crate root:

| Item | What it is |
|---|---|
| [`install_crypto_provider()`](https://docs.rs/mcp-server-core/latest/mcp_server_core/fn.install_crypto_provider.html) | Installs rustls' `ring` provider as the process default. Call it once before serving TLS; later calls do nothing. `Server::main` calls it for you. |
| [`shutdown_signal()`](https://docs.rs/mcp-server-core/latest/mcp_server_core/fn.shutdown_signal.html) | A `CancellationToken` cancelled on Ctrl-C, or `SIGTERM` on Unix. Call it inside a Tokio runtime. |
| `axum`, `rmcp` | The two crates whose types appear in this crate's API, re-exported. See [Re-exports](#re-exports). |

[Architecture](architecture.md) explains how the modules work together on a request.

### Public constants

| Constant | Value | Explained on |
|---|---|---|
| `app::MIN_ADMIN_PASSWORD_CHARS` | 12 | [Configuration reference](configuration.md#validation) |
| `app::RECOMMENDED_ADMIN_PASSWORD_CHARS` | 15 | [Configuration reference](configuration.md#warnings) |
| `app::RECOMMENDED_STATIC_TOKEN_CHARS` | 32 | [Configuration reference](configuration.md#warnings) |
| `caller::STATIC_SUBJECT` | `"static"` | [Sign-in modes](sign-in.md#who-made-a-request) |
| `combined::COMBINED` | `"mcp"` | [Several services and /mcp](combined.md) |
| `credential::MAX_CREDENTIAL_LEN` | 256 bytes | [Sign-in modes](sign-in.md#the-credentialverifier-trait) |
| `credential::MAX_PASSWORD_LEN` | 1024 bytes | [Sign-in modes](sign-in.md#the-credentialverifier-trait) |
| `guards::GLOBAL_MAX_FAILURES` | 30 | [Limits](limits.md#the-global-ceiling) |
| `guards::BLOCK_MAX_ATTEMPTS` | 25 | [Limits](limits.md#per-block) |
| `jwt::LEEWAY_SECS` | 5 | [OAuth and tokens](oauth.md#tokens) |
| `jwt::SERVER_SUBJECT` | `"server"` | [OAuth and tokens](oauth.md#tokens) |
| `oauth::LOGIN_ATTEMPTS` | 5 | [Limits](limits.md#per-address) |
| `oauth::LOGIN_WINDOW` | 60 seconds | [Limits](limits.md#per-address) |
| `oauth::MAX_RUNNING_CHECKS` | 16 | [Limits](limits.md#credential-checks) |
| `oauth::CHECK_TIMEOUT` | 15 seconds | [Limits](limits.md#credential-checks) |
| `oauth::CHECK_SLOT_WAIT` | 5 seconds | [Limits](limits.md#credential-checks) |
| `oauth::BEARER_VALID_FOR` | 600 seconds | [Limits](limits.md#verdict-cache) |
| `oauth::BEARER_INVALID_FOR` | 60 seconds | [Limits](limits.md#verdict-cache) |
| `oauth::MAX_GRANT_AGE` | 90 days | [OAuth and tokens](oauth.md#auth_time-and-the-90-day-limit) |
| `oauth::MAX_REDIRECT_URIS` | 10 | [Limits](limits.md#client-registration) |
| `oauth::MAX_REDIRECT_URI_LEN` | 2048 bytes | [Limits](limits.md#client-registration) |
| `oauth::MAX_CLIENT_NAME_CHARS` | 200 | [Limits](limits.md#client-registration) |
| `policy::AUDIT_TARGET` | `"audit"` | [Read-only mode and the audit log](read-only-and-audit.md#where-the-lines-go) |
| `prompt::UNAVAILABLE` | A sentence for the end of a prompt that names tools: `"If a tool named here is not available on this server (for example because the service is read-only or the tool is turned off), say so and stop that step."` | [Prompts](prompts.md#the-prompt-module) |
| `server::BODY_LIMIT` | 1,048,576 bytes (1 MiB) | [Limits](limits.md#request-bodies) |
| `service::QUIET_LOG_TARGETS` | `rmcp::transport::streamable_http_server`, `rmcp::transport::worker` | [Observability](observability.md#rmcp-session-targets) |

## What app::Server does

Before you replace `app::Server`, know what it does, so you keep what you need. `Server::main`:

1. handles `--version` (or `-V`), `--help` (or `-h`) and `--healthcheck`, and exits with status 2 on any other argument; otherwise it calls `install_crypto_provider()`;
2. reads the configuration with `Server::load`: `CoreConfig::from_env`, the sign-in verifier (for `SignIn::OwnerPassword`, `OAUTH_ADMIN_PASSWORD` of at least 12 characters, not only spaces; for `SignIn::Custom`, your function's), `<PREFIX>_SERVICES`, `<PREFIX>_READ_ONLY`, `AUDIT_LOG_PATH` and `<PREFIX>_COMBINED`, then each selected service's factory. For `SignIn::ServiceCredential` it then takes the verifier of the one enabled service that defines one. It reports a static token that cannot be used (shaped like a JWT, or next to a verifier that takes people's own credentials) as a configuration error, collects the startup warnings and removes duplicate errors;
3. rewrites `LOG_LEVEL` with `observability::log_filter`, applying every service's log caps, quietening rmcp's session targets and keeping the `audit` target on, then calls `observability::init`;
4. logs the startup warnings, each enabled service with its URL, read-only state and tools, and the combined endpoint with its number of tools;
5. builds the application with `Server::router`: an `AuthState` whose resources are the services (and `mcp` when the combined endpoint is on), each service's router with its `ToolPolicy` attached, the combined endpoint, `server::build_app`, `/favicon.ico`, your `wrap_router` function, and a last layer that adds `X-Content-Type-Options: nosniff` to every response and `Strict-Transport-Security: max-age=31536000` when serving certificate files;
6. serves it with `tls::serve` until `shutdown_signal()` fires.

Anything you leave out is absent. In particular:

- without a `ToolPolicy` on a service's router, the policy wrapper changes nothing: no read-only mode and no audit lines;
- `build_app` sends `nosniff` but never HSTS;
- `AuthState::new` panics on a static token it cannot use, where `Server::load` would report it with the other errors;
- `PasswordVerifier::new` takes a password of any length; the 12-character minimum is checked by `Server::load`;
- without `log_filter`, a `LOG_LEVEL` of `info` or more verbose lets rmcp log MCP session ids, and a `LOG_LEVEL` of `warn` or quieter drops the audit lines from the logs (the audit file, if any, is still written).

## A server without app::Server

This builds one service, `tools`, behind the owner's password, from the same environment variables `app::Server` reads, with read-only mode and the audit log wired in:

```rust,no_run
use mcp_server_core::axum::Extension;
use mcp_server_core::config::{CoreConfig, EnvReader};
use mcp_server_core::credential::PasswordVerifier;
use mcp_server_core::oauth::AuthState;
use mcp_server_core::policy::{AUDIT_TARGET, AuditLog, ToolPolicy};
use mcp_server_core::rmcp::ServerHandler;
use mcp_server_core::server::build_app;
use mcp_server_core::service::{HttpSettings, ServiceContext, mcp_service};
use mcp_server_core::{install_crypto_provider, observability, shutdown_signal, tls};
use std::sync::Arc;

/// Your MCP server: in practice a `#[tool_router]` with your tools.
#[derive(Clone)]
struct Tools;

impl ServerHandler for Tools {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_crypto_provider();

    // 1. Configuration: the core settings and the owner's password, every error at once.
    let mut env = EnvReader::from_process();
    let core = CoreConfig::from_env(&mut env, "mcp-tools", "mcp_tools");
    let password = env.secret_required("OAUTH_ADMIN_PASSWORD");
    let (Some(core), Some(password)) = (core, password) else {
        for e in &env.errors {
            eprintln!("configuration error: {e}");
        }
        std::process::exit(1);
    };

    // 2. Logs, metrics and traces, keeping session ids out and the audit target on.
    let mut obs = core.observability.clone();
    obs.log_level = observability::log_filter(&obs.log_level, &[], &[AUDIT_TARGET]);
    let _guard = observability::init(&obs)?;

    // 3. The authorization server, with one protected resource: PUBLIC_URL/tools.
    let auth = AuthState::new(
        core.oauth.clone(),
        &["tools"],
        Arc::new(PasswordVerifier::new(password)),
    );

    // 4. The service on the hardened transport, with its read-only rule and audit log.
    let shutdown = shutdown_signal();
    let ctx = ServiceContext {
        http: HttpSettings::from_core(&core),
        shutdown: shutdown.clone(),
    };
    let policy = ToolPolicy {
        service: "tools".into(),
        endpoint: "/tools".into(),
        read_only: false,
        audit: Arc::new(AuditLog::new(None)),
    };
    let tools = mcp_service(&ctx, || Ok(Tools)).layer(Extension(policy));

    // 5. /healthz, the OAuth routes and /tools behind its bearer guard. Serve until SIGTERM.
    let app = build_app(auth, vec![("tools", tools)]);
    tls::serve(app, core.bind_addr, core.tls.clone(), shutdown).await
}
```

It needs `anyhow` and `tokio` (with `macros` and `rt-multi-thread`) as dependencies of your own. The sections below take each step in turn.

### Configuration: CoreConfig

[`CoreConfig::from_env(env, service_name, crate_target)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/config/struct.CoreConfig.html) reads the variables every server shares, from `PUBLIC_URL` to `OTEL_EXPORTER_OTLP_ENDPOINT`. It returns `None` when it recorded any error in `env.errors`, so read the rest of your configuration from the same `EnvReader` before you report. `service_name` names the server in traces; `crate_target` is the tracing target `DEBUG` raises to debug.

It does not read `OAUTH_ADMIN_PASSWORD`, `AUDIT_LOG_PATH` or the `<PREFIX>_` variables: those belong to `app::Server`. The [configuration reference](configuration.md) says which variable is read where.

| Field | Type | Holds |
|---|---|---|
| `public_url` | `String` | `PUBLIC_URL` without a trailing slash |
| `public_host` | `String` | Its host, IPv6 without brackets |
| `oauth` | `OAuthSettings` | `public_url`, `signing_key` (`OAUTH_SIGNING_KEY`), `trusted_proxies` (`TRUSTED_PROXIES`) and `static_token` (`MCP_AUTH_TOKEN`) |
| `allowed_origins` | `Vec<String>` | `ALLOWED_ORIGINS` |
| `bind_addr` | `SocketAddr` | `BIND_ADDR`, default `0.0.0.0:8443` |
| `tls` | `TlsMode` | `Insecure`, `Files { cert, key }` or `SelfSigned { sans }`, chosen by `TlsMode::select` |
| `observability` | `ObservabilityConfig` | `LOG_LEVEL`, `LOG_FORMAT`, `DEBUG`, `DEBUG_UNSAFE_LOG_CONTENT`, `METRICS_ADDR`, whether `OTEL_EXPORTER_OTLP_ENDPOINT` is set, and the `service_name` and `crate_target` given to `from_env` |

`core.service_url("tools")` is `PUBLIC_URL/tools`. You can also fill the structs yourself: `CoreConfig`, `OAuthSettings` and `HttpSettings` have public fields. [`EnvReader`](https://docs.rs/mcp-server-core/latest/mcp_server_core/config/struct.EnvReader.html) works with any lookup function, `EnvReader::new(|name: &str| ...)`, and its methods are described under [Reading configuration with ServiceEnv](writing-a-service.md#reading-configuration-with-serviceenv).

`PUBLIC_URL` cannot have a path, and the OAuth metadata lives at `/.well-known/...` on its root. Serve the application at the root of its host: merge other routes into it rather than nesting it under a prefix.

### The authorization server: AuthState

[`AuthState::new(settings, services, verifier)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/struct.AuthState.html) returns an `Arc<AuthState>` shared by the OAuth routes and every bearer guard.

- `services` are the protected resources, each `PUBLIC_URL/<name>`. List every path you will guard, and `combined::COMBINED` (`mcp`) if you serve the combined endpoint. They also appear as `scopes_supported` in the metadata.
- `verifier` decides who may sign in: a [`PasswordVerifier`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/struct.PasswordVerifier.html), or your own [`CredentialVerifier`](sign-in.md#the-credentialverifier-trait).
- It panics if `settings.static_token` is set while the verifier carries credentials or accepts them as bearer tokens, or when the token has the shape of a JWT. Check those before calling it if the values come from outside.

It holds the token issuer, the credential sealer, the sign-in limiter, the replay guard, the verdict cache and the check runner; [Architecture](architecture.md#state-in-memory) lists what each keeps. Its public methods:

| Method | Returns |
|---|---|
| `sign_in_version()` | The `ver` every code, access and refresh token must carry |
| `subject_of(credential)` | Who signed in with `credential`: the verifier's own subject if it names one, else `owner` when credentials are not carried, else `key:` and 16 hex digits of a hash keyed by `OAUTH_SIGNING_KEY` |
| `settings()` | The `OAuthSettings` it was built with |
| `jwt()` | The [`Jwt`](https://docs.rs/mcp-server-core/latest/mcp_server_core/jwt/struct.Jwt.html) that issues and verifies tokens, for [minting one in a test](oauth.md#minting-a-token-in-a-test) |
| `sealer()` | The [`Sealer`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/struct.Sealer.html) for carried credentials |
| `verifier()` | The verifier |
| `services()`, `has_service(name)` | The protected resources' names |
| `resource(name)` | `PUBLIC_URL/<name>` |
| `resource_metadata_url(name)` | `PUBLIC_URL/.well-known/oauth-protected-resource/<name>` |
| `service_for_resource(url)` | The name whose resource URL is exactly `url` |

[`oauth_router(state)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/fn.oauth_router.html) returns the five OAuth routes listed on [Endpoints](endpoints.md); `build_app` merges it for you. [`require_bearer`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/fn.require_bearer.html) is the bearer guard, a middleware whose state is the `AuthState` and the path's name: `axum::middleware::from_fn_with_state((auth.clone(), "tools".to_string()), require_bearer)` guards a router as `build_app` does. [`client_ip(peer, headers, trusted)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/fn.client_ip.html) gives the address the limiter uses, which a rate-limiting layer of your own can use too.

### Services: mcp_service

[`service::mcp_service(ctx, factory)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/service/fn.mcp_service.html) serves any rmcp `ServerHandler` over Streamable HTTP and returns an `axum::Router` to mount at a path. `factory` is `Fn() -> Result<S, std::io::Error>` and runs once per MCP session, so it should only clone `Arc`s. Around the handler it adds:

- Host and Origin checks: the `PUBLIC_URL` host and `localhost`, `127.0.0.1` and `::1`; the `PUBLIC_URL` origin and `ALLOWED_ORIGINS` (see [Host and Origin checks](deployment.md#host-and-origin-checks));
- the 1 MiB limit on each request body rmcp reads, and the shutdown token from `ctx`, which ends open sessions;
- the policy wrapper, [`policy::Guarded`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/struct.Guarded.html), which reads a `ToolPolicy` from the request;
- sessions bound to the credential that opened them when the request carries a `Credential`, with the caps described under [MCP sessions](limits.md#mcp-sessions).

`ctx` is a [`ServiceContext`](writing-a-service.md#servicecontext-and-httpsettings): `HttpSettings::from_core(&core)` and the shutdown token you serve with.

### Read-only mode and the audit log

The policy wrapper looks for a [`ToolPolicy`](https://docs.rs/mcp-server-core/latest/mcp_server_core/policy/struct.ToolPolicy.html) in the request extensions. Attach one to each service's router with `axum::Extension`, as the example does:

| Field | Holds |
|---|---|
| `service` | The service name recorded in audit lines and named in the refusal |
| `endpoint` | The path recorded in audit lines, such as `/tools` |
| `read_only` | Hide and refuse the tools not marked `read_only_hint = true` |
| `audit` | An `Arc<AuditLog>`. `AuditLog::new(Some(path))` also appends JSON lines to `path`; share one `AuditLog` between services. |

Without a `ToolPolicy`, tools are served unchanged. `app::Server` builds each service's policy with [`Safety::policy(name)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Safety.html), which records the endpoint as `/<name>`. [Read-only mode and the audit log](read-only-and-audit.md#the-policy-module) describes the module.

### The combined endpoint

`app::Server` serves every service's tools together at `/mcp`. To do the same, give each handler its policy with `Guarded::with_policy`, recording `/mcp` as the endpoint, and combine them:

```rust
use mcp_server_core::axum::Router;
use mcp_server_core::combined::{COMBINED, Combined, DynHandler};
use mcp_server_core::policy::{AuditLog, Guarded, ToolPolicy};
use mcp_server_core::rmcp::ServerHandler;
use mcp_server_core::rmcp::model::Implementation;
use mcp_server_core::service::{ServiceContext, mcp_service};
use std::sync::Arc;

#[derive(Clone)]
struct Tools;

impl ServerHandler for Tools {}

/// `/mcp` over one service, `tools`: its tools appear as `tools_<tool>`.
fn combined(ctx: &ServiceContext, audit: Arc<AuditLog>) -> Router {
    mcp_service(ctx, move || {
        let policy = ToolPolicy {
            service: "tools".into(),
            endpoint: format!("/{COMBINED}"),
            read_only: false,
            audit: audit.clone(),
        };
        let handlers = vec![("tools", DynHandler::new(Guarded::with_policy(Tools, policy)))];
        Ok(Combined::new(Implementation::new("mcp-tools", "1.0.0"), handlers))
    })
}
```

Then include `COMBINED` in the names given to `AuthState::new` and pass `(COMBINED, combined(&ctx, audit))` to `build_app`. Service names must not contain `_`, which separates the service from the tool name; [Several services and /mcp](combined.md) describes the endpoint.

### The application: build_app

[`server::build_app(auth, services)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/server/fn.build_app.html) takes the `AuthState` and a list of `(name, router)` pairs and returns the application:

- `GET /healthz`, answering `ok`;
- the OAuth routes;
- each router nested at `/<name>` behind its own bearer guard;
- around all of these: `http_requests_total` metrics, the 1 MiB body limit, a `request` tracing span and `X-Content-Type-Options: nosniff`.

It panics with `service <name> is not registered with AuthState` when a name was not given to `AuthState::new`. It does not add `/favicon.ico`, the combined endpoint or HSTS. To send HSTS as `app::Server` does when it serves certificate files, add a layer:

```rust
use mcp_server_core::axum::Router;
use mcp_server_core::axum::http::{HeaderValue, header};
use mcp_server_core::axum::middleware::map_response;
use mcp_server_core::axum::response::Response;

fn with_hsts(app: Router) -> Router {
    app.layer(map_response(|mut res: Response| async move {
        res.headers_mut().insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        );
        res
    }))
}
```

Routes you add after `build_app` are outside its layers. Add [`server::http_metrics`](https://docs.rs/mcp-server-core/latest/mcp_server_core/server/fn.http_metrics.html) to them with `axum::middleware::from_fn(http_metrics)` to count them in `http_requests_total`.

### Serving: tls::serve

[`tls::serve(app, addr, mode, shutdown)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/tls/fn.serve.html) serves the application on `addr` until `shutdown` is cancelled, then gives open connections up to 10 seconds to finish. `mode` is a [`TlsMode`](https://docs.rs/mcp-server-core/latest/mcp_server_core/tls/enum.TlsMode.html):

| Mode | Serves |
|---|---|
| `TlsMode::Insecure` | Plain HTTP, with a warning in the log |
| `TlsMode::Files { cert, key }` | HTTPS with a PEM chain and key, checked for changes every 30 seconds and reloaded |
| `TlsMode::SelfSigned { sans }` | HTTPS with a certificate generated in memory for `sans`, its SHA-256 fingerprint logged |

`TlsMode::select(insecure, cert, key, public_host)` chooses as `CoreConfig` does, and `is_tls()` says whether the mode speaks TLS. [`generate_self_signed(sans)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/tls/fn.generate_self_signed.html) returns the certificate and key as PEM with the fingerprint, and [`tls::healthcheck(port, tls)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/tls/fn.healthcheck.html) is the probe behind `--healthcheck`. Call `install_crypto_provider()` before serving TLS. [TLS and deployment](deployment.md) explains the modes for operators.

### Logs, metrics and traces

[`observability::init(&config)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/fn.init.html) installs the global `tracing` subscriber, the Prometheus listener when `METRICS_ADDR` is set and the OTLP exporter when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Call it once and keep the returned guard for the life of the process: dropping it flushes traces. It fails if a global subscriber is already installed. If your application has its own, skip `init` and pass your filter through [`log_filter(level, caps, always_on)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/fn.log_filter.html), which caps the targets in `caps` at `info` and those in `QUIET_LOG_TARGETS` at `warn` (never above the level `LOG_LEVEL` sets for everything), and keeps the targets in `always_on` at `info`. Only `init` turns on `DEBUG` and `DEBUG_UNSAFE_LOG_CONTENT`: without it, `debug_enabled()` and `content_logging_enabled()` stay `false`. [Observability](observability.md) describes the logs and metrics themselves.

## Serving with your own listener

`tls::serve` is optional. Any server works if handlers can see the peer address as `ConnectInfo<SocketAddr>`: the bearer guard and the sign-in page use it for the sign-in limits, and without it every client counts as `0.0.0.0` and shares one allowance. With axum's own server, over plain HTTP:

```rust,no_run
# async fn run(app: mcp_server_core::axum::Router) -> std::io::Result<()> {
use mcp_server_core::axum;
use std::net::SocketAddr;

let shutdown = mcp_server_core::shutdown_signal();
let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
axum::serve(
    listener,
    app.into_make_service_with_connect_info::<SocketAddr>(),
)
.with_graceful_shutdown(shutdown.cancelled_owned())
.await
# }
```

Use the same token for `ServiceContext::shutdown`, so open MCP sessions end when the server stops. Behind a proxy, `TRUSTED_PROXIES` still decides whose `X-Forwarded-For` is believed; see [How X-Forwarded-For is read](deployment.md#how-x-forwarded-for-is-read).

## Re-exports

| Path | Crate | Version |
|---|---|---|
| `mcp_server_core::axum` | [axum](https://docs.rs/axum/0.8) | 0.8 |
| `mcp_server_core::rmcp` | [rmcp](https://docs.rs/rmcp/3.8) | 3.8, with the `server`, `macros` and `transport-streamable-http-server` features |

Both appear in this crate's API: `axum::Router` in `Service::router`, `build_app` and `wrap_router`; rmcp's `ServerHandler`, models and request context in `DynHandler`, `Guarded`, `Combined` and the `prompt` helpers. Use them through these paths, so your types are the ones the crate expects. A second copy of rmcp or axum at another version in your dependency tree gives types that do not match, and errors that are hard to read.

rmcp's macros (`#[tool_router]`, `#[tool]`, `#[tool_handler]` and the prompt macros) expand to paths that start with `rmcp::`. In a crate that does not depend on rmcp itself, bring the re-export into scope under that name, or the expansion fails with ``cannot find module or crate `rmcp` in this scope``:

```rust
use mcp_server_core::rmcp;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};

#[derive(Clone)]
struct Hello {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl Hello {
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
```

The same goes for schemars, which rmcp re-exports for tool arguments: `use mcp_server_core::rmcp::schemars::{self, JsonSchema};` lets `#[derive(JsonSchema)]` find it, as [`examples/notes.rs`](https://github.com/Trozz/mcp-server-core-rs/blob/main/examples/notes.rs) does. The repository's examples and this site's doctests compile without the first line only because they can see rmcp as a dependency of the crate itself.

One form does not work this way: `#[tool_router(server_handler)]`, which writes the `ServerHandler` impl for you, expands to absolute `::rmcp::` paths, and no `use` line satisfies those. Write the `#[tool_handler]` impl yourself, as above.

## Feature flags

| Feature | Default | Adds |
|---|---|---|
| `otel` | on | OpenTelemetry trace export over OTLP/HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` is set |
| `prometheus` | on | The Prometheus listener on `METRICS_ADDR` |

Without them the crate pulls in fewer dependencies. The public API is the same either way; setting the variable of a missing feature only logs a warning, as [Observability](observability.md#feature-flags) describes. To turn both off:

```toml
[dependencies]
mcp-server-core = { version = "0.3", default-features = false }
```

or to keep only metrics, add `features = ["prometheus"]`. CI builds and lints the crate with every feature and with none.

## Stability and semver

The crate follows [semantic versioning](https://semver.org/). Before 1.0, a minor version (0.1 to 0.2) may change the API, and a patch version (0.1.0 to 0.1.1) does not. Because rmcp and axum types are part of the API, a new minor version of either reaches you as a new minor version of this crate. [Releases and versioning](releases.md) has the details.

### non_exhaustive types

These types are `#[non_exhaustive]`, so later versions can add variants or fields without a breaking change:

| Type | Kind | What it means for you |
|---|---|---|
| `app::SignIn` | enum | A `match` on it needs a `_` arm. |
| `app::Loaded` | struct | Built only by `Server::load`; read its fields. |
| `caller::Caller` | struct | Build one with `Caller::new(subject, via)`, for your own middleware or tests. |
| `caller::Via` | enum | A `match` needs a `_` arm. |
| `credential::CredentialCheck` | enum | Return its variants freely; a `match` needs a `_` arm. |
| `credential::SealError` | enum | A `match` needs a `_` arm. |
| `guards::Ceiling` | enum | A `match` needs a `_` arm. |
| `guards::Refusal` | enum | A `match` needs a `_` arm. |
| `jwt::TokenKind` | enum | A `match` needs a `_` arm. |
| `jwt::JwtError` | enum | A `match` needs a `_` arm. |
| `tls::TlsMode` | enum | A `match` needs a `_` arm. |

Other structs with public fields, such as `ServiceContext`, `HttpSettings`, `OAuthSettings`, `ToolPolicy` and `jwt::Payload`, are built with struct literals, as on this page. A new field in one of them is a breaking change, so it comes only in a minor version. `Payload` implements `Default`: build it with `..Default::default()`, as the crate's own code does.

## API documentation

docs.rs builds the API documentation with every feature on:

- [mcp_server_core on docs.rs](https://docs.rs/mcp-server-core/latest/mcp_server_core/), the latest release;
- `https://docs.rs/mcp-server-core/<version>/mcp_server_core/` for a given release, such as [0.1.0](https://docs.rs/mcp-server-core/0.1.0/mcp_server_core/).

Run `cargo doc --open --all-features` in the repository for the documentation of the code you have checked out.
