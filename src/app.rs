//! [`Server`]: a whole MCP server binary from a list of services.
//!
//! ```no_run
//! # use mcp_server_core::service::{Service, ServiceEnv};
//! # use std::sync::Arc;
//! # fn weather(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { None }
//! # fn tides(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { None }
//! use mcp_server_core::app::{Server, SignIn};
//!
//! #[tokio::main]
//! async fn main() -> std::process::ExitCode {
//!     Server::new("mcp-sea", env!("CARGO_PKG_VERSION"))
//!         .env_prefix("SEA")
//!         .service("weather", weather)
//!         .service("tides", tides)
//!         .sign_in(SignIn::OwnerPassword)
//!         .docs_url("https://example.com/mcp-sea")
//!         .main()
//!         .await
//! }
//! ```
//!
//! [`Server::main`] handles `--version`, `--help` and `--healthcheck`, reads the configuration
//! (reporting every error at once), starts logging, mounts each service at `/<name>` and serves.
//!
//! Besides the [core variables](crate::config), a server reads, with `SEA` standing for its
//! [prefix](Server::env_prefix):
//!
//! | Variable | Default | |
//! |---|---|---|
//! | `SEA_SERVICES` | every service | Comma-separated services to run. Unselected services read no configuration. |
//! | `SEA_COMBINED` | `true` | Also serve every service's tools together at `/mcp`, as `<service>_<tool>`. |
//! | `SEA_READ_ONLY` | none | Comma-separated services (or `all`) whose write tools are hidden and refused. |
//! | `AUDIT_LOG_PATH` | none | Append an audit line (JSON) for every write tool call to this file. |
//! | `OAUTH_ADMIN_PASSWORD` | required with [`SignIn::OwnerPassword`] | The owner's password, at least 12 characters. |

use crate::combined::{COMBINED, Combined, DynHandler, prefixed_name};
use crate::config::{CoreConfig, EnvReader};
use crate::credential::{CredentialVerifier, PasswordVerifier};
use crate::oauth::AuthState;
use crate::policy::{AUDIT_TARGET, AuditLog, Guarded, ToolPolicy};
use crate::server::build_app;
use crate::service::{HttpSettings, Service, ServiceContext, ServiceEnv, ServiceFactory, icons};
use crate::{install_crypto_provider, observability, shutdown_signal, tls};
use rmcp::model::Implementation;
use secrecy::ExposeSecret;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Shortest `OAUTH_ADMIN_PASSWORD` accepted.
pub const MIN_ADMIN_PASSWORD_CHARS: usize = 12;
/// `OAUTH_ADMIN_PASSWORD`s shorter than this get a warning at startup.
pub const RECOMMENDED_ADMIN_PASSWORD_CHARS: usize = 15;
/// `MCP_AUTH_TOKEN`s shorter than this get a warning at startup.
pub const RECOMMENDED_STATIC_TOKEN_CHARS: usize = 32;

/// How people sign in, and what their tokens carry.
///
/// Deliberately small. For single sign-on, MFA or many named users, put an identity-aware
/// gateway (such as Cloudflare Access or oauth2-proxy) in front of `/authorize`; see
/// SECURITY.md.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum SignIn {
    /// One person, the owner, signs in with `OAUTH_ADMIN_PASSWORD`. Tools act with the server's
    /// own upstream configuration (say, an account's app password in the environment).
    /// `MCP_AUTH_TOKEN` may be set as well, for clients that cannot do OAuth.
    OwnerPassword,
    /// Each person signs in with their own credential for the upstream service, checked by the
    /// [`CredentialVerifier`] of the enabled service that has one
    /// ([`Service::credential_verifier`]; more than one is a configuration error, since each
    /// service's tools would receive a credential meant for another upstream). Tools find it as a
    /// [`Credential`](crate::credential::Credential) in the request extensions, so one server can
    /// serve many people. Clients may also send the credential itself as their bearer token.
    ServiceCredential,
    /// A verifier built from the environment by your function, which records any problems in
    /// `env.errors`.
    Custom(fn(&mut ServiceEnv) -> Option<Arc<dyn CredentialVerifier>>),
}

impl std::fmt::Debug for SignIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignIn::OwnerPassword => "OwnerPassword",
            SignIn::ServiceCredential => "ServiceCredential",
            SignIn::Custom(_) => "Custom(..)",
        })
    }
}

/// The read-only services and the audit log, applied to every service's tools.
#[derive(Clone)]
pub struct Safety {
    /// Services whose write tools are hidden and refused.
    pub read_only: Vec<&'static str>,
    /// Where write tool calls are recorded.
    pub audit: Arc<AuditLog>,
}

impl Safety {
    /// Whether `service` is read-only.
    pub fn is_read_only(&self, service: &str) -> bool {
        self.read_only.contains(&service)
    }

    /// The policy for `service` on its own endpoint `/<service>`.
    pub fn policy(&self, service: &str) -> ToolPolicy {
        ToolPolicy {
            service: service.to_string(),
            endpoint: format!("/{service}"),
            read_only: self.is_read_only(service),
            audit: self.audit.clone(),
        }
    }
}

/// A server's configuration, read and checked, with its services built.
#[non_exhaustive]
pub struct Loaded {
    /// The core settings.
    pub core: CoreConfig,
    /// The selected services, in registration order or in the order `<PREFIX>_SERVICES` names
    /// them.
    pub services: Vec<Arc<dyn Service>>,
    /// Read-only services and the audit log.
    pub safety: Safety,
    /// Whether every service's tools are also served together at `/mcp`.
    pub combined: bool,
    /// Who may sign in.
    pub verifier: Arc<dyn CredentialVerifier>,
    /// Settings that work but are weak, logged at startup.
    pub warnings: Vec<String>,
}

/// Builds an MCP server binary from services. See the [module documentation](self).
pub struct Server {
    name: &'static str,
    version: &'static str,
    crate_target: String,
    env_prefix: String,
    services: Vec<(&'static str, ServiceFactory)>,
    sign_in: SignIn,
    icon: Option<(&'static [u8], &'static str)>,
    docs_url: Option<&'static str>,
    wrap: Option<fn(axum::Router) -> axum::Router>,
}

/// Why `name` cannot be a service name, if it cannot.
fn invalid_service_name(name: &str) -> Option<&'static str> {
    if name == COMBINED {
        return Some("is reserved for the combined endpoint");
    }
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    (!ok).then_some("must be lowercase letters, digits and '-'")
}

impl Server {
    /// A server called `name` (used in logs, traces and the combined endpoint's `serverInfo`) at
    /// `version`. Its environment prefix defaults to `MCP` and its tracing target to `name` with
    /// `-` replaced by `_`; people sign in with the owner's password unless you choose otherwise.
    pub fn new(name: &'static str, version: &'static str) -> Self {
        Server {
            name,
            version,
            crate_target: name.replace('-', "_"),
            env_prefix: "MCP".into(),
            services: Vec::new(),
            sign_in: SignIn::OwnerPassword,
            icon: None,
            docs_url: None,
            wrap: None,
        }
    }

    /// The prefix of this server's own variables: `<PREFIX>_SERVICES`, `<PREFIX>_COMBINED` and
    /// `<PREFIX>_READ_ONLY`.
    pub fn env_prefix(mut self, prefix: &str) -> Self {
        self.env_prefix = prefix.trim_end_matches('_').to_ascii_uppercase();
        self
    }

    /// The tracing target prefix of your crates, which `DEBUG` raises to debug. With
    /// `mcp_weather`, `mcp_weather_api::client` is covered too.
    pub fn crate_target(mut self, target: &str) -> Self {
        self.crate_target = target.to_string();
        self
    }

    /// Registers a service, mounted at `/<name>`. Services are mounted, and their tools listed on
    /// `/mcp`, in registration order, or in the order `<PREFIX>_SERVICES` names them when it is
    /// set.
    ///
    /// # Panics
    ///
    /// If `name` is not lowercase letters, digits and `-`, is `mcp`, or is already registered.
    pub fn service(mut self, name: &'static str, factory: ServiceFactory) -> Self {
        if let Some(why) = invalid_service_name(name) {
            panic!("service name {name:?} {why}");
        }
        assert!(
            self.services.iter().all(|(n, _)| *n != name),
            "service {name:?} is registered twice"
        );
        self.services.push((name, factory));
        self
    }

    /// Registers several services; see [`service`](Self::service).
    pub fn services(self, services: &[(&'static str, ServiceFactory)]) -> Self {
        services
            .iter()
            .fold(self, |s, (name, factory)| s.service(name, *factory))
    }

    /// How people sign in. Defaults to [`SignIn::OwnerPassword`].
    pub fn sign_in(mut self, sign_in: SignIn) -> Self {
        self.sign_in = sign_in;
        self
    }

    /// The server's icon: a 128x128 PNG, served as `/favicon.ico` and in the combined endpoint's
    /// `serverInfo`, and an SVG.
    pub fn icon(mut self, png: &'static [u8], svg: &'static str) -> Self {
        self.icon = Some((png, svg));
        self
    }

    /// Wraps the whole application in your own layers, for example a request rate limiter or extra
    /// routes. They sit outside every built-in layer except the security headers. Routes added
    /// here, like `/favicon.ico`, are outside the body limit, the request metrics and the request
    /// span:
    ///
    /// ```
    /// # use mcp_server_core::app::Server;
    /// use mcp_server_core::axum::{Router, routing::get};
    ///
    /// fn extras(app: Router) -> Router {
    ///     app.route("/version", get(|| async { env!("CARGO_PKG_VERSION") }))
    /// }
    ///
    /// let server = Server::new("mcp-example", "1.0.0").wrap_router(extras);
    /// ```
    pub fn wrap_router(mut self, wrap: fn(axum::Router) -> axum::Router) -> Self {
        self.wrap = Some(wrap);
        self
    }

    /// Where the configuration is documented, for `--help`.
    pub fn docs_url(mut self, url: &'static str) -> Self {
        self.docs_url = Some(url);
        self
    }

    /// The server's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The server's version.
    pub fn version(&self) -> &'static str {
        self.version
    }

    /// The registered services' names, in order.
    pub fn registered(&self) -> Vec<&'static str> {
        self.services.iter().map(|(n, _)| *n).collect()
    }

    /// `<PREFIX>_<suffix>`.
    pub fn var(&self, suffix: &str) -> String {
        format!("{}_{suffix}", self.env_prefix)
    }

    fn known(&self) -> String {
        self.registered().join(", ")
    }

    /// Resolves `<PREFIX>_SERVICES` (comma list, unset means every registered service).
    fn select(&self, raw: Option<&str>) -> Result<Vec<(&'static str, ServiceFactory)>, String> {
        let Some(raw) = raw else {
            return Ok(self.services.clone());
        };
        let var = self.var("SERVICES");
        let mut selected: Vec<(&'static str, ServiceFactory)> = Vec::new();
        for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let Some(entry) = self.services.iter().find(|(n, _)| *n == name) else {
                return Err(format!(
                    "{var} contains an unknown service: {name} (known: {})",
                    self.known()
                ));
            };
            if !selected.iter().any(|(n, _)| *n == name) {
                selected.push(*entry);
            }
        }
        if selected.is_empty() {
            return Err(format!(
                "{var} must name at least one service (known: {})",
                self.known()
            ));
        }
        Ok(selected)
    }

    /// Resolves `<PREFIX>_READ_ONLY` (comma list or `all`, unset or empty means none). Names
    /// that are registered but not selected are accepted and have no effect.
    fn read_only(&self, raw: Option<&str>) -> Result<Vec<&'static str>, String> {
        let names = raw
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let mut out: Vec<&'static str> = Vec::new();
        for name in names {
            if name == "all" {
                return Ok(self.registered());
            }
            let Some((known, _)) = self.services.iter().find(|(n, _)| *n == name) else {
                return Err(format!(
                    "{} contains an unknown service: {name} (known: all, {})",
                    self.var("READ_ONLY"),
                    self.known()
                ));
            };
            if !out.contains(known) {
                out.push(known);
            }
        }
        Ok(out)
    }

    /// Reads the configuration and builds every selected service. Every problem is recorded in
    /// `env.errors` (each once); `None` means the server cannot start. Unselected services never
    /// read their configuration.
    pub fn load(&self, env: &mut ServiceEnv) -> Option<Loaded> {
        let core = CoreConfig::from_env(env, self.name, &self.crate_target);
        let mut verifier: Option<Arc<dyn CredentialVerifier>> = match self.sign_in {
            SignIn::OwnerPassword => owner_password(env),
            SignIn::ServiceCredential => None,
            SignIn::Custom(build) => build(env),
        };
        let selected = match self.select(env.optional(&self.var("SERVICES")).as_deref()) {
            Ok(s) => s,
            Err(e) => {
                env.errors.push(e);
                Vec::new()
            }
        };
        let read_only = match self.read_only(env.optional(&self.var("READ_ONLY")).as_deref()) {
            Ok(r) => r,
            Err(e) => {
                env.errors.push(e);
                Vec::new()
            }
        };
        let audit_path = env.optional("AUDIT_LOG_PATH").map(PathBuf::from);
        let combined = env.bool(&self.var("COMBINED"), true);
        let mut services: Vec<Arc<dyn Service>> = Vec::new();
        for (name, factory) in selected {
            if let Some(s) = factory(env) {
                if s.name() != name {
                    env.errors.push(format!(
                        "the service registered as {name} is named {}",
                        s.name()
                    ));
                }
                services.push(s);
            }
        }
        if matches!(self.sign_in, SignIn::ServiceCredential) {
            let defining: Vec<(&str, Arc<dyn CredentialVerifier>)> = services
                .iter()
                .filter_map(|s| s.credential_verifier().map(|v| (s.name(), v)))
                .collect();
            match defining.as_slice() {
                [] if !services.is_empty() => env
                    .errors
                    .push("no enabled service defines how people sign in".to_string()),
                [] => {}
                [(_, v)] => verifier = Some(v.clone()),
                several => env.errors.push(format!(
                    "more than one enabled service defines how people sign in ({}): enable one of them",
                    several.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                )),
            }
        }
        let mut warnings = Vec::new();
        if let Some(token) = core.as_ref().and_then(|c| c.oauth.static_token.as_ref()) {
            let token = token.expose_secret();
            let problems: Vec<String> = verifier
                .as_ref()
                .and_then(|v| crate::oauth::static_token_verifier_problem(v.as_ref()))
                .into_iter()
                .chain(crate::oauth::static_token_shape_problem(token))
                .collect();
            if !problems.is_empty() {
                env.errors.extend(problems);
            } else if token.chars().count() < RECOMMENDED_STATIC_TOKEN_CHARS {
                warnings.push(format!(
                    "MCP_AUTH_TOKEN is shorter than {RECOMMENDED_STATIC_TOKEN_CHARS} characters: use a long random value"
                ));
            }
        }
        if matches!(self.sign_in, SignIn::OwnerPassword)
            && let Some(p) = env.optional("OAUTH_ADMIN_PASSWORD")
            && p.chars().count() < RECOMMENDED_ADMIN_PASSWORD_CHARS
            && p.chars().count() >= MIN_ADMIN_PASSWORD_CHARS
        {
            warnings.push(format!(
                "OAUTH_ADMIN_PASSWORD is shorter than {RECOMMENDED_ADMIN_PASSWORD_CHARS} characters: a longer passphrase is much harder to guess"
            ));
        }
        // Services may share variables: report each error once.
        let mut seen = std::collections::HashSet::new();
        env.errors.retain(|e| seen.insert(e.clone()));
        if !env.errors.is_empty() {
            return None;
        }
        Some(Loaded {
            core: core?,
            services,
            safety: Safety {
                read_only,
                audit: Arc::new(AuditLog::new(audit_path)),
            },
            combined,
            verifier: verifier?,
            warnings,
        })
    }

    /// The combined endpoint's `serverInfo`: this server's name, version and icon.
    fn combined_info(&self) -> Implementation {
        let info = Implementation::new(self.name, self.version);
        match self.icon {
            Some((png, svg)) => info.with_icons(icons(png, svg)),
            None => info,
        }
    }

    /// The combined endpoint: every service's tools as `<service>_<tool>`, each service under its
    /// own read-only rule and audit log, recorded with endpoint `/mcp`.
    fn combined_router(&self, loaded: &Loaded, ctx: &ServiceContext) -> axum::Router {
        let parts: Vec<(Arc<dyn Service>, ToolPolicy)> = loaded
            .services
            .iter()
            .map(|s| {
                let policy = ToolPolicy {
                    endpoint: format!("/{COMBINED}"),
                    ..loaded.safety.policy(s.name())
                };
                (s.clone(), policy)
            })
            .collect();
        let info = self.combined_info();
        crate::service::mcp_service(ctx, move || {
            let handlers = parts
                .iter()
                .map(|(s, policy)| {
                    let guarded = Guarded::with_policy(s.handler(), policy.clone());
                    (s.name(), DynHandler::new(guarded))
                })
                .collect();
            Ok(Combined::new(info.clone(), handlers))
        })
    }

    /// The whole HTTP application: `/healthz`, the OAuth routes, each service at `/<name>` (its
    /// own OAuth protected resource, under its read-only rule and audit log), `/favicon.ico` when
    /// there is an icon and, when `loaded.combined`, every service's tools together at `/mcp`,
    /// passed through [`wrap_router`](Self::wrap_router). Every response, the wrapped routes'
    /// too, sends `X-Content-Type-Options: nosniff`, and `Strict-Transport-Security` when the
    /// server serves certificate files (`TLS_CERT_PATH`).
    pub fn router(&self, loaded: &Loaded, ctx: &ServiceContext) -> axum::Router {
        let services = &loaded.services;
        assert!(
            services.iter().all(|s| s.name() != COMBINED),
            "{COMBINED} is reserved for the combined endpoint"
        );
        let combined = loaded.combined && !services.is_empty();
        let mut names: Vec<&str> = services.iter().map(|s| s.name()).collect();
        if combined {
            names.push(COMBINED);
        }
        let auth = AuthState::new(loaded.core.oauth.clone(), &names, loaded.verifier.clone());
        let mut routers: Vec<(&'static str, axum::Router)> = services
            .iter()
            .map(|s| {
                let policy = axum::Extension(loaded.safety.policy(s.name()));
                (s.name(), s.clone().router(ctx).layer(policy))
            })
            .collect();
        if combined {
            routers.push((COMBINED, self.combined_router(loaded, ctx)));
        }
        let app = build_app(auth, routers);
        let app = match self.icon {
            Some((png, _)) => app.route(
                "/favicon.ico",
                axum::routing::get(move || async move {
                    ([(axum::http::header::CONTENT_TYPE, "image/png")], png)
                }),
            ),
            None => app,
        };
        let app = match self.wrap {
            Some(wrap) => wrap(app),
            None => app,
        };
        // HSTS only with certificate files: a self-signed certificate means local use or a proxy
        // in front, and the proxy sets its own policy.
        let hsts = matches!(loaded.core.tls, tls::TlsMode::Files { .. });
        app.layer(axum::middleware::map_response(
            move |mut res: axum::response::Response| async move {
                let headers = res.headers_mut();
                headers.insert(
                    axum::http::header::X_CONTENT_TYPE_OPTIONS,
                    axum::http::HeaderValue::from_static("nosniff"),
                );
                if hsts {
                    headers.insert(
                        axum::http::header::STRICT_TRANSPORT_SECURITY,
                        axum::http::HeaderValue::from_static("max-age=31536000"),
                    );
                }
                res
            },
        ))
    }

    /// Every service's log caps.
    pub fn log_caps(services: &[Arc<dyn Service>]) -> Vec<&'static str> {
        services
            .iter()
            .flat_map(|s| s.log_caps().iter().copied())
            .collect()
    }

    /// The tool names `/mcp` offers, in order.
    pub fn combined_tool_names(services: &[Arc<dyn Service>]) -> Vec<String> {
        services
            .iter()
            .flat_map(|s| {
                s.tool_names()
                    .into_iter()
                    .map(|t| prefixed_name(s.name(), &t))
            })
            .collect()
    }

    /// Starts logging and serves `loaded` until Ctrl-C or SIGTERM.
    pub async fn run(&self, loaded: Loaded) -> anyhow::Result<()> {
        let mut obs = loaded.core.observability.clone();
        obs.log_level = observability::log_filter(
            &obs.log_level,
            &Self::log_caps(&loaded.services),
            &[AUDIT_TARGET],
        );
        let _guard = observability::init(&obs)?;
        tracing::info!(version = self.version, "starting {}", self.name);
        for w in &loaded.warnings {
            tracing::warn!("{w}");
        }
        for s in &loaded.services {
            tracing::info!(
                service = s.name(),
                url = loaded.core.service_url(s.name()),
                read_only = loaded.safety.is_read_only(s.name()),
                tools = ?s.tool_names(),
                "service enabled"
            );
        }
        if loaded.combined && !loaded.services.is_empty() {
            tracing::info!(
                url = loaded.core.service_url(COMBINED),
                tools = Self::combined_tool_names(&loaded.services).len(),
                "combined endpoint enabled"
            );
        }
        let shutdown = shutdown_signal();
        let ctx = ServiceContext {
            http: HttpSettings::from_core(&loaded.core),
            shutdown: shutdown.clone(),
        };
        let app = self.router(&loaded, &ctx);
        tracing::info!(addr = %loaded.core.bind_addr, "listening");
        tls::serve(
            app,
            loaded.core.bind_addr,
            loaded.core.tls.clone(),
            shutdown,
        )
        .await
    }

    fn usage(&self) -> String {
        let docs = match self.docs_url {
            Some(url) => format!("; see {url}"),
            None => ".".to_string(),
        };
        format!(
            "usage: {} [--version | --healthcheck]\nAll configuration is read from environment variables{docs}",
            self.name
        )
    }

    /// Everything `main` does: handles `--version`, `--help` and `--healthcheck`, reads the
    /// configuration from the process environment (printing every error), then [`run`](Self::run)s.
    pub async fn main(self) -> ExitCode {
        let arg = std::env::args().nth(1);
        match arg.as_deref() {
            Some("--version" | "-V") => {
                println!("{} {}", self.name, self.version);
                return ExitCode::SUCCESS;
            }
            Some("--healthcheck") => return healthcheck().await,
            Some("--help" | "-h") => {
                println!("{}", self.usage());
                return ExitCode::SUCCESS;
            }
            Some(other) => {
                eprintln!("unknown argument: {other}\n{}", self.usage());
                return ExitCode::from(2);
            }
            None => {}
        }
        install_crypto_provider();
        let mut env: ServiceEnv = EnvReader::new(Box::new(|k: &str| std::env::var(k).ok()));
        let Some(loaded) = self.load(&mut env) else {
            for e in &env.errors {
                eprintln!("configuration error: {e}");
            }
            return ExitCode::FAILURE;
        };
        match self.run(loaded).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "fatal");
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        }
    }
}

/// Reads `OAUTH_ADMIN_PASSWORD` for [`SignIn::OwnerPassword`].
fn owner_password(env: &mut ServiceEnv) -> Option<Arc<dyn CredentialVerifier>> {
    let password = env.secret_required("OAUTH_ADMIN_PASSWORD")?;
    let p = password.expose_secret();
    if p.chars().count() < MIN_ADMIN_PASSWORD_CHARS || p.trim().is_empty() {
        env.errors.push(format!(
            "OAUTH_ADMIN_PASSWORD must be at least {MIN_ADMIN_PASSWORD_CHARS} characters, not only spaces"
        ));
        return None;
    }
    Some(Arc::new(PasswordVerifier::new(password)))
}

/// The container healthcheck: `GET /healthz` on 127.0.0.1 at the `BIND_ADDR` port.
pub async fn healthcheck() -> ExitCode {
    install_crypto_provider();
    let mut env = EnvReader::from_process();
    let addr = env.parse("BIND_ADDR", SocketAddr::from(([0, 0, 0, 0], 8443)));
    let insecure = env.bool("INSECURE_HTTP", false);
    if tls::healthcheck(addr.port(), !insecure).await {
        return ExitCode::SUCCESS;
    }
    eprintln!("healthcheck failed");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> ServiceEnv {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        ServiceEnv::new(Box::new(move |k: &str| map.get(k).cloned()))
    }

    const CORE: &[(&str, &str)] = &[
        ("PUBLIC_URL", "https://mcp.example.com"),
        ("OAUTH_SIGNING_KEY", "0123456789abcdef0123456789abcdef"),
        ("OAUTH_ADMIN_PASSWORD", "a long password"),
    ];

    fn with_core(extra: &[(&str, &str)]) -> ServiceEnv {
        let mut all = CORE.to_vec();
        all.extend_from_slice(extra);
        env(&all)
    }

    #[derive(Clone)]
    struct Nothing;
    impl rmcp::ServerHandler for Nothing {}

    struct Named(&'static str);
    impl Service for Named {
        fn name(&self) -> &'static str {
            self.0
        }
        fn handler(&self) -> DynHandler {
            DynHandler::new(Nothing)
        }
    }

    fn alpha(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
        Some(Arc::new(Named("alpha")))
    }

    fn needy(env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
        env.required("NEEDY_TOKEN");
        None
    }

    /// Two services reading the same variable.
    fn sharing(env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
        env.required("SHARED_TOKEN");
        None
    }

    fn misnamed(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
        Some(Arc::new(Named("other")))
    }

    fn two() -> Server {
        Server::new("mcp-test", "1.0.0")
            .env_prefix("TEST")
            .service("alpha", alpha)
            .service("needy", needy)
    }

    fn names(v: &[(&'static str, ServiceFactory)]) -> Vec<&'static str> {
        v.iter().map(|(n, _)| *n).collect()
    }

    #[test]
    fn defaults() {
        let s = Server::new("mcp-test", "1.0.0");
        assert_eq!(s.crate_target, "mcp_test");
        assert_eq!(s.var("SERVICES"), "MCP_SERVICES");
        assert_eq!(s.env_prefix("my_app_").var("COMBINED"), "MY_APP_COMBINED");
    }

    #[test]
    fn unset_selects_every_registered_service() {
        assert_eq!(names(&two().select(None).unwrap()), vec!["alpha", "needy"]);
    }

    #[test]
    fn explicit_selection_is_trimmed_and_deduplicated() {
        assert_eq!(
            names(&two().select(Some(" needy , alpha,needy")).unwrap()),
            vec!["needy", "alpha"]
        );
    }

    #[test]
    fn unknown_or_empty_selection_is_an_error() {
        let e = two().select(Some("alpha,beta")).unwrap_err();
        assert_eq!(
            e,
            "TEST_SERVICES contains an unknown service: beta (known: alpha, needy)"
        );
        let e = two().select(Some(" , ")).unwrap_err();
        assert!(
            e.starts_with("TEST_SERVICES must name at least one service"),
            "{e}"
        );
        let e = two().select(Some(COMBINED)).unwrap_err();
        assert!(e.contains("unknown service: mcp"), "{e}");
    }

    #[test]
    fn unselected_services_do_not_read_config() {
        let mut e = with_core(&[("TEST_SERVICES", "alpha")]);
        let loaded = two().load(&mut e).expect("loads");
        assert!(e.errors.is_empty(), "{:?}", e.errors);
        assert_eq!(loaded.services.len(), 1);
        assert_eq!(loaded.services[0].name(), "alpha");

        let mut e = with_core(&[]);
        assert!(two().load(&mut e).is_none());
        assert_eq!(e.errors, vec!["NEEDY_TOKEN is required".to_string()]);
    }

    #[test]
    fn core_and_service_errors_are_reported_together() {
        let mut e = env(&[("PUBLIC_URL", "ftp://x"), ("OAUTH_ADMIN_PASSWORD", "short")]);
        assert!(two().load(&mut e).is_none());
        let joined = e.errors.join("\n");
        assert!(joined.contains("PUBLIC_URL"), "{joined}");
        assert!(joined.contains("OAUTH_SIGNING_KEY is required"), "{joined}");
        assert!(
            joined.contains("OAUTH_ADMIN_PASSWORD must be at least 12 characters"),
            "{joined}"
        );
        assert!(joined.contains("NEEDY_TOKEN is required"), "{joined}");
        assert!(!joined.contains("short"), "secret leaked: {joined}");
    }

    #[test]
    fn the_owner_password_is_required_and_twelve_characters_is_enough() {
        let mut e = env(&CORE[..2]);
        assert!(two().load(&mut e).is_none());
        assert!(
            e.errors
                .contains(&"OAUTH_ADMIN_PASSWORD is required".to_string()),
            "{:?}",
            e.errors
        );
        let mut e = with_core(&[
            ("TEST_SERVICES", "alpha"),
            ("OAUTH_ADMIN_PASSWORD", "twelve chars"),
        ]);
        let loaded = two().load(&mut e).expect("loads");
        assert!(!loaded.verifier.carried());
    }

    #[test]
    fn shared_variable_errors_are_reported_once() {
        let s = Server::new("mcp-test", "1")
            .service("one", sharing)
            .service("two", sharing);
        let mut e = with_core(&[]);
        assert!(s.load(&mut e).is_none());
        assert_eq!(e.errors, vec!["SHARED_TOKEN is required".to_string()]);
    }

    #[test]
    fn a_service_must_have_the_name_it_was_registered_with() {
        let s = Server::new("mcp-test", "1").service("alpha", misnamed);
        let mut e = with_core(&[]);
        assert!(s.load(&mut e).is_none());
        assert_eq!(
            e.errors,
            vec!["the service registered as alpha is named other".to_string()]
        );
    }

    #[test]
    #[should_panic(expected = "is reserved for the combined endpoint")]
    fn mcp_is_not_a_service_name() {
        let _ = Server::new("mcp-test", "1").service("mcp", alpha);
    }

    #[test]
    #[should_panic(expected = "must be lowercase letters, digits and '-'")]
    fn service_names_are_path_segments() {
        let _ = Server::new("mcp-test", "1").service("my_service", alpha);
    }

    #[test]
    #[should_panic(expected = "registered twice")]
    fn service_names_are_unique() {
        let _ = Server::new("mcp-test", "1")
            .service("alpha", alpha)
            .service("alpha", alpha);
    }

    #[test]
    fn the_combined_endpoint_is_on_unless_turned_off() {
        let s = Server::new("mcp-test", "1")
            .env_prefix("TEST")
            .service("alpha", alpha);
        let mut e = with_core(&[]);
        assert!(s.load(&mut e).expect("loads").combined);
        let mut e = with_core(&[("TEST_COMBINED", "false")]);
        assert!(!s.load(&mut e).expect("loads").combined);
        let mut e = with_core(&[("TEST_COMBINED", "maybe")]);
        assert!(s.load(&mut e).is_none());
        assert_eq!(e.errors.len(), 1, "{:?}", e.errors);
        assert!(e.errors[0].contains("TEST_COMBINED"), "{:?}", e.errors);
    }

    #[test]
    fn read_only_accepts_names_all_and_nothing() {
        let s = two();
        assert_eq!(s.read_only(None).unwrap(), Vec::<&str>::new());
        assert_eq!(s.read_only(Some(" , ")).unwrap(), Vec::<&str>::new());
        assert_eq!(
            s.read_only(Some(" needy,alpha,needy")).unwrap(),
            vec!["needy", "alpha"]
        );
        assert_eq!(
            s.read_only(Some("alpha,all")).unwrap(),
            vec!["alpha", "needy"]
        );
        assert_eq!(
            s.read_only(Some("alpha,beta")).unwrap_err(),
            "TEST_READ_ONLY contains an unknown service: beta (known: all, alpha, needy)"
        );
    }

    #[test]
    fn read_only_names_need_not_be_selected() {
        let mut e = with_core(&[("TEST_SERVICES", "alpha"), ("TEST_READ_ONLY", "needy")]);
        let loaded = two().load(&mut e).expect("loads");
        assert!(loaded.safety.is_read_only("needy"));
        assert!(!loaded.safety.is_read_only("alpha"));
        assert!(!loaded.safety.policy("alpha").read_only);
        assert_eq!(loaded.safety.policy("alpha").endpoint, "/alpha");
    }

    struct Keyed;
    impl Service for Keyed {
        fn name(&self) -> &'static str {
            "keyed"
        }
        fn handler(&self) -> DynHandler {
            DynHandler::new(Nothing)
        }
        fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
            struct Key;
            impl CredentialVerifier for Key {
                fn label(&self) -> &str {
                    "example key"
                }
                fn check<'a>(&'a self, _: &'a str) -> crate::credential::CheckFuture<'a> {
                    Box::pin(async { crate::credential::CredentialCheck::Valid })
                }
            }
            Some(Arc::new(Key))
        }
    }

    fn keyed(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
        Some(Arc::new(Keyed))
    }

    #[test]
    fn service_credentials_come_from_the_one_service_that_defines_them() {
        let s = Server::new("mcp-test", "1")
            .service("alpha", alpha)
            .service("keyed", keyed)
            .sign_in(SignIn::ServiceCredential);
        let mut e = env(&CORE[..2]);
        let loaded = s.load(&mut e).expect("no admin password needed");
        assert_eq!(loaded.verifier.label(), "example key");
        assert!(loaded.verifier.carried());

        let s = Server::new("mcp-test", "1")
            .service("alpha", alpha)
            .sign_in(SignIn::ServiceCredential);
        let mut e = env(&CORE[..2]);
        assert!(s.load(&mut e).is_none());
        assert_eq!(
            e.errors,
            vec!["no enabled service defines how people sign in".to_string()]
        );
    }

    #[test]
    fn a_static_token_needs_sign_in_that_carries_no_credential() {
        let s = Server::new("mcp-test", "1")
            .service("keyed", keyed)
            .sign_in(SignIn::ServiceCredential);
        let mut e = with_core(&[("MCP_AUTH_TOKEN", "static-token")]);
        assert!(s.load(&mut e).is_none());
        assert_eq!(
            e.errors,
            vec![
                "MCP_AUTH_TOKEN cannot be used when people sign in with their own example key"
                    .to_string()
            ]
        );
        let s = Server::new("mcp-test", "1").service("alpha", alpha);
        let mut e = with_core(&[("MCP_AUTH_TOKEN", "static-token")]);
        assert!(s.load(&mut e).is_some(), "{:?}", e.errors);
    }

    #[test]
    fn two_services_that_both_define_sign_in_are_refused() {
        fn keyed_too(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
            struct KeyedToo;
            impl Service for KeyedToo {
                fn name(&self) -> &'static str {
                    "keyed-too"
                }
                fn handler(&self) -> DynHandler {
                    DynHandler::new(Nothing)
                }
                fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
                    Keyed.credential_verifier()
                }
            }
            Some(Arc::new(KeyedToo))
        }
        let s = Server::new("mcp-test", "1")
            .service("keyed", keyed)
            .service("keyed-too", keyed_too)
            .sign_in(SignIn::ServiceCredential);
        let mut e = env(&CORE[..2]);
        assert!(s.load(&mut e).is_none());
        assert_eq!(
            e.errors,
            vec![
                "more than one enabled service defines how people sign in (keyed, keyed-too): enable one of them"
                    .to_string()
            ]
        );
        let mut e = env(&[CORE[0], CORE[1], ("MCP_SERVICES", "keyed-too")]);
        assert!(s.load(&mut e).is_some(), "{:?}", e.errors);
    }

    #[test]
    fn a_password_of_spaces_is_refused_and_a_short_one_warned_about() {
        let s = Server::new("mcp-test", "1").service("alpha", alpha);
        let mut e = with_core(&[("OAUTH_ADMIN_PASSWORD", "              ")]);
        assert!(s.load(&mut e).is_none());
        assert!(e.errors[0].contains("not only spaces"), "{:?}", e.errors);
        let mut e = with_core(&[("OAUTH_ADMIN_PASSWORD", "twelve chars")]);
        let loaded = s.load(&mut e).expect("loads");
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("shorter than 15"));
        let mut e = with_core(&[("OAUTH_ADMIN_PASSWORD", "a much longer passphrase")]);
        assert!(s.load(&mut e).expect("loads").warnings.is_empty());
    }

    #[test]
    fn a_static_token_shaped_like_a_jwt_or_short_is_reported() {
        let s = Server::new("mcp-test", "1").service("alpha", alpha);
        let mut e = with_core(&[("MCP_AUTH_TOKEN", "aaa.bbb.ccc")]);
        assert!(s.load(&mut e).is_none());
        assert!(e.errors[0].contains("shape of a JWT"), "{:?}", e.errors);
        // Reported with the other errors, not only once they are fixed.
        let mut e = with_core(&[
            ("OAUTH_ADMIN_PASSWORD", "short"),
            ("MCP_AUTH_TOKEN", "aaa.bbb.ccc"),
        ]);
        assert!(s.load(&mut e).is_none());
        assert!(e.errors.iter().any(|x| x.contains("shape of a JWT")));
        assert!(e.errors.iter().any(|x| x.contains("OAUTH_ADMIN_PASSWORD")));
        let mut e = with_core(&[("MCP_AUTH_TOKEN", "short-token")]);
        let loaded = s.load(&mut e).expect("loads");
        assert!(
            loaded.warnings.iter().any(|w| w.contains("MCP_AUTH_TOKEN")),
            "{:?}",
            loaded.warnings
        );
    }

    #[test]
    fn custom_sign_in_reads_its_own_configuration() {
        fn custom(env: &mut ServiceEnv) -> Option<Arc<dyn CredentialVerifier>> {
            let p = env.secret_required("CUSTOM_PASSWORD")?;
            Some(Arc::new(PasswordVerifier::new(p)))
        }
        let s = Server::new("mcp-test", "1")
            .service("alpha", alpha)
            .sign_in(SignIn::Custom(custom));
        let mut e = env(&CORE[..2]);
        assert!(s.load(&mut e).is_none());
        assert_eq!(e.errors, vec!["CUSTOM_PASSWORD is required".to_string()]);
    }

    #[test]
    fn usage_names_the_docs() {
        let s = Server::new("mcp-test", "1");
        assert!(s.usage().ends_with("environment variables."));
        let s = s.docs_url("https://example.com/docs");
        assert!(s.usage().ends_with("; see https://example.com/docs"));
    }

    #[test]
    fn log_caps_are_the_services_own() {
        assert!(Server::log_caps(&[]).is_empty());
    }
}
