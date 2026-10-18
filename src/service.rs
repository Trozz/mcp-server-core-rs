//! Services: the MCP servers this crate hosts, each mounted at `/<name>`.
//!
//! A [`Service`] is a name and an rmcp handler. [`mcp_service`] serves any rmcp handler over
//! Streamable HTTP with the protections this crate adds; the default [`Service::router`] uses it.

use crate::combined::DynHandler;
use crate::config::{CoreConfig, EnvReader};
use crate::credential::{Credential, CredentialVerifier};
use crate::policy::Guarded;
use crate::server::BODY_LIMIT;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rmcp::ServerHandler;
use rmcp::model::Icon;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Tracing targets kept at warn whatever `LOG_LEVEL` says: rmcp's streamable HTTP server logs
/// MCP session ids (at info and in error text), and its transport workers carry them in a trace
/// span name, while session ids should stay out of logs and traces.
pub const QUIET_LOG_TARGETS: &[&str] = &[
    "rmcp::transport::streamable_http_server",
    "rmcp::transport::worker",
];

/// The environment reader every service factory receives.
pub type ServiceEnv = EnvReader<Box<dyn Fn(&str) -> Option<String>>>;

/// Reads a service's configuration and builds it. Errors go to `env.errors`, so every problem is
/// reported at once; `None` means the service cannot start.
pub type ServiceFactory = fn(&mut ServiceEnv) -> Option<Arc<dyn Service>>;

/// What the MCP HTTP layer needs from the core configuration.
#[derive(Debug, Clone)]
pub struct HttpSettings {
    /// External base URL without a trailing slash, e.g. `https://mcp.example.com`.
    pub public_url: String,
    /// Host part of `public_url`.
    pub public_host: String,
    /// Extra allowed browser origins (`ALLOWED_ORIGINS`), passed to rmcp as given.
    pub allowed_origins: Vec<String>,
}

impl HttpSettings {
    /// The settings from a loaded [`CoreConfig`].
    pub fn from_core(core: &CoreConfig) -> Self {
        Self {
            public_url: core.public_url.clone(),
            public_host: core.public_host.clone(),
            allowed_origins: core.allowed_origins.clone(),
        }
    }
}

/// What a service gets when it is mounted.
#[derive(Debug, Clone)]
pub struct ServiceContext {
    /// Host, origin and URL settings for [`mcp_service`].
    pub http: HttpSettings,
    /// Cancelled when the server shuts down.
    pub shutdown: CancellationToken,
}

/// One MCP service (say `weather`), mounted by the server at `/<name>`.
///
/// Only [`name`](Self::name) and [`handler`](Self::handler) are required:
///
/// ```
/// use mcp_server_core::combined::DynHandler;
/// use mcp_server_core::rmcp::ServerHandler;
/// use mcp_server_core::service::Service;
///
/// #[derive(Clone)]
/// struct Tools;
/// impl ServerHandler for Tools {}
///
/// struct Weather;
///
/// impl Service for Weather {
///     fn name(&self) -> &'static str {
///         "weather"
///     }
///     fn handler(&self) -> DynHandler {
///         DynHandler::new(Tools)
///     }
/// }
/// ```
pub trait Service: Send + Sync + 'static {
    /// Path segment, OAuth resource suffix and scope: lowercase letters, digits and `-`, never
    /// `mcp` (the combined endpoint) and never containing `_` (the combined endpoint's prefix
    /// separator).
    fn name(&self) -> &'static str;
    /// This service's MCP handler. It serves the service's tools and prompts on the combined
    /// `/mcp` endpoint and, through the default [`router`](Self::router), at `/<name>`. Called once per MCP
    /// session: keep it cheap, cloning `Arc`s.
    fn handler(&self) -> DynHandler;
    /// The Streamable HTTP service mounted at `/<name>`. The default serves
    /// [`handler`](Self::handler), which carries tools and prompts; override it with
    /// [`mcp_service`] and your concrete handler to serve resources too, or to do work when the
    /// service is mounted (logging its settings, warming a cache).
    fn router(self: Arc<Self>, ctx: &ServiceContext) -> axum::Router {
        mcp_service(ctx, move || Ok(self.handler()))
    }
    /// Tool names, logged at startup. Defaults to none.
    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }
    /// Tracing targets (usually dependencies) to cap at info whatever `LOG_LEVEL` says, because
    /// their debug or trace output can leak secrets.
    fn log_caps(&self) -> &'static [&'static str] {
        &[]
    }
    /// How people sign in to use this service with their own credential, for
    /// [`SignIn::ServiceCredential`](crate::app::SignIn::ServiceCredential): the server uses the
    /// first enabled service that returns one.
    fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
        None
    }
}

/// `scheme://host:port` for `public_url`, with the scheme's default port made explicit so rmcp
/// matches exactly that origin (rmcp treats a port-less entry as "any port").
fn origin_with_port(public_url: &str) -> String {
    let (scheme, rest) = public_url
        .split_once("://")
        .unwrap_or(("https", public_url));
    let authority = rest.split('/').next().unwrap_or(rest);
    let has_port = authority
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.ends_with(':') && port.parse::<u16>().is_ok());
    if has_port {
        return format!("{scheme}://{authority}");
    }
    let port = if scheme == "http" { 80 } else { 443 };
    format!("{scheme}://{authority}:{port}")
}

/// Serves an rmcp handler over Streamable HTTP, with:
///
/// - host and origin checks (DNS-rebinding protection): `PUBLIC_URL`'s host and loopback names,
///   `PUBLIC_URL`'s origin and `ALLOWED_ORIGINS`;
/// - the request body limit and shutdown wiring;
/// - the read-only rule and audit log of a [`ToolPolicy`](crate::policy::ToolPolicy) attached to
///   the router as an extension (none, no change);
/// - MCP sessions bound to the credential that opened them, so on a server shared by many people
///   nobody can use or end someone else's session, and capped per credential and in total.
///
/// `factory` runs once per MCP session: only clone `Arc`s in it.
pub fn mcp_service<S, F>(ctx: &ServiceContext, factory: F) -> axum::Router
where
    S: ServerHandler + Send + 'static,
    F: Fn() -> Result<S, std::io::Error> + Send + Sync + 'static,
{
    let http = &ctx.http;
    let mut hosts = vec![http.public_host.clone()];
    for h in ["localhost", "127.0.0.1", "::1"] {
        if !hosts.iter().any(|x| x == h) {
            hosts.push(h.to_string());
        }
    }
    let mut origins = vec![origin_with_port(&http.public_url)];
    origins.extend(http.allowed_origins.iter().cloned());
    let config = StreamableHttpServerConfig::default()
        .with_allowed_hosts(hosts)
        .with_allowed_origins(origins)
        .enforce_origin_validation()
        .with_max_request_body_bytes(BODY_LIMIT)
        .with_cancellation_token(ctx.shutdown.clone());
    let manager = Arc::new(LocalSessionManager::default());
    let service =
        StreamableHttpService::new(move || factory().map(Guarded::new), manager.clone(), config);
    let owners = Arc::new(SessionOwners::new(manager, SessionLimits::DEFAULT));
    axum::Router::new()
        .fallback_service(service)
        .layer(axum::middleware::from_fn_with_state(owners, bind_sessions))
}

const SESSION_HEADER: &str = "mcp-session-id";

/// Bounds on the session-owner table of one mount.
#[derive(Debug, Clone, Copy)]
struct SessionLimits {
    /// Sessions remembered at once. When full, entries of sessions rmcp has ended are dropped;
    /// if none has ended, new sessions are refused rather than pushing out someone else's.
    total: usize,
    /// Sessions one credential may hold; opening another closes its own least recently used one.
    per_owner: usize,
    /// An entry unused for this long is treated as gone: a little longer than rmcp's own idle
    /// timeout, after which rmcp has ended the session anyway.
    idle: Duration,
}

impl SessionLimits {
    const DEFAULT: SessionLimits = SessionLimits {
        total: 10_000,
        per_owner: 50,
        idle: Duration::from_secs(360),
    };
}

/// Which credential opened each MCP session on one mount, by fingerprint. A session id is only
/// usable with the credential that opened it, so on a server shared by many people one person
/// cannot read or end another's session even if they learn its id, and cannot push other
/// people's sessions out by opening many of their own.
struct SessionOwners {
    manager: Arc<LocalSessionManager>,
    limits: SessionLimits,
    sessions: Mutex<HashMap<String, Owner>>,
}

/// The fingerprint of the credential that opened a session (none without a guard), and when the
/// session was last used.
type Owner = (Option<[u8; 32]>, Instant);

/// What [`SessionOwners::admit`] decided about a new session.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    /// Recorded. These sessions were dropped to make room and should be closed.
    Admitted(Vec<String>),
    /// The table is full of entries that may still be live: the caller should look up which
    /// sessions rmcp still holds and ask again.
    NeedLiveSessions,
    /// Full of live sessions: refuse the new one.
    Full,
}

impl SessionOwners {
    fn new(manager: Arc<LocalSessionManager>, limits: SessionLimits) -> Self {
        SessionOwners {
            manager,
            limits,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `who` opened session `id`; refreshes its last use when it did.
    fn owned_by(&self, id: &str, who: Option<[u8; 32]>) -> bool {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get_mut(id) {
            Some((owner, used)) if now.duration_since(*used) < self.limits.idle => {
                if *owner == who {
                    *used = now;
                    true
                } else {
                    false
                }
            }
            Some(_) => {
                sessions.remove(id);
                false
            }
            None => false,
        }
    }

    /// Records a new session `id` opened by `who`. `live` is the set of sessions rmcp still
    /// holds, needed only when the table is full.
    fn admit(
        &self,
        id: &str,
        who: Option<[u8; 32]>,
        live: Option<&std::collections::HashSet<String>>,
    ) -> Admission {
        let now = Instant::now();
        let limits = self.limits;
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut dropped = Vec::new();
        if who.is_some() {
            let mut own: Vec<(String, Instant)> = sessions
                .iter()
                .filter(|(_, (owner, _))| *owner == who)
                .map(|(k, (_, used))| (k.clone(), *used))
                .collect();
            if own.len() >= limits.per_owner {
                // Make room for the new one by closing this owner's least recently used.
                own.sort_by_key(|(_, used)| *used);
                let excess = own.len() + 1 - limits.per_owner;
                for (k, _) in own.into_iter().take(excess) {
                    sessions.remove(&k);
                    dropped.push(k);
                }
            }
        }
        if sessions.len() >= limits.total {
            sessions.retain(|_, (_, used)| now.duration_since(*used) < limits.idle);
        }
        if sessions.len() >= limits.total {
            let Some(live) = live else {
                return Admission::NeedLiveSessions;
            };
            sessions.retain(|k, _| live.contains(k));
        }
        if sessions.len() >= limits.total {
            return Admission::Full;
        }
        sessions.insert(id.to_owned(), (who, now));
        Admission::Admitted(dropped)
    }

    fn remove(&self, id: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }

    async fn live_sessions(&self) -> std::collections::HashSet<String> {
        self.manager
            .sessions
            .read()
            .await
            .keys()
            .map(|k| k.to_string())
            .collect()
    }

    async fn close(&self, id: &str) {
        use rmcp::transport::streamable_http_server::session::SessionManager as _;
        let _ = self.manager.close_session(&Arc::from(id)).await;
    }
}

/// Records the credential that opens a session, and answers 404 (as for an unknown session, so
/// clients start a new one) when a request names a session opened with another credential.
async fn bind_sessions(
    State(owners): State<Arc<SessionOwners>>,
    req: Request,
    next: Next,
) -> Response {
    let who = req
        .extensions()
        .get::<Credential>()
        .map(Credential::fingerprint);
    let session = req
        .headers()
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let delete = req.method() == Method::DELETE;
    if let Some(id) = &session
        && !owners.owned_by(id, who)
    {
        return (StatusCode::NOT_FOUND, "Session not found").into_response();
    }
    let res = next.run(req).await;
    match session {
        None => {
            let Some(id) = res
                .headers()
                .get(SESSION_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
            else {
                return res;
            };
            let mut admission = owners.admit(&id, who, None);
            if admission == Admission::NeedLiveSessions {
                let live = owners.live_sessions().await;
                admission = owners.admit(&id, who, Some(&live));
            }
            match admission {
                Admission::Admitted(dropped) => {
                    for old in dropped {
                        owners.close(&old).await;
                    }
                    res
                }
                Admission::NeedLiveSessions | Admission::Full => {
                    owners.close(&id).await;
                    let mut busy = (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "This server has too many open sessions. Try again shortly.",
                    )
                        .into_response();
                    busy.headers_mut().insert(
                        axum::http::header::RETRY_AFTER,
                        axum::http::HeaderValue::from_static("30"),
                    );
                    busy
                }
            }
        }
        Some(id) if delete && res.status().is_success() => {
            owners.remove(&id);
            res
        }
        Some(_) => res,
    }
}

/// `serverInfo` icons as data URIs: a 128x128 PNG first, then an SVG.
pub fn icons(png: &[u8], svg: &str) -> Vec<Icon> {
    vec![
        Icon::new(format!("data:image/png;base64,{}", STANDARD.encode(png)))
            .with_mime_type("image/png")
            .with_sizes(vec!["128x128".into()]),
        Icon::new(format!(
            "data:image/svg+xml;base64,{}",
            STANDARD.encode(svg)
        ))
        .with_mime_type("image/svg+xml")
        .with_sizes(vec!["any".into()]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icons_are_png_then_svg_data_uris() {
        let icons = icons(b"png-bytes", "<svg/>");
        assert_eq!(icons.len(), 2);
        assert_eq!(
            icons[0].src,
            format!("data:image/png;base64,{}", STANDARD.encode(b"png-bytes"))
        );
        assert_eq!(icons[0].mime_type.as_deref(), Some("image/png"));
        assert_eq!(icons[0].sizes, Some(vec!["128x128".to_string()]));
        assert_eq!(
            icons[1].src,
            format!("data:image/svg+xml;base64,{}", STANDARD.encode("<svg/>"))
        );
        assert_eq!(icons[1].mime_type.as_deref(), Some("image/svg+xml"));
        assert_eq!(icons[1].sizes, Some(vec!["any".to_string()]));
    }

    fn owners(total: usize, per_owner: usize) -> SessionOwners {
        SessionOwners::new(
            Arc::new(LocalSessionManager::default()),
            SessionLimits {
                total,
                per_owner,
                idle: Duration::from_secs(360),
            },
        )
    }

    #[test]
    fn one_owner_cannot_hold_more_than_its_share() {
        let o = owners(100, 3);
        let (alice, bob) = (Some([1; 32]), Some([2; 32]));
        assert_eq!(o.admit("a1", alice, None), Admission::Admitted(vec![]));
        for i in 0..3 {
            assert_eq!(
                o.admit(&format!("b{i}"), bob, None),
                Admission::Admitted(vec![])
            );
        }
        assert_eq!(
            o.admit("b3", bob, None),
            Admission::Admitted(vec!["b0".into()]),
            "Bob's own oldest session makes room"
        );
        assert!(o.owned_by("a1", alice), "Alice is untouched");
        assert!(!o.owned_by("b0", bob));
        assert!(o.owned_by("b3", bob));
    }

    #[test]
    fn a_full_table_keeps_live_sessions_and_refuses_new_ones() {
        let o = owners(3, 10);
        for (i, who) in [[1; 32], [2; 32], [3; 32]].into_iter().enumerate() {
            assert_eq!(
                o.admit(&format!("s{i}"), Some(who), None),
                Admission::Admitted(vec![])
            );
        }
        assert_eq!(
            o.admit("new", Some([4; 32]), None),
            Admission::NeedLiveSessions
        );
        let all: std::collections::HashSet<String> =
            ["s0", "s1", "s2"].iter().map(|s| s.to_string()).collect();
        assert_eq!(o.admit("new", Some([4; 32]), Some(&all)), Admission::Full);
        assert!(
            o.owned_by("s0", Some([1; 32])),
            "nobody's live session is pushed out"
        );
        let some: std::collections::HashSet<String> =
            ["s0", "s2"].iter().map(|s| s.to_string()).collect();
        assert_eq!(
            o.admit("new", Some([4; 32]), Some(&some)),
            Admission::Admitted(vec![]),
            "sessions rmcp has ended make room"
        );
        assert!(!o.owned_by("s1", Some([2; 32])));
        assert!(o.owned_by("new", Some([4; 32])));
    }

    #[test]
    fn origin_gets_explicit_default_port() {
        assert_eq!(
            origin_with_port("https://mail.example.com"),
            "https://mail.example.com:443"
        );
        assert_eq!(
            origin_with_port("http://localhost:8443"),
            "http://localhost:8443"
        );
        assert_eq!(origin_with_port("http://localhost"), "http://localhost:80");
        assert_eq!(origin_with_port("https://[::1]"), "https://[::1]:443");
        assert_eq!(origin_with_port("https://[::1]:9000"), "https://[::1]:9000");
    }
}
