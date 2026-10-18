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
    /// Sessions remembered at once. When full, idle entries and those of sessions rmcp has ended
    /// are swept first; then the owner holding the most (more than the newcomer's count plus
    /// one) gives up its least recently used session, or a newcomer holding at least as many as
    /// anyone else gives up its own. Only when shares are about even are new sessions refused.
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
    table: Mutex<Table>,
}

/// The fingerprint of the credential that opened a session (none without a guard).
type Who = Option<[u8; 32]>;

#[derive(Default)]
struct Table {
    /// Session id to its owner and last use.
    sessions: HashMap<String, (Who, Instant)>,
    /// Sessions held per owner.
    counts: HashMap<Who, usize>,
    /// When the full table was last swept for idle and ended sessions.
    last_sweep: Option<Instant>,
}

impl Table {
    fn insert(&mut self, id: String, who: Who, now: Instant) {
        if self.sessions.insert(id, (who, now)).is_none() {
            *self.counts.entry(who).or_default() += 1;
        }
    }

    fn remove(&mut self, id: &str) -> bool {
        let Some((who, _)) = self.sessions.remove(id) else {
            return false;
        };
        if let Some(n) = self.counts.get_mut(&who) {
            *n -= 1;
            if *n == 0 {
                self.counts.remove(&who);
            }
        }
        true
    }

    fn retain(&mut self, mut keep: impl FnMut(&str, &(Who, Instant)) -> bool) {
        self.sessions.retain(|k, v| keep(k, v));
        self.counts.clear();
        for (who, _) in self.sessions.values() {
            *self.counts.entry(*who).or_default() += 1;
        }
    }

    fn count(&self, who: Who) -> usize {
        self.counts.get(&who).copied().unwrap_or(0)
    }

    /// The least recently used session of `who`.
    fn oldest_of(&self, who: Who) -> Option<String> {
        self.sessions
            .iter()
            .filter(|(_, (owner, _))| *owner == who)
            .min_by_key(|(_, (_, used))| *used)
            .map(|(k, _)| k.clone())
    }

    /// The owner, other than `who`, holding the most sessions, and how many.
    fn largest_other(&self, who: Who) -> Option<(Who, usize)> {
        self.counts
            .iter()
            .filter(|(owner, _)| **owner != who)
            .max_by_key(|(_, n)| **n)
            .map(|(owner, n)| (*owner, *n))
    }

    /// Whether a new session for `who` could get a slot in a full table by taking one from
    /// whoever holds the most, so that everyone tends toward an equal share.
    fn fair_share_room(&self, who: Who) -> Option<Who> {
        let mine = self.count(who);
        self.largest_other(who)
            .filter(|(_, n)| *n > mine + 1)
            .map(|(owner, _)| owner)
    }

    /// Whose least recently used session makes room for a new one of `who` in a full table:
    /// whoever holds clearly more, or else `who` itself when it holds any, so a key that already
    /// has sessions replaces its own instead of being refused or pushing someone else out.
    fn room_for(&self, who: Who) -> Option<Who> {
        self.fair_share_room(who)
            .or_else(|| (who.is_some() && self.count(who) > 0).then_some(who))
    }
}

/// Whether a request may use the session it names.
#[derive(Debug, PartialEq, Eq)]
enum Ownership {
    Owner,
    NotOwner,
    /// The owner's entry has not been used for a while; ask rmcp whether the session lives.
    Stale,
}

/// What [`SessionOwners::admit`] decided about a new session.
#[derive(Debug, PartialEq, Eq)]
struct Admission {
    admitted: bool,
    /// Sessions dropped to make room, to be closed in rmcp.
    dropped: Vec<String>,
}

impl SessionOwners {
    fn new(manager: Arc<LocalSessionManager>, limits: SessionLimits) -> Self {
        SessionOwners {
            manager,
            limits,
            table: Mutex::new(Table::default()),
        }
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn owned_by(&self, id: &str, who: Who) -> Ownership {
        let now = Instant::now();
        let mut table = self.table();
        match table.sessions.get_mut(id) {
            Some((owner, _)) if *owner != who => Ownership::NotOwner,
            Some((_, used)) if now.duration_since(*used) < self.limits.idle => {
                *used = now;
                Ownership::Owner
            }
            Some(_) => Ownership::Stale,
            None => Ownership::NotOwner,
        }
    }

    /// Marks session `id` as used now, if `who` owns it.
    fn touch(&self, id: &str, who: Who) {
        if let Some((owner, used)) = self.table().sessions.get_mut(id)
            && *owner == who
        {
            *used = Instant::now();
        }
    }

    /// Whether a full table is due a sweep, which needs the sessions rmcp still holds.
    fn wants_live_sessions(&self) -> bool {
        let table = self.table();
        table.sessions.len() >= self.limits.total && self.sweep_due(&table)
    }

    fn sweep_due(&self, table: &Table) -> bool {
        table.last_sweep.is_none_or(|t| t.elapsed() >= SWEEP_EVERY)
    }

    /// Whether a new session for `who` would be refused, judged cheaply before rmcp builds it:
    /// the table is full, was swept moments ago, and no one holds more than their share.
    fn refuse_early(&self, who: Who) -> bool {
        let table = self.table();
        table.sessions.len() >= self.limits.total
            && !self.sweep_due(&table)
            && !(who.is_some() && table.count(who) >= self.limits.per_owner)
            && table.room_for(who).is_none()
    }

    /// Records a new session `id` opened by `who`. `live` is the set of sessions rmcp still
    /// holds, when [`Self::wants_live_sessions`] asked for it.
    fn admit(
        &self,
        id: &str,
        who: Who,
        live: Option<&std::collections::HashSet<String>>,
    ) -> Admission {
        let now = Instant::now();
        let limits = self.limits;
        let mut table = self.table();
        let mut dropped = Vec::new();
        // One owner never holds more than its cap: its own oldest session makes room.
        if who.is_some() {
            while table.count(who) >= limits.per_owner {
                let Some(oldest) = table.oldest_of(who) else {
                    break;
                };
                table.remove(&oldest);
                dropped.push(oldest);
            }
        }
        if table.sessions.len() >= limits.total && self.sweep_due(&table) {
            table.retain(|_, (_, used)| now.duration_since(*used) < limits.idle);
            if let Some(live) = live {
                table.retain(|k, _| live.contains(k));
            }
            table.last_sweep = Some(now);
        }
        if table.sessions.len() >= limits.total {
            // Take a slot from whoever holds the most, never from someone with fewer than
            // the newcomer would have.
            let Some(owner) = table.room_for(who) else {
                return Admission {
                    admitted: false,
                    dropped,
                };
            };
            if let Some(oldest) = table.oldest_of(owner) {
                table.remove(&oldest);
                dropped.push(oldest);
            }
        }
        table.insert(id.to_owned(), who, now);
        Admission {
            admitted: true,
            dropped,
        }
    }

    fn remove(&self, id: &str) {
        self.table().remove(id);
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

    async fn is_live(&self, id: &str) -> bool {
        self.manager.sessions.read().await.contains_key(id)
    }

    async fn close(&self, id: &str) {
        use rmcp::transport::streamable_http_server::session::SessionManager as _;
        let _ = self.manager.close_session(&Arc::from(id)).await;
    }
}

/// The full table is swept for idle and ended sessions at most this often.
const SWEEP_EVERY: Duration = Duration::from_secs(1);

fn too_many_sessions() -> Response {
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
    match &session {
        Some(id) => match owners.owned_by(id, who) {
            Ownership::Owner => {}
            Ownership::NotOwner => {
                return (StatusCode::NOT_FOUND, "Session not found").into_response();
            }
            // Quiet for a while, as during a long tool call: still the owner's if rmcp has
            // kept the session.
            Ownership::Stale => {
                if owners.is_live(id).await {
                    owners.touch(id, who);
                } else {
                    owners.remove(id);
                    return (StatusCode::NOT_FOUND, "Session not found").into_response();
                }
            }
        },
        None if owners.refuse_early(who) => return too_many_sessions(),
        None => {}
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
            // Decided and cleaned up in a task of its own, so the table and rmcp stay in step
            // even if the client goes away meanwhile.
            let task = tokio::spawn({
                let owners = owners.clone();
                async move {
                    let live = if owners.wants_live_sessions() {
                        Some(owners.live_sessions().await)
                    } else {
                        None
                    };
                    let admission = owners.admit(&id, who, live.as_ref());
                    for old in &admission.dropped {
                        owners.close(old).await;
                    }
                    if !admission.admitted {
                        owners.close(&id).await;
                    }
                    admission.admitted
                }
            });
            if task.await.unwrap_or(false) {
                res
            } else {
                too_many_sessions()
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

    fn ok(dropped: &[&str]) -> Admission {
        Admission {
            admitted: true,
            dropped: dropped.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn live(ids: &[&str]) -> std::collections::HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn one_owner_cannot_hold_more_than_its_share() {
        let o = owners(100, 3);
        let (alice, bob) = (Some([1; 32]), Some([2; 32]));
        assert_eq!(o.admit("a1", alice, None), ok(&[]));
        for i in 0..3 {
            assert_eq!(o.admit(&format!("b{i}"), bob, None), ok(&[]));
        }
        assert_eq!(
            o.admit("b3", bob, None),
            ok(&["b0"]),
            "Bob's own oldest session makes room"
        );
        assert_eq!(
            o.owned_by("a1", alice),
            Ownership::Owner,
            "Alice is untouched"
        );
        assert_eq!(o.owned_by("b0", bob), Ownership::NotOwner);
        assert_eq!(o.owned_by("b3", bob), Ownership::Owner);
        assert_eq!(o.owned_by("b3", alice), Ownership::NotOwner);
    }

    #[test]
    fn a_full_table_frees_ended_sessions_first() {
        let o = owners(3, 10);
        for (i, who) in [[1; 32], [2; 32], [3; 32]].into_iter().enumerate() {
            assert_eq!(o.admit(&format!("s{i}"), Some(who), None), ok(&[]));
        }
        assert!(o.wants_live_sessions());
        assert_eq!(
            o.admit("new", Some([4; 32]), Some(&live(&["s0", "s2"]))),
            ok(&[]),
            "the session rmcp has ended makes room"
        );
        assert_eq!(o.owned_by("s1", Some([2; 32])), Ownership::NotOwner);
        assert_eq!(o.owned_by("new", Some([4; 32])), Ownership::Owner);
    }

    #[test]
    fn a_full_table_takes_room_from_whoever_holds_most() {
        let o = owners(4, 3);
        let (a, b, c) = (Some([1; 32]), Some([2; 32]), Some([3; 32]));
        for id in ["a1", "a2", "a3"] {
            assert_eq!(o.admit(id, a, None), ok(&[]));
        }
        assert_eq!(o.admit("b1", b, None), ok(&[]));
        let all = live(&["a1", "a2", "a3", "b1"]);
        assert_eq!(
            o.admit("c1", c, Some(&all)),
            ok(&["a1"]),
            "the largest holder gives up its oldest"
        );
        assert_eq!(
            o.owned_by("b1", b),
            Ownership::Owner,
            "Bob's only session is kept"
        );
        // Now a holds 2, b 1, c 1: c's next takes from a, d's from a, and then shares are even.
        assert_eq!(o.admit("d1", Some([4; 32]), None), ok(&["a2"]));
        assert_eq!(
            o.admit("e1", Some([5; 32]), None),
            Admission {
                admitted: false,
                dropped: vec![]
            },
            "everyone holds one: nobody is pushed out for a newcomer"
        );
        assert!(
            o.refuse_early(Some([6; 32])),
            "and the next is refused cheaply"
        );
        // An owner at its cap in a full table can still swap one of its own.
        let o = owners(2, 1);
        o.admit("a1", a, None);
        o.admit("b1", b, None);
        assert!(!o.admit("c1", c, Some(&live(&["a1", "b1"]))).admitted);
        assert!(o.refuse_early(c));
        assert!(!o.refuse_early(a));
        assert_eq!(o.admit("a2", a, None), ok(&["a1"]));
    }

    #[test]
    fn the_largest_holder_below_its_cap_replaces_its_own_sessions() {
        let o = owners(4, 10);
        let (a, b) = (Some([1; 32]), Some([2; 32]));
        for id in ["a1", "a2", "a3"] {
            assert_eq!(o.admit(id, a, None), ok(&[]));
        }
        assert_eq!(o.admit("b1", b, None), ok(&[]));
        let all = live(&["a1", "a2", "a3", "b1"]);
        assert!(!o.refuse_early(a), "a holds the most, so it is not refused");
        assert_eq!(
            o.admit("a4", a, Some(&all)),
            ok(&["a1"]),
            "a full table makes room from a's own oldest"
        );
        assert_eq!(o.admit("b2", b, None), ok(&["a2"]), "b still takes from a");
    }

    #[test]
    fn a_key_with_one_fewer_than_the_largest_replaces_its_own() {
        let o = owners(3, 10);
        let (a, b) = (Some([1; 32]), Some([2; 32]));
        o.admit("a1", a, None);
        o.admit("a2", a, None);
        o.admit("b1", b, None);
        let all = live(&["a1", "a2", "b1"]);
        assert!(!o.refuse_early(b));
        assert_eq!(o.admit("b2", b, Some(&all)), ok(&["b1"]));
        // A newcomer still takes from whoever holds clearly more, then shares are even.
        assert_eq!(o.admit("c1", Some([3; 32]), None), ok(&["a1"]));
        assert!(
            o.refuse_early(Some([4; 32])),
            "everyone holds one: a newcomer with none is refused"
        );
    }

    #[test]
    fn a_quiet_session_is_stale_not_gone() {
        let o = SessionOwners::new(
            Arc::new(LocalSessionManager::default()),
            SessionLimits {
                total: 10,
                per_owner: 10,
                idle: Duration::ZERO,
            },
        );
        let who = Some([1; 32]);
        o.admit("s", who, None);
        assert_eq!(o.owned_by("s", who), Ownership::Stale);
        assert_eq!(o.owned_by("s", Some([2; 32])), Ownership::NotOwner);
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
