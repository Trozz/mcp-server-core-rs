//! The OAuth 2.1 authorization server and the bearer guard in front of every service.
//!
//! Endpoints, all at the root of `PUBLIC_URL`:
//!
//! | Path | |
//! |---|---|
//! | `GET /.well-known/oauth-protected-resource/<service>` | Protected-resource metadata (RFC 9728) |
//! | `GET /.well-known/oauth-authorization-server` | Authorization-server metadata (RFC 8414) |
//! | `POST /register` | Dynamic client registration (RFC 7591), public clients only |
//! | `GET, POST /authorize` | The sign-in page; authorization code with PKCE S256 only |
//! | `POST /token` | `authorization_code` and `refresh_token` grants |
//!
//! Every service `<name>` is its own protected resource, `PUBLIC_URL/<name>`, and access tokens
//! are bound to it (RFC 8707): a token for one service is refused by every other.
//!
//! Nothing is stored. Clients, CSRF tokens, codes, access and refresh tokens are all JWTs signed
//! with `OAUTH_SIGNING_KEY` (HS256); only the one-time use of authorization codes is remembered in
//! memory until they expire. Rotating the key signs everyone out.

mod authorize;
mod metadata;
mod middleware;
mod register;
mod token;

pub use authorize::client_ip;
pub use middleware::require_bearer;
pub use register::validate_redirect_uri;

use crate::credential::{CheckCache, CheckRunner, CredentialVerifier, Sealer};
use crate::guards::{Ceiling, LoginLimiter, ReplayGuard};
use crate::jwt::Jwt;
use axum::Router;
use axum::routing::{get, post};
use secrecy::{ExposeSecret, SecretString};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// What the authorization server needs from the core configuration.
#[derive(Clone)]
pub struct OAuthSettings {
    /// External base URL without a trailing slash: the issuer, and the prefix of every resource.
    pub public_url: String,
    /// Signs every token (HS256) and derives the key that seals credentials. At least 32 bytes.
    pub signing_key: SecretString,
    /// Reverse proxies whose `X-Forwarded-For` is believed when limiting sign-in attempts.
    pub trusted_proxies: Vec<IpAddr>,
    /// A fixed bearer token accepted on every service (`MCP_AUTH_TOKEN`), for clients that
    /// cannot do OAuth. Only for sign-in that does not carry credentials: requests made with it
    /// have no [`Credential`](crate::credential::Credential).
    pub static_token: Option<SecretString>,
}

impl std::fmt::Debug for OAuthSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthSettings")
            .field("public_url", &self.public_url)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("static_token", &self.static_token.as_ref().map(|_| ".."))
            .finish_non_exhaustive()
    }
}

/// How long a bearer credential found valid upstream is trusted before it is checked again.
pub const BEARER_VALID_FOR: Duration = Duration::from_secs(600);
/// How long a rejected bearer credential is remembered.
pub const BEARER_INVALID_FOR: Duration = Duration::from_secs(60);
const BEARER_CACHE_ENTRIES: usize = 10_000;
/// Credential checks allowed to run at once, across sign-ins and bearer credentials.
pub const MAX_RUNNING_CHECKS: usize = 16;
/// Credential checks that may start per [`LOGIN_WINDOW`], across every address. Credentials
/// already checked (cached) and issued tokens are not affected; past the cap new credentials are
/// answered "unavailable, try again" instead of being sent upstream.
pub const MAX_NEW_CHECKS: usize = 60;
/// Longest a grant lasts after the person signed in, however often it is refreshed. Then they
/// sign in again.
pub const MAX_GRANT_AGE: Duration = Duration::from_secs(90 * 24 * 3600);
/// Longest a credential check may take before it counts as unavailable.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(15);
/// Longest a check waits for a free slot when [`MAX_RUNNING_CHECKS`] are already running.
pub const CHECK_SLOT_WAIT: Duration = Duration::from_secs(5);
/// Failed sign-in attempts one address may make per [`LOGIN_WINDOW`]. Failures across all
/// addresses are capped too (see [`crate::guards::Ceiling`]): with a credential that is not
/// carried, such as the owner's password, reaching that cap blocks everyone for the window.
pub const LOGIN_ATTEMPTS: usize = 5;
/// The window [`LOGIN_ATTEMPTS`] counts over.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(60);

/// The authorization server's state, shared by its routes and every service's bearer guard.
pub struct AuthState {
    pub(crate) settings: OAuthSettings,
    pub(crate) jwt: Jwt,
    pub(crate) limiter: LoginLimiter,
    pub(crate) replay: ReplayGuard,
    pub(crate) verifier: Arc<dyn CredentialVerifier>,
    pub(crate) sealer: Sealer,
    /// Recent verdicts on credentials sent directly as bearer tokens.
    pub(crate) bearer_checks: CheckCache,
    /// Runs credential checks: shared per credential, capped and timed out.
    pub(crate) checks: CheckRunner,
    services: Vec<String>,
    sign_in_version: String,
}

/// Why the static token cannot be used with a verifier, if it cannot.
pub(crate) fn static_token_problem(
    token: &str,
    verifier: &dyn CredentialVerifier,
) -> Option<String> {
    if verifier.carried() || verifier.accepts_bearer() {
        return Some(format!(
            "MCP_AUTH_TOKEN cannot be used when people sign in with their own {}",
            verifier.label()
        ));
    }
    if token.split('.').count() == 3 {
        return Some(
            "MCP_AUTH_TOKEN must not have the shape of a JWT (three dot-separated parts)".into(),
        );
    }
    None
}

/// The keyed hash tokens carry as `ver`: of the sign-in mode and the verifier's generation.
fn sign_in_version(signing_key: &[u8], verifier: &dyn CredentialVerifier) -> String {
    use base64::Engine as _;
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, signing_key);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(b"mcp-server-core sign-in v1\0");
    ctx.update(if verifier.carried() {
        b"carried\0"
    } else {
        b"password\0"
    });
    ctx.update(verifier.generation());
    let tag = ctx.sign();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&tag.as_ref()[..16])
}

impl AuthState {
    /// `services` are the enabled service names; each is the protected resource
    /// `PUBLIC_URL/<name>`. Tokens the authorization server keeps for itself (client, CSRF, code,
    /// refresh) use the public URL as audience; access tokens use their resource. `verifier`
    /// decides who may sign in.
    ///
    /// # Panics
    ///
    /// If `settings.static_token` is set while `verifier` carries credentials or accepts them as
    /// bearer tokens (requests made with it would lack the credential tools expect, and wrong
    /// tokens could be tried as credentials without limit), or when the static token has the shape
    /// of a JWT. [`Server::load`](crate::app::Server::load) reports these as configuration errors.
    pub fn new(
        settings: OAuthSettings,
        services: &[&str],
        verifier: Arc<dyn CredentialVerifier>,
    ) -> Arc<Self> {
        if let Some(token) = &settings.static_token
            && let Some(problem) = static_token_problem(token.expose_secret(), verifier.as_ref())
        {
            panic!("{problem}");
        }
        let key = settings.signing_key.expose_secret().as_bytes();
        let jwt = Jwt::new(
            key,
            settings.public_url.clone(),
            settings.public_url.clone(),
        );
        let sealer = Sealer::new(key);
        let sign_in_version = sign_in_version(key, verifier.as_ref());
        // One shared secret (the owner's password, the static token) is worth a lockout of
        // everyone during a distributed attack; with per-person credentials it is not.
        let ceiling = if verifier.carried() {
            Ceiling::BlockFailing
        } else {
            Ceiling::BlockEveryone
        };
        Arc::new(Self {
            settings,
            jwt,
            limiter: LoginLimiter::new(LOGIN_ATTEMPTS, LOGIN_WINDOW, ceiling),
            replay: ReplayGuard::new(),
            verifier,
            sealer,
            bearer_checks: CheckCache::new(
                BEARER_VALID_FOR,
                BEARER_INVALID_FOR,
                BEARER_CACHE_ENTRIES,
            ),
            checks: CheckRunner::with_rate(
                MAX_RUNNING_CHECKS,
                CHECK_TIMEOUT,
                CHECK_SLOT_WAIT,
                MAX_NEW_CHECKS,
                LOGIN_WINDOW,
            ),
            services: services.iter().map(|s| s.to_string()).collect(),
            sign_in_version,
        })
    }

    /// The `ver` every code, access and refresh token must carry: a keyed hash of the sign-in mode
    /// and the verifier's [generation](CredentialVerifier::generation). Changing the owner's
    /// password, switching between sign-in modes or rotating `OAUTH_SIGNING_KEY` changes it and so
    /// ends every earlier grant.
    pub fn sign_in_version(&self) -> &str {
        &self.sign_in_version
    }

    /// Whether a code, access or refresh token's grant still holds: same sign-in version, a
    /// sealed credential exactly when credentials are carried, and signed in less than
    /// [`MAX_GRANT_AGE`] ago.
    pub(crate) fn grant_is_current(&self, claims: &crate::jwt::Claims) -> bool {
        let p = &claims.payload;
        let version_ok = p
            .ver
            .as_deref()
            .is_some_and(|v| crate::pkce::ct_eq(v, &self.sign_in_version));
        let mode_ok = p.credential.is_some() == self.verifier.carried();
        let now = jsonwebtoken::get_current_timestamp();
        let fresh = p.auth_time.is_some_and(|t| {
            t <= now + crate::jwt::LEEWAY_SECS && now - t.min(now) < MAX_GRANT_AGE.as_secs()
        });
        version_ok && mode_ok && fresh
    }

    /// The settings this server was built with.
    pub fn settings(&self) -> &OAuthSettings {
        &self.settings
    }

    /// Issues and verifies this server's tokens, e.g. to mint one in a test.
    pub fn jwt(&self) -> &Jwt {
        &self.jwt
    }

    /// Seals and opens the credentials carried in tokens.
    pub fn sealer(&self) -> &Sealer {
        &self.sealer
    }

    /// Who may sign in.
    pub fn verifier(&self) -> &dyn CredentialVerifier {
        self.verifier.as_ref()
    }

    /// The enabled service names, each a protected resource.
    pub fn services(&self) -> &[String] {
        &self.services
    }

    /// Whether `service` is one of them.
    pub fn has_service(&self, service: &str) -> bool {
        self.services.iter().any(|s| s == service)
    }

    /// The resource URL of `service`: `PUBLIC_URL/<service>`.
    pub fn resource(&self, service: &str) -> String {
        format!("{}/{service}", self.settings.public_url)
    }

    /// Where `service`'s protected-resource metadata is served.
    pub fn resource_metadata_url(&self, service: &str) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource/{service}",
            self.settings.public_url
        )
    }

    /// The enabled service whose resource URL is exactly `resource`.
    pub fn service_for_resource(&self, resource: &str) -> Option<&str> {
        self.services
            .iter()
            .find(|s| self.resource(s) == resource)
            .map(String::as_str)
    }
}

/// The authorization server's routes: metadata, registration, sign-in and token endpoints.
/// [`crate::server::build_app`] merges them for you.
pub fn oauth_router(state: Arc<AuthState>) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource/{service}",
            get(metadata::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server),
        )
        .route("/register", post(register::register))
        .route("/token", post(token::token))
        .route(
            "/authorize",
            get(authorize::get_authorize).post(authorize::post_authorize),
        )
        .with_state(state)
}
