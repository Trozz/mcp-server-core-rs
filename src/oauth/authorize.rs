use super::AuthState;
use crate::credential::{self, CheckRunner, CredentialCheck, Ticket};
use crate::jwt::{Payload, TokenKind};
use crate::pkce;
use axum::extract::{ConnectInfo, Form, FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub state: Option<String>,
    // `scope` is ignored: the resource decides what is granted.
    pub resource: Option<String>,
}

#[derive(Debug)]
pub enum Rejection {
    BadClient(&'static str),
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        error: &'static str,
        description: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct ValidRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub state: Option<String>,
    pub scope: String,
    pub resource: String,
    pub client_name: Option<String>,
}

pub fn validate(st: &AuthState, p: &AuthorizeParams) -> Result<ValidRequest, Rejection> {
    let client_id = p
        .client_id
        .as_deref()
        .ok_or(Rejection::BadClient("missing client_id"))?;
    let client = st
        .jwt
        .verify(client_id, TokenKind::Client)
        .map_err(|_| Rejection::BadClient("unknown client"))?;
    let redirect_uri = p
        .redirect_uri
        .as_deref()
        .ok_or(Rejection::BadClient("missing redirect_uri"))?;
    let registered = client.payload.redirect_uris.unwrap_or_default();
    if !registered.iter().any(|r| r == redirect_uri) {
        return Err(Rejection::BadClient(
            "redirect_uri is not registered for this client",
        ));
    }
    let state = p.state.clone().filter(|s| !s.is_empty());
    let redirect = |error, description| Rejection::Redirect {
        redirect_uri: redirect_uri.to_string(),
        state: state.clone(),
        error,
        description,
    };
    if p.response_type.as_deref() != Some("code") {
        return Err(redirect(
            "unsupported_response_type",
            "response_type must be code",
        ));
    }
    if p.code_challenge_method.as_deref() != Some("S256") {
        return Err(redirect(
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }
    let Some(code_challenge) = p.code_challenge.clone().filter(|c| c.len() == 43) else {
        return Err(redirect("invalid_request", "code_challenge is required"));
    };
    // A request without `resource` (clients older than the 2025-06-18 MCP auth spec) gets the
    // only service when there is one; the combined endpoint is never chosen by default.
    let services: Vec<&String> = st
        .services()
        .iter()
        .filter(|s| s.as_str() != crate::combined::COMBINED)
        .collect();
    let resource = match (p.resource.as_deref(), services.as_slice()) {
        (Some(r), _) => r.to_string(),
        (None, [only]) => st.resource(only),
        (None, _) => {
            return Err(redirect(
                "invalid_target",
                "resource is required: name the URL of the service, or of /mcp for every service",
            ));
        }
    };
    let Some(service) = st.service_for_resource(&resource) else {
        return Err(redirect(
            "invalid_target",
            "resource is not a service on this server",
        ));
    };
    Ok(ValidRequest {
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        code_challenge,
        state,
        scope: service.to_string(),
        resource,
        client_name: client.payload.client_name,
    })
}

pub fn binding(v: &ValidRequest) -> String {
    pkce::s256(&format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        v.client_id,
        v.redirect_uri,
        v.code_challenge,
        v.state.as_deref().unwrap_or(""),
        v.scope,
        v.resource
    ))
}

pub struct ClientIp(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = Infallible;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip()),
        ))
    }
}

/// The address a request came from, for rate limiting. `X-Forwarded-For` is believed only when
/// the connection comes from one of the `trusted` proxies: then the rightmost entry that is not
/// itself a trusted proxy is the client. A malformed entry, or none, falls back to the peer.
/// IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`, as a dual-stack listener reports IPv4 peers)
/// are treated as the IPv4 address, in the peer, the header and `trusted` alike.
pub fn client_ip(peer: Option<IpAddr>, headers: &HeaderMap, trusted: &[IpAddr]) -> IpAddr {
    let peer_ip = peer.unwrap_or(IpAddr::from([0, 0, 0, 0])).to_canonical();
    let is_trusted = |ip: IpAddr| trusted.iter().any(|t| t.to_canonical() == ip);
    if !is_trusted(peer_ip) {
        return peer_ip;
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .collect();
    for entry in entries.into_iter().rev() {
        let Some(ip) = forwarded_ip(entry) else {
            return peer_ip;
        };
        let ip = ip.to_canonical();
        if !is_trusted(ip) {
            return ip;
        }
    }
    peer_ip
}

/// The address in one `X-Forwarded-For` entry: `203.0.113.7`, `203.0.113.7:5000`, `2001:db8::1`
/// or `[2001:db8::1]:443`.
fn forwarded_ip(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sock) = entry.parse::<SocketAddr>() {
        return Some(sock.ip());
    }
    entry
        .strip_prefix('[')
        .and_then(|e| e.strip_suffix(']'))
        .and_then(|e| e.parse().ok())
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(flatten)]
    pub params: AuthorizeParams,
    pub csrf: String,
    /// What was typed; absent when people sign in through an upstream provider.
    #[serde(default)]
    pub credential: String,
}

pub(super) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn with_page_headers(status: StatusCode, html: String) -> Response {
    let mut res = (status, Html(html)).into_response();
    let h = res.headers_mut();
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::SERVICE_UNAVAILABLE {
        h.insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(super::middleware::RETRY_AFTER_SECS),
        );
    }
    res
}

pub(super) fn refusal_page(refusal: crate::guards::Refusal) -> Response {
    match refusal {
        crate::guards::Refusal::Busy => error_page(
            StatusCode::SERVICE_UNAVAILABLE,
            "This server is refusing new addresses while it is under heavy load. Try again \
             shortly.",
        ),
        _ => error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts from this address: credentials were rejected, or several are \
             being checked at once. Wait a little and try again.",
        ),
    }
}

pub(super) fn error_page(status: StatusCode, message: &str) -> Response {
    with_page_headers(
        status,
        format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Authorization error</title><p>{}</p>",
            escape(message)
        ),
    )
}

fn login_page(
    st: &AuthState,
    v: &ValidRequest,
    status: StatusCode,
    error: Option<&str>,
) -> Response {
    let csrf = st
        .jwt
        .issue(
            TokenKind::Csrf,
            Some(Duration::from_secs(600)),
            Payload {
                binding: Some(binding(v)),
                ..Default::default()
            },
        )
        .unwrap_or_default();
    let hidden = [
        ("response_type", "code"),
        ("client_id", v.client_id.as_str()),
        ("redirect_uri", v.redirect_uri.as_str()),
        ("code_challenge", v.code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", v.state.as_deref().unwrap_or("")),
        ("scope", v.scope.as_str()),
        ("resource", v.resource.as_str()),
        ("csrf", csrf.as_str()),
    ]
    .iter()
    .map(|(n, val)| {
        format!(
            "<input type=\"hidden\" name=\"{n}\" value=\"{}\">",
            escape(val)
        )
    })
    .collect::<String>();
    let destination = url::Url::parse(&v.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(escape))
        .map(|h| format!("<p>After you authorize, you will be sent to <strong>{h}</strong>.</p>"))
        .unwrap_or_default();
    let client_html = v
        .client_name
        .as_deref()
        .map(|n| {
            format!(
                "<p>Client name (self-reported, unverified): <strong>{}</strong></p>",
                escape(n)
            )
        })
        .unwrap_or_default();
    let error_html = error
        .map(|e| format!("<p style=\"color:#b00\">{}</p>", escape(e)))
        .unwrap_or_default();
    let target = if v.scope == crate::combined::COMBINED {
        "<strong>every service</strong> on this server, through <code>/mcp</code>".to_string()
    } else {
        format!(
            "the <strong>{}</strong> service on this server",
            escape(&v.scope)
        )
    };
    let verifier = st.verifier.as_ref();
    if let Some(upstream) = verifier.upstream() {
        let provider = escape(upstream.provider());
        let help = match verifier.help().trim() {
            "" => String::new(),
            h => format!("<p><small>{}</small></p>", escape(h)),
        };
        let html = format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
<title>Authorize</title><style>body{{font-family:system-ui;max-width:24rem;margin:4rem auto;padding:0 1rem}}button{{margin-top:1rem;padding:.5rem 1rem}}small{{color:#555}}</style></head>\
<body><h1>Authorize access</h1><p>An MCP client is requesting access to {target}.</p>{client_html}{destination}\
<p>Only continue if you started connecting this client. You will sign in at <strong>{provider}</strong> and approve access there; \
what {provider} grants is kept only in encrypted form inside this connection's tokens, and this server does not store it.</p>{error_html}\
<form method=\"post\" action=\"/authorize\">{hidden}{help}<button type=\"submit\">Continue to {provider}</button></form></body></html>"
        );
        return with_page_headers(status, html);
    }
    let label = escape(verifier.label());
    let field = escape(&capitalised(verifier.label()));
    let help = match verifier.help().trim() {
        "" => String::new(),
        h => format!("<p><small>{}</small></p>", escape(h)),
    };
    let (intro, autocomplete) = if verifier.carried() {
        (
            format!(
                "<p>Sign in with your own {label}. It is checked once, then kept only in encrypted \
                 form inside this connection's tokens; this server does not store it.</p>"
            ),
            "off",
        )
    } else {
        (
            format!("<p>Sign in with this server's {label}.</p>"),
            "current-password",
        )
    };
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
<title>Authorize</title><style>body{{font-family:system-ui;max-width:24rem;margin:4rem auto;padding:0 1rem}}input[type=password]{{width:100%;padding:.5rem}}button{{margin-top:1rem;padding:.5rem 1rem}}small{{color:#555}}</style></head>\
<body><h1>Authorize access</h1><p>An MCP client is requesting access to {target}.</p>{client_html}{destination}\
{intro}{error_html}\
<form method=\"post\" action=\"/authorize\">{hidden}<label>{field}<input type=\"password\" name=\"credential\" autocomplete=\"{autocomplete}\" spellcheck=\"false\" autofocus required></label>\
{help}<button type=\"submit\">Authorize</button></form></body></html>"
    );
    with_page_headers(status, html)
}

/// `s` with its first letter in upper case, for a field label.
fn capitalised(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// An error sent back to the client's redirect URI, with `iss` (RFC 9207). `after_post` answers
/// 303 so no user agent re-sends a form body; otherwise 302.
pub(super) fn redirect_error(
    issuer: &str,
    redirect_uri: &str,
    state: Option<&str>,
    error: &str,
    description: &str,
    after_post: bool,
) -> Response {
    let Ok(mut url) = url::Url::parse(redirect_uri) else {
        return error_page(StatusCode::BAD_REQUEST, "invalid redirect_uri");
    };
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("error", error)
            .append_pair("error_description", description);
        if let Some(s) = state {
            q.append_pair("state", s);
        }
        q.append_pair("iss", issuer);
    }
    let res = Redirect::to(url.as_str()).into_response();
    if after_post { res } else { res.with_found() }
}

trait Found {
    fn with_found(self) -> Response;
}

impl Found for Response {
    fn with_found(mut self) -> Response {
        *self.status_mut() = StatusCode::FOUND;
        self
    }
}

fn rejection_response(st: &AuthState, r: Rejection, after_post: bool) -> Response {
    match r {
        Rejection::BadClient(msg) => error_page(StatusCode::BAD_REQUEST, msg),
        Rejection::Redirect {
            redirect_uri,
            state,
            error,
            description,
        } => redirect_error(
            &st.settings.public_url,
            &redirect_uri,
            state.as_deref(),
            error,
            description,
            after_post,
        ),
    }
}

pub async fn get_authorize(
    State(st): State<Arc<AuthState>>,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    match validate(&st, &p) {
        Ok(v) => login_page(&st, &v, StatusCode::OK, None),
        Err(r) => rejection_response(&st, r, false),
    }
}

pub async fn post_authorize(
    State(st): State<Arc<AuthState>>,
    ClientIp(peer): ClientIp,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = client_ip(peer, &headers, &st.settings.trusted_proxies);
    if let Some(refusal) = st.limiter.refusal(ip) {
        metrics::counter!("oauth_requests_total", "endpoint" => "authorize", "outcome" => "rate_limited").increment(1);
        return refusal_page(refusal);
    }
    let v = match validate(&st, &form.params) {
        Ok(v) => v,
        Err(r) => return rejection_response(&st, r, true),
    };
    let csrf_ok = st
        .jwt
        .verify(&form.csrf, TokenKind::Csrf)
        .ok()
        .and_then(|c| c.payload.binding)
        .is_some_and(|b| pkce::ct_eq(&b, &binding(&v)));
    if !csrf_ok {
        return error_page(
            StatusCode::BAD_REQUEST,
            "The login form expired or was modified. Start the connection again.",
        );
    }
    if let Some(upstream) = st.verifier.upstream() {
        return super::callback::start(&st, &v, upstream);
    }
    let label = st.verifier.label();
    let entered = st.verifier.prepare(&form.credential);
    // Input that could not be a credential is refused here without asking upstream, so it costs
    // nothing and is not counted as a failed attempt.
    if !st.verifier.plausible(entered) {
        return login_page(
            &st,
            &v,
            StatusCode::UNAUTHORIZED,
            Some(&format!("That is not a {label}.")),
        );
    }
    let verdict = match st.checks.join(credential::fingerprint(entered)) {
        Ticket::Follow(rx) => CheckRunner::follow(rx).await,
        Ticket::Lead(lead) => match st.limiter.try_reserve(ip) {
            Ok(reservation) => {
                super::middleware::settled_check(&st, entered, lead, reservation, None).await
            }
            Err(refusal) => {
                st.checks.finish(lead, super::middleware::refused());
                metrics::counter!("oauth_requests_total", "endpoint" => "authorize", "outcome" => "rate_limited").increment(1);
                return refusal_page(refusal);
            }
        },
    };
    match verdict {
        CredentialCheck::Valid => {}
        CredentialCheck::Invalid(reason) => {
            metrics::counter!("oauth_login_failures_total").increment(1);
            tracing::warn!(%ip, "oauth login failed: credential rejected");
            let message = reason.unwrap_or_else(|| format!("That {label} was not accepted."));
            return login_page(&st, &v, StatusCode::UNAUTHORIZED, Some(&message));
        }
        CredentialCheck::Unavailable(why) => {
            metrics::counter!("oauth_requests_total", "endpoint" => "authorize", "outcome" => "unavailable").increment(1);
            tracing::warn!(%ip, reason = %why, "oauth login: credential could not be checked");
            return login_page(
                &st,
                &v,
                StatusCode::SERVICE_UNAVAILABLE,
                Some(&format!(
                    "Your {label} could not be checked right now: {why}"
                )),
            );
        }
    }
    // Only a credential the tools use travels on, sealed; a password only proved who signed in.
    let sealed = if st.verifier.carried() {
        let Ok(sealed) = st.sealer.seal(entered) else {
            return error_page(StatusCode::INTERNAL_SERVER_ERROR, "token error");
        };
        Some(sealed)
    } else {
        None
    };
    let subject = st.subject_of(entered);
    grant_code(&st, &v, sealed, subject)
}

/// Issues an authorization code for the validated request `v` (with the person's sealed
/// credential, if carried, and their subject) and sends the browser back to the client. Answers
/// 303, so no user agent re-sends a form body to the client's redirect URI (RFC 9700 4.12).
pub(super) fn grant_code(
    st: &AuthState,
    v: &ValidRequest,
    sealed: Option<String>,
    subject: String,
) -> Response {
    let payload = Payload {
        client_id: Some(v.client_id.clone()),
        redirect_uri: Some(v.redirect_uri.clone()),
        code_challenge: Some(v.code_challenge.clone()),
        scope: Some(v.scope.clone()),
        resource: Some(v.resource.clone()),
        credential: sealed,
        ver: Some(st.sign_in_version().to_string()),
        auth_time: Some(jsonwebtoken::get_current_timestamp()),
        ..Default::default()
    };
    let audience = st.settings.public_url.clone();
    let Ok(code) = st.jwt.issue_as(
        TokenKind::Code,
        Some(Duration::from_secs(60)),
        payload,
        &audience,
        &subject,
    ) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "token error");
    };
    let Ok(mut url) = url::Url::parse(&v.redirect_uri) else {
        return error_page(StatusCode::BAD_REQUEST, "invalid redirect_uri");
    };
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("code", &code);
        if let Some(s) = &v.state {
            q.append_pair("state", s);
        }
        q.append_pair("iss", &st.settings.public_url);
    }
    metrics::counter!("oauth_requests_total", "endpoint" => "authorize", "outcome" => "ok")
        .increment(1);
    tracing::info!(subject = %subject, "oauth authorization granted");
    // 303 after the POST that carried the credential, so no user agent re-sends the form body
    // to the client's redirect_uri (RFC 9700 4.12).
    let mut res = Redirect::to(url.as_str()).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::Payload;
    use crate::oauth::OAuthSettings;

    fn st_with(services: &[&str]) -> std::sync::Arc<AuthState> {
        AuthState::new(
            OAuthSettings {
                public_url: "https://mail.example.com".into(),
                signing_key: "0123456789abcdef0123456789abcdef".to_string().into(),
                trusted_proxies: Vec::new(),
                static_token: None,
            },
            services,
            std::sync::Arc::new(crate::credential::PasswordVerifier::new(
                "a long password".to_string().into(),
            )),
        )
    }

    fn st() -> std::sync::Arc<AuthState> {
        st_with(&["mail"])
    }

    fn client(st: &AuthState) -> String {
        st.jwt
            .issue(
                TokenKind::Client,
                None,
                Payload {
                    redirect_uris: Some(vec!["https://app.example.com/cb".into()]),
                    ..Default::default()
                },
            )
            .unwrap()
    }

    fn params(client_id: &str) -> AuthorizeParams {
        AuthorizeParams {
            response_type: Some("code".into()),
            client_id: Some(client_id.into()),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            state: Some("xyz".into()),
            resource: Some("https://mail.example.com/mail".into()),
        }
    }

    #[test]
    fn accepts_valid_request() {
        let st = st();
        let v = validate(&st, &params(&client(&st))).unwrap();
        assert_eq!(v.redirect_uri, "https://app.example.com/cb");
        assert_eq!(v.scope, "mail");
        assert_eq!(v.resource, "https://mail.example.com/mail");
    }

    #[test]
    fn empty_state_is_treated_as_absent() {
        let st = st();
        let mut p = params(&client(&st));
        p.state = Some(String::new());
        assert_eq!(validate(&st, &p).unwrap().state, None);
    }

    #[test]
    fn missing_resource_defaults_to_the_only_service() {
        let st = st();
        let mut p = params(&client(&st));
        p.resource = None;
        let v = validate(&st, &p).unwrap();
        assert_eq!(v.resource, "https://mail.example.com/mail");
        assert_eq!(v.scope, "mail");
    }

    #[test]
    fn missing_resource_defaults_to_the_only_service_not_the_combined_endpoint() {
        let st = st_with(&["mail", crate::combined::COMBINED]);
        let mut p = params(&client(&st));
        p.resource = None;
        let v = validate(&st, &p).unwrap();
        assert_eq!(v.scope, "mail");
        p.resource = Some("https://mail.example.com/mcp".into());
        assert_eq!(validate(&st, &p).unwrap().scope, "mcp");
    }

    #[test]
    fn missing_resource_is_rejected_when_several_services_exist() {
        let st = st_with(&["mail", "calendar"]);
        let mut p = params(&client(&st));
        p.resource = None;
        assert!(matches!(
            validate(&st, &p),
            Err(Rejection::Redirect {
                error: "invalid_target",
                ..
            })
        ));
    }

    #[test]
    fn each_service_resource_grants_its_own_scope() {
        let st = st_with(&["mail", "calendar"]);
        let mut p = params(&client(&st));
        p.resource = Some("https://mail.example.com/calendar".into());
        let v = validate(&st, &p).unwrap();
        assert_eq!(v.scope, "calendar");
        assert_eq!(v.resource, "https://mail.example.com/calendar");
    }

    #[test]
    fn invalid_client_is_not_redirected() {
        let st = st();
        assert!(matches!(
            validate(&st, &params("garbage")),
            Err(Rejection::BadClient(_))
        ));
    }

    #[test]
    fn unregistered_redirect_uri_is_not_redirected() {
        let st = st();
        let mut p = params(&client(&st));
        p.redirect_uri = Some("https://evil.example.com/cb".into());
        assert!(matches!(validate(&st, &p), Err(Rejection::BadClient(_))));
    }

    #[test]
    fn plain_pkce_is_rejected_with_redirect() {
        let st = st();
        let mut p = params(&client(&st));
        p.code_challenge_method = Some("plain".into());
        assert!(matches!(
            validate(&st, &p),
            Err(Rejection::Redirect {
                error: "invalid_request",
                ..
            })
        ));
    }

    #[test]
    fn missing_challenge_is_rejected_with_redirect() {
        let st = st();
        let mut p = params(&client(&st));
        p.code_challenge = None;
        assert!(matches!(validate(&st, &p), Err(Rejection::Redirect { .. })));
    }

    #[test]
    fn wrong_response_type_is_rejected_with_redirect() {
        let st = st();
        let mut p = params(&client(&st));
        p.response_type = Some("token".into());
        assert!(matches!(
            validate(&st, &p),
            Err(Rejection::Redirect {
                error: "unsupported_response_type",
                ..
            })
        ));
    }

    #[test]
    fn wrong_resource_is_rejected_with_redirect() {
        let st = st();
        let mut p = params(&client(&st));
        for wrong in [
            "https://other.example.com/mail",
            "https://mail.example.com/mcp",
            "https://mail.example.com/calendar",
            "https://mail.example.com/mail/",
        ] {
            p.resource = Some(wrong.into());
            assert!(
                matches!(
                    validate(&st, &p),
                    Err(Rejection::Redirect {
                        error: "invalid_target",
                        ..
                    })
                ),
                "{wrong}"
            );
        }
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn client_ip_ignores_forwarded_for_from_untrusted_peer() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(client_ip(Some(peer), &xff(&["198.51.100.1"]), &[]), peer);
    }

    #[test]
    fn client_ip_takes_rightmost_untrusted_entry() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let inner: IpAddr = "10.0.0.2".parse().unwrap();
        let headers = xff(&["1.1.1.1, 198.51.100.7", "10.0.0.2"]);
        assert_eq!(
            client_ip(Some(proxy), &headers, &[proxy, inner]),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_reads_entries_with_ports() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        for (entry, want) in [
            ("198.51.100.7:5000", "198.51.100.7"),
            ("[2001:db8::7]:443", "2001:db8::7"),
            ("[2001:db8::8]", "2001:db8::8"),
        ] {
            assert_eq!(
                client_ip(Some(proxy), &xff(&[entry]), &[proxy]),
                want.parse::<IpAddr>().unwrap(),
                "{entry}"
            );
        }
    }

    #[test]
    fn client_ip_treats_ipv4_mapped_addresses_as_ipv4() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let client: IpAddr = "198.51.100.66".parse().unwrap();
        // A dual-stack listener reports an IPv4 proxy as ::ffff:10.0.0.1.
        assert_eq!(
            client_ip(Some(mapped), &xff(&["198.51.100.66"]), &[proxy]),
            client
        );
        assert_eq!(
            client_ip(Some(proxy), &xff(&["::ffff:198.51.100.66"]), &[mapped]),
            client
        );
        assert_eq!(client_ip(Some(mapped), &HeaderMap::new(), &[]), proxy);
    }

    #[test]
    fn client_ip_falls_back_to_peer_on_garbage_or_missing_header() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(
            client_ip(Some(proxy), &xff(&["not-an-ip"]), &[proxy]),
            proxy
        );
        assert_eq!(client_ip(Some(proxy), &HeaderMap::new(), &[proxy]), proxy);
    }

    #[test]
    fn binding_changes_with_any_parameter() {
        let st = st();
        let a = validate(&st, &params(&client(&st))).unwrap();
        let mut b = a.clone();
        b.state = Some("other".into());
        assert_ne!(binding(&a), binding(&b));
    }
}
