//! Signing in through an upstream OAuth provider: leaving the sign-in page for the provider, and
//! `GET /callback`, where the provider sends the person back. See [`crate::upstream`].

use super::AuthState;
use super::authorize::{
    AuthorizeParams, ClientIp, ValidRequest, client_ip, error_page, grant_code, redirect_error,
    refusal_page, validate,
};
use crate::pkce;
use crate::upstream::{
    CALLBACK_PATH, Exchange, MAX_UPSTREAM_CREDENTIAL_LEN, PENDING_TTL_SECS, UpstreamSignIn,
    valid_subject,
};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Prefix of the cookie that holds a pending sign-in; the rest of its name comes from the
/// sign-in's `state`, so several sign-ins can be pending in one browser.
const COOKIE_PREFIX: &str = "mcp_pending_";
/// Characters of the state's hash in the cookie name.
const COOKIE_ID_CHARS: usize = 16;
/// Longest code or state accepted from the provider, in bytes.
const MAX_PARAM_LEN: usize = 4096;

/// The authorization request waiting for the provider, sealed into the browser's cookie.
#[derive(Serialize, Deserialize)]
struct Pending {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    resource: String,
    /// `s256` of the `state` sent to the provider.
    nonce: String,
    /// Unix seconds after which the sign-in has to start again.
    exp: u64,
}

impl Pending {
    fn params(&self) -> AuthorizeParams {
        AuthorizeParams {
            response_type: Some("code".into()),
            client_id: Some(self.client_id.clone()),
            redirect_uri: Some(self.redirect_uri.clone()),
            code_challenge: Some(self.code_challenge.clone()),
            code_challenge_method: Some("S256".into()),
            state: self.state.clone(),
            resource: Some(self.resource.clone()),
        }
    }
}

/// A fresh random `state` for the provider: 256 bits, base64url.
fn new_state() -> Option<String> {
    use base64::Engine as _;
    use ring::rand::SecureRandom as _;
    let mut raw = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut raw).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw))
}

/// The cookie name of the sign-in whose provider `state` is `state`.
fn cookie_name(state: &str) -> String {
    let hash = pkce::s256(&format!("mcp-server-core pending cookie\0{state}"));
    format!("{COOKIE_PREFIX}{}", &hash[..COOKIE_ID_CHARS])
}

/// `Set-Cookie` attributes: only sent back to the callback, never readable by scripts, sent on
/// the provider's top-level redirect (Lax) and, over https, only over https.
fn cookie_attributes(st: &AuthState, max_age: u64) -> String {
    let secure = if st.settings.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!("Path={CALLBACK_PATH}; Max-Age={max_age}; HttpOnly; SameSite=Lax{secure}")
}

/// The value of cookie `name` in the request, if it sent one.
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
}

/// Leaves the sign-in page for the provider: seals the validated request into a cookie bound to
/// a random `state` and sends the browser to the provider's authorization URL.
pub(super) fn start(st: &AuthState, v: &ValidRequest, upstream: &dyn UpstreamSignIn) -> Response {
    let Some(state) = new_state() else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "token error");
    };
    let pending = Pending {
        client_id: v.client_id.clone(),
        redirect_uri: v.redirect_uri.clone(),
        code_challenge: v.code_challenge.clone(),
        state: v.state.clone(),
        resource: v.resource.clone(),
        nonce: pkce::s256(&state),
        exp: jsonwebtoken::get_current_timestamp() + PENDING_TTL_SECS,
    };
    let sealed = serde_json::to_string(&pending)
        .ok()
        .and_then(|json| st.pending.seal(&json).ok());
    let Some(sealed) = sealed else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "token error");
    };
    let set_cookie = format!(
        "{}={sealed}; {}",
        cookie_name(&state),
        cookie_attributes(st, PENDING_TTL_SECS)
    );
    let target = upstream.authorize_url(&st.callback_url(), &state);
    metrics::counter!("oauth_requests_total", "endpoint" => "authorize", "outcome" => "upstream")
        .increment(1);
    let mut res = Redirect::to(&target).into_response();
    let h = res.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    match HeaderValue::from_str(&set_cookie) {
        Ok(v) => {
            h.insert(header::SET_COOKIE, v);
        }
        Err(_) => return error_page(StatusCode::INTERNAL_SERVER_ERROR, "token error"),
    }
    res
}

/// What the provider sends back.
#[derive(Debug, Default, Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// `response` with the pending sign-in's cookie cleared.
fn clearing(st: &AuthState, state: &str, mut response: Response) -> Response {
    let clear = format!("{}=; {}", cookie_name(state), cookie_attributes(st, 0));
    if let Ok(v) = HeaderValue::from_str(&clear) {
        response.headers_mut().append(header::SET_COOKIE, v);
    }
    response
}

const START_AGAIN: &str =
    "This sign-in expired or was started in another browser. Start connecting the client again.";

/// `GET /callback`: checks the provider's `state` against the browser's pending sign-in,
/// exchanges the code and sends the browser on to the MCP client with an authorization code.
pub async fn get_callback(
    State(st): State<Arc<AuthState>>,
    ClientIp(peer): ClientIp,
    headers: HeaderMap,
    Query(p): Query<CallbackParams>,
) -> Response {
    let Some(upstream) = st.verifier.upstream() else {
        return error_page(StatusCode::NOT_FOUND, "not found");
    };
    let provider = upstream.provider().to_string();
    let Some(state) = p
        .state
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= MAX_PARAM_LEN)
    else {
        return error_page(StatusCode::BAD_REQUEST, START_AGAIN);
    };
    let pending = cookie(&headers, &cookie_name(state))
        .and_then(|sealed| st.pending.open(sealed).ok())
        .and_then(|json| serde_json::from_str::<Pending>(json.expose()).ok())
        .filter(|p| p.exp > jsonwebtoken::get_current_timestamp())
        .filter(|p| pkce::ct_eq(&p.nonce, &pkce::s256(state)));
    let Some(pending) = pending else {
        metrics::counter!("oauth_requests_total", "endpoint" => "callback", "outcome" => "no_pending").increment(1);
        return clearing(&st, state, error_page(StatusCode::BAD_REQUEST, START_AGAIN));
    };
    // The client and its redirect URI are checked again: the pending request is the person's own,
    // but the server's services or the client's registration may have changed since.
    let v = match validate(&st, &pending.params()) {
        Ok(v) => v,
        Err(_) => {
            return clearing(&st, state, error_page(StatusCode::BAD_REQUEST, START_AGAIN));
        }
    };
    let back_to_client = |error: &str, description: &str| {
        clearing(
            &st,
            state,
            redirect_error(
                &st.settings.public_url,
                &v.redirect_uri,
                v.state.as_deref(),
                error,
                description,
                true,
            ),
        )
    };
    if let Some(error) = p.error.as_deref() {
        metrics::counter!("oauth_requests_total", "endpoint" => "callback", "outcome" => "denied")
            .increment(1);
        tracing::info!(provider = %provider, "upstream sign-in not approved");
        return if error == "access_denied" {
            back_to_client("access_denied", "access was not approved at the provider")
        } else {
            back_to_client(
                "server_error",
                "the provider could not complete the sign-in",
            )
        };
    }
    let Some(code) = p
        .code
        .as_deref()
        .filter(|c| !c.is_empty() && c.len() <= MAX_PARAM_LEN)
    else {
        return back_to_client("server_error", "the provider sent no authorization code");
    };
    let ip = client_ip(peer, &headers, &st.settings.trusted_proxies);
    let reservation = match st.limiter.try_reserve(ip) {
        Ok(r) => r,
        Err(refusal) => {
            metrics::counter!("oauth_requests_total", "endpoint" => "callback", "outcome" => "rate_limited").increment(1);
            return refusal_page(refusal);
        }
    };
    let exchanged =
        match tokio::time::timeout(super::CHECK_SLOT_WAIT, st.exchanges.clone().acquire_owned())
            .await
        {
            Ok(Ok(permit)) => {
                let redirect_uri = st.callback_url();
                let outcome = tokio::time::timeout(
                    super::CHECK_TIMEOUT,
                    upstream.exchange(code, &redirect_uri),
                )
                .await
                .unwrap_or_else(|_| {
                    Exchange::Unavailable(format!("{provider} did not answer in time"))
                });
                drop(permit);
                outcome
            }
            _ => Exchange::Unavailable("too many sign-ins are being completed at once".into()),
        };
    let grant = match exchanged {
        Exchange::Granted(grant) => {
            st.limiter.refund(reservation);
            grant
        }
        Exchange::Refused(why) => {
            st.limiter.fail(reservation);
            metrics::counter!("oauth_login_failures_total").increment(1);
            tracing::warn!(%ip, provider = %provider, "upstream sign-in refused");
            return clearing(
                &st,
                state,
                error_page(
                    StatusCode::UNAUTHORIZED,
                    &format!(
                        "{provider} did not accept this sign-in: {why} Start connecting the client again."
                    ),
                ),
            );
        }
        Exchange::Unavailable(why) => {
            st.limiter.refund(reservation);
            metrics::counter!("oauth_requests_total", "endpoint" => "callback", "outcome" => "unavailable").increment(1);
            tracing::warn!(provider = %provider, reason = %why, "upstream sign-in could not be completed");
            return clearing(
                &st,
                state,
                error_page(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &format!("The sign-in could not be completed with {provider} right now: {why}"),
                ),
            );
        }
    };
    if grant.credential.is_empty() || grant.credential.len() > MAX_UPSTREAM_CREDENTIAL_LEN {
        tracing::error!(provider = %provider, "upstream granted an empty or oversized credential");
        return clearing(
            &st,
            state,
            error_page(
                StatusCode::BAD_GATEWAY,
                "the provider's answer was not usable",
            ),
        );
    }
    let subject = match grant.subject.as_deref() {
        Some(s) if valid_subject(s) => s.to_string(),
        Some(_) => {
            tracing::error!(provider = %provider, "upstream named an unusable subject");
            return clearing(
                &st,
                state,
                error_page(
                    StatusCode::BAD_GATEWAY,
                    "the provider's answer was not usable",
                ),
            );
        }
        None => st.subject_of(&grant.credential),
    };
    let Ok(sealed) = st.sealer.seal(&grant.credential) else {
        return error_page(StatusCode::INTERNAL_SERVER_ERROR, "token error");
    };
    metrics::counter!("oauth_requests_total", "endpoint" => "callback", "outcome" => "ok")
        .increment(1);
    clearing(&st, state, grant_code(&st, &v, Some(sealed), subject))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_names_depend_on_the_state_and_are_tokens() {
        let a = cookie_name("state-a");
        let b = cookie_name("state-b");
        assert_ne!(a, b);
        assert!(a.starts_with(COOKIE_PREFIX));
        assert_eq!(a.len(), COOKIE_PREFIX.len() + COOKIE_ID_CHARS);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        );
    }

    #[test]
    fn cookies_are_found_among_others() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            HeaderValue::from_static("a=1; mcp_pending_x=v; b=2"),
        );
        h.append(header::COOKIE, HeaderValue::from_static("c=3"));
        assert_eq!(cookie(&h, "mcp_pending_x"), Some("v"));
        assert_eq!(cookie(&h, "c"), Some("3"));
        assert_eq!(cookie(&h, "mcp_pending"), None);
    }

    #[test]
    fn states_are_random_and_long() {
        let a = new_state().unwrap();
        assert_eq!(a.len(), 43);
        assert_ne!(a, new_state().unwrap());
    }
}
