use super::AuthState;
use super::authorize::client_ip;
use crate::caller::{Caller, STATIC_SUBJECT, Via};
use crate::credential::{self, Credential, CredentialCheck};
use crate::credential::{CheckRunner, Lead, Ticket};
use crate::guards::{Refusal, Reservation};
use crate::jwt::TokenKind;
use crate::pkce;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use secrecy::ExposeSecret;
use std::net::SocketAddr;
use std::sync::Arc;

fn unauthorized(st: &AuthState, service: &str, token_present: bool) -> Response {
    let mut value = format!(
        "Bearer resource_metadata=\"{}\"",
        st.resource_metadata_url(service)
    );
    if token_present {
        value.push_str(", error=\"invalid_token\"");
    }
    let mut res = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(v) = HeaderValue::from_str(&value) {
        res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
    }
    res
}

fn unavailable(st: &AuthState, why: &str) -> Response {
    let body = format!(
        "Your {} could not be checked right now: {why}",
        st.verifier.label()
    );
    let mut res = (StatusCode::SERVICE_UNAVAILABLE, body).into_response();
    res.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    res
}

/// Seconds a client is asked to wait after being refused for too many attempts.
pub(crate) const RETRY_AFTER_SECS: &str = "30";

/// 429 for a client with too many rejected credentials, or too many checks in flight.
fn too_many_attempts() -> Response {
    let mut res = (
        StatusCode::TOO_MANY_REQUESTS,
        "Too many attempts from this address: credentials or tokens were rejected, or several \
         are being checked at once. Try again shortly.",
    )
        .into_response();
    res.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_static(RETRY_AFTER_SECS),
    );
    res
}

/// Why a credential cannot be checked while the server refuses new addresses during an attack.
pub(crate) const BUSY: &str =
    "the server is refusing new addresses while it is under heavy load; try again shortly";

/// The response for a refused attempt.
fn refusal_response(st: &AuthState, refusal: Refusal) -> Response {
    match refusal {
        Refusal::Busy => unavailable(st, BUSY),
        _ => too_many_attempts(),
    }
}

/// The verdict followers get when their lead was refused for too many attempts.
pub(crate) fn refused() -> CredentialCheck {
    CredentialCheck::Unavailable("too many attempts from this address; try again shortly".into())
}

/// Runs `lead`'s upstream check and settles what the attempt cost, in a task of its own so the
/// outcome is recorded even if the client goes away mid-check: the reservation is kept only for
/// a rejection and given back otherwise, and with `cache` the verdict is remembered.
pub(crate) async fn settled_check(
    st: &Arc<AuthState>,
    credential: &str,
    lead: Lead,
    reservation: Reservation,
    cache: Option<[u8; 32]>,
) -> CredentialCheck {
    let task = {
        let st = st.clone();
        let credential = credential.to_owned();
        tokio::spawn(async move {
            let verdict = st
                .checks
                .lead(lead, st.verifier.as_ref(), &credential)
                .await;
            let rejected = matches!(verdict, CredentialCheck::Invalid(_));
            if rejected {
                st.limiter.fail(reservation);
            } else {
                st.limiter.refund(reservation);
            }
            if let Some(fp) = cache
                && !matches!(verdict, CredentialCheck::Unavailable(_))
            {
                st.bearer_checks.put(fp, !rejected);
            }
            verdict
        })
    };
    task.await
        .unwrap_or_else(|_| CredentialCheck::Unavailable("the check stopped unexpectedly".into()))
}

/// The token of an `Authorization: Bearer <token>` value. The scheme is case-insensitive.
fn bearer_token(value: &str) -> Option<&str> {
    let (scheme, rest) = value.trim().split_once(|c: char| c.is_ascii_whitespace())?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| rest.trim())
        .filter(|t| !t.is_empty())
}

/// An OAuth token from this server is a JWT; a credential sent directly is not.
fn looks_like_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

/// Guards one service path. It lets a request through with:
///
/// - an OAuth access token this server issued for this service, whose grant still holds (see
///   [`AuthState::sign_in_version`]). When the verifier carries credentials, the token's sealed
///   credential is opened and added as a [`Credential`] extension;
/// - the static token (`MCP_AUTH_TOKEN`), when one is configured;
/// - when the verifier [accepts bearer credentials](crate::credential::CredentialVerifier::accepts_bearer),
///   the person's credential itself, checked with the verifier (the verdict is cached briefly
///   under its fingerprint) and added as a [`Credential`] extension.
///
/// Every request let through gets a [`Caller`] extension; one with an OAuth token also gets its
/// [`Claims`](crate::jwt::Claims). Anything else gets 401 with a `WWW-Authenticate` header naming
/// the service's resource metadata, as MCP clients expect. Wrong static tokens and rejected
/// credentials count towards the per-address sign-in limit; tokens this server issued never do,
/// even expired ones, and are never sent upstream.
pub async fn require_bearer(
    State((st, service)): State<(Arc<AuthState>, String)>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
        .map(str::to_owned);
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return unauthorized(&st, &service, false);
    };

    // 1. An OAuth token from this server.
    if looks_like_jwt(&token) {
        if let Ok(claims) = st
            .jwt
            .verify_for(&token, TokenKind::Access, &st.resource(&service))
        {
            if !st.grant_is_current(&claims) {
                return unauthorized(&st, &service, true);
            }
            if st.verifier.carried() {
                let Some(credential) = claims
                    .payload
                    .credential
                    .as_deref()
                    .and_then(|sealed| st.sealer.open(sealed).ok())
                else {
                    return unauthorized(&st, &service, true);
                };
                req.extensions_mut().insert(credential);
            }
            let caller = Caller::new(
                claims.sub.clone(),
                Via::OAuth {
                    client_id: claims.payload.client_id.clone(),
                },
            );
            req.extensions_mut().insert(caller);
            req.extensions_mut().insert(claims);
            return next.run(req).await;
        }
        // Expired, for another service, or signed under an old key or sign-in: never a guess at
        // anything else, and never forwarded upstream.
        if st.jwt.claims_issuer_here(&token) || !st.verifier.accepts_bearer() {
            return unauthorized(&st, &service, true);
        }
    }

    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = client_ip(peer, req.headers(), &st.settings.trusted_proxies);

    // 2. The static token. Its verifier never accepts bearer credentials (AuthState::new
    // enforces it), so a miss here is a wrong guess: the attempt is counted before comparing.
    if let Some(expected) = &st.settings.static_token {
        let reservation = match st.limiter.try_reserve(ip) {
            Ok(r) => r,
            Err(refusal) => {
                metrics::counter!("bearer_credential_checks_total", "outcome" => "rate_limited")
                    .increment(1);
                return refusal_response(&st, refusal);
            }
        };
        if pkce::ct_eq(&token, expected.expose_secret()) {
            st.limiter.refund(reservation);
            req.extensions_mut()
                .insert(Caller::new(STATIC_SUBJECT, Via::StaticToken));
            return next.run(req).await;
        }
        st.limiter.fail(reservation);
        tracing::warn!(%ip, "wrong static token rejected");
        return unauthorized(&st, &service, true);
    }

    // 3. The person's own credential.
    if !st.verifier.accepts_bearer() {
        // Nothing to guess at: refused without counting, so junk cannot lock anyone out.
        return unauthorized(&st, &service, true);
    }
    let token = st.verifier.prepare(&token).to_owned();
    if !st.verifier.plausible(&token) {
        return unauthorized(&st, &service, true);
    }
    let fingerprint = credential::fingerprint(&token);
    match st.bearer_checks.get(&fingerprint) {
        // A credential found valid recently: its holder has already proved possession, so a
        // blocked address that shares it (say, behind one NAT) is still let in.
        Some(true) => {}
        Some(false) => return unauthorized(&st, &service, true),
        None => {
            // A request arriving while the same credential is being checked follows that check
            // and is not counted again. The request that leads the check counts before anything
            // goes upstream, so concurrent attempts cannot get past the limit.
            let verdict = match st.checks.join(fingerprint) {
                Ticket::Follow(rx) => CheckRunner::follow(rx).await,
                Ticket::Lead(lead) => match st.limiter.try_reserve(ip) {
                    Ok(reservation) => {
                        settled_check(&st, &token, lead, reservation, Some(fingerprint)).await
                    }
                    Err(refusal) => {
                        st.checks.finish(lead, refused());
                        metrics::counter!("bearer_credential_checks_total", "outcome" => "rate_limited")
                            .increment(1);
                        return refusal_response(&st, refusal);
                    }
                },
            };
            match verdict {
                CredentialCheck::Valid => {
                    metrics::counter!("bearer_credential_checks_total", "outcome" => "valid")
                        .increment(1);
                }
                CredentialCheck::Invalid(_) => {
                    metrics::counter!("bearer_credential_checks_total", "outcome" => "invalid")
                        .increment(1);
                    tracing::warn!(%ip, "bearer credential rejected");
                    return unauthorized(&st, &service, true);
                }
                CredentialCheck::Unavailable(why) => {
                    metrics::counter!("bearer_credential_checks_total", "outcome" => "unavailable")
                        .increment(1);
                    tracing::warn!(reason = %why, "bearer credential could not be checked");
                    return unavailable(&st, &why);
                }
            }
        }
    }
    let subject = st.verifier.subject(&token);
    req.extensions_mut()
        .insert(Caller::new(subject, Via::Credential));
    if st.verifier.carried() {
        req.extensions_mut().insert(Credential::new(token));
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::bearer_token;

    #[test]
    fn the_bearer_scheme_is_case_insensitive() {
        for v in ["Bearer abc", "bearer abc", "BEARER  abc ", "Bearer\tabc"] {
            assert_eq!(bearer_token(v), Some("abc"), "{v:?}");
        }
        for v in ["Basic abc", "Bearer", "Bearer   ", "Bearerabc", ""] {
            assert_eq!(bearer_token(v), None, "{v:?}");
        }
    }
}
