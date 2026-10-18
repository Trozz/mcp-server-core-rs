use super::AuthState;
use crate::jwt::{Payload, TokenKind};
use crate::pkce;
use axum::Json;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const ACCESS_TTL: Duration = Duration::from_secs(3600);
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub resource: Option<String>,
}

fn no_store(mut res: Response) -> Response {
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn oauth_error(code: &'static str, description: &str) -> Response {
    metrics::counter!("oauth_requests_total", "endpoint" => "token", "outcome" => code)
        .increment(1);
    no_store(
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": code, "error_description": description})),
        )
            .into_response(),
    )
}

/// The service a grant is for: its stored resource must still be an enabled service, and a
/// `resource` parameter on the token request (RFC 8707) must name the same resource.
/// Errors are `(error code, description)` for `oauth_error`.
fn granted_service(
    st: &AuthState,
    stored: Option<&str>,
    requested: Option<&str>,
) -> Result<String, (&'static str, &'static str)> {
    let Some(resource) = stored else {
        return Err(("invalid_grant", "grant has no resource"));
    };
    if requested.is_some_and(|r| r != resource) {
        return Err(("invalid_target", "resource does not match the grant"));
    }
    st.service_for_resource(resource)
        .map(String::from)
        .ok_or(("invalid_target", "resource is not a service on this server"))
}

/// Who a grant is for and when they signed in, carried from the code to every token after it.
struct Grant {
    subject: String,
    auth_time: u64,
    credential: Option<String>,
}

/// Issues an access and a refresh token for `grant`. Neither outlives the grant.
fn issue_pair(st: &AuthState, client_id: String, service: String, grant: Grant) -> Response {
    let resource = st.resource(&service);
    let payload = Payload {
        client_id: Some(client_id),
        scope: Some(service.clone()),
        resource: Some(resource.clone()),
        credential: grant.credential,
        ver: Some(st.sign_in_version().to_string()),
        auth_time: Some(grant.auth_time),
        ..Default::default()
    };
    let now = jsonwebtoken::get_current_timestamp();
    let grant_left = Duration::from_secs(
        grant
            .auth_time
            .saturating_add(super::MAX_GRANT_AGE.as_secs())
            .saturating_sub(now),
    );
    let access_ttl = ACCESS_TTL.min(grant_left);
    let refresh_ttl = REFRESH_TTL.min(grant_left);
    let audience = st.settings.public_url.clone();
    let (Ok(access), Ok(refresh)) = (
        st.jwt.issue_as(
            TokenKind::Access,
            Some(access_ttl),
            payload.clone(),
            &resource,
            &grant.subject,
        ),
        st.jwt.issue_as(
            TokenKind::Refresh,
            Some(refresh_ttl),
            payload,
            &audience,
            &grant.subject,
        ),
    ) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "token error").into_response();
    };
    metrics::counter!("oauth_requests_total", "endpoint" => "token", "outcome" => "ok")
        .increment(1);
    no_store(
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": access_ttl.as_secs(),
            "refresh_token": refresh,
            "scope": service,
        }))
        .into_response(),
    )
}

fn authorization_code(st: &AuthState, req: &TokenRequest) -> Response {
    let (Some(code), Some(client_id), Some(verifier), Some(redirect_uri)) = (
        &req.code,
        &req.client_id,
        &req.code_verifier,
        &req.redirect_uri,
    ) else {
        return oauth_error(
            "invalid_request",
            "code, client_id, code_verifier and redirect_uri are required",
        );
    };
    let Ok(claims) = st.jwt.verify(code, TokenKind::Code) else {
        return oauth_error("invalid_grant", "invalid or expired code");
    };
    let p = &claims.payload;
    if p.client_id.as_deref() != Some(client_id.as_str())
        || p.redirect_uri.as_deref() != Some(redirect_uri.as_str())
    {
        return oauth_error(
            "invalid_grant",
            "code was issued to a different client or redirect_uri",
        );
    }
    if st.jwt.verify(client_id, TokenKind::Client).is_err() {
        return oauth_error("invalid_client", "unknown client");
    }
    if !p
        .code_challenge
        .as_deref()
        .is_some_and(|c| pkce::verify(verifier, c))
    {
        return oauth_error("invalid_grant", "PKCE verification failed");
    }
    let service = match granted_service(st, p.resource.as_deref(), req.resource.as_deref()) {
        Ok(s) => s,
        Err((code, description)) => return oauth_error(code, description),
    };
    let Ok(credential) = sealed_credential(st, p.credential.as_deref()) else {
        return oauth_error("invalid_grant", "grant has no credential");
    };
    if !st.grant_is_current(&claims) {
        return oauth_error("invalid_grant", "sign in again");
    }
    if !st.replay.first_use(&claims.jti, claims.exp.unwrap_or(0)) {
        tracing::warn!("authorization code replay rejected");
        return oauth_error("invalid_grant", "code already used");
    }
    let grant = Grant {
        subject: claims.sub.clone(),
        auth_time: p.auth_time.unwrap_or_default(),
        credential,
    };
    issue_pair(st, client_id.clone(), service, grant)
}

/// The sealed credential a grant passes on: when credentials are carried it must be present and
/// still open with the current key (`Err` otherwise); when they are not, there is none.
fn sealed_credential(st: &AuthState, sealed: Option<&str>) -> Result<Option<String>, ()> {
    if !st.verifier.carried() {
        return Ok(None);
    }
    let sealed = sealed.ok_or(())?;
    st.sealer.open(sealed).map_err(|_| ())?;
    Ok(Some(sealed.to_string()))
}

fn refresh(st: &AuthState, req: &TokenRequest) -> Response {
    let (Some(token), Some(req_client_id)) = (&req.refresh_token, &req.client_id) else {
        return oauth_error(
            "invalid_request",
            "refresh_token and client_id are required",
        );
    };
    let Ok(claims) = st.jwt.verify(token, TokenKind::Refresh) else {
        return oauth_error("invalid_grant", "invalid or expired refresh token");
    };
    let Some(client_id) = claims.payload.client_id.clone() else {
        return oauth_error("invalid_grant", "refresh token has no client");
    };
    if *req_client_id != client_id {
        return oauth_error(
            "invalid_grant",
            "refresh token was issued to a different client",
        );
    }
    if st.jwt.verify(&client_id, TokenKind::Client).is_err() {
        return oauth_error("invalid_client", "unknown client");
    }
    let service = match granted_service(
        st,
        claims.payload.resource.as_deref(),
        req.resource.as_deref(),
    ) {
        Ok(s) => s,
        Err((code, description)) => return oauth_error(code, description),
    };
    let Ok(credential) = sealed_credential(st, claims.payload.credential.as_deref()) else {
        return oauth_error("invalid_grant", "grant has no credential");
    };
    if !st.grant_is_current(&claims) {
        return oauth_error("invalid_grant", "sign in again");
    }
    let grant = Grant {
        subject: claims.sub.clone(),
        auth_time: claims.payload.auth_time.unwrap_or_default(),
        credential,
    };
    issue_pair(st, client_id, service, grant)
}

pub async fn token(
    State(st): State<Arc<AuthState>>,
    req: Result<Form<TokenRequest>, FormRejection>,
) -> Response {
    let req = match req {
        Ok(Form(req)) => req,
        Err(r) if r.status() == StatusCode::PAYLOAD_TOO_LARGE => return r.into_response(),
        Err(_) => {
            return oauth_error(
                "invalid_request",
                "send a form with grant_type and each parameter at most once",
            );
        }
    };
    match req.grant_type.as_str() {
        "authorization_code" => authorization_code(&st, &req),
        "refresh_token" => refresh(&st, &req),
        _ => oauth_error(
            "unsupported_grant_type",
            "use authorization_code or refresh_token",
        ),
    }
}
