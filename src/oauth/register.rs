use super::AuthState;
use crate::jwt::{Payload, TokenKind};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
}

/// Whether a client may register `uri` as a redirect URI: `https` with a host, or `http` on a
/// loopback host (RFC 8252 native apps), without a fragment or user information.
pub fn validate_redirect_uri(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri) else {
        return false;
    };
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        _ => false,
    }
}

fn error(code: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": code, "error_description": description})),
    )
        .into_response()
}

pub async fn register(
    State(st): State<Arc<AuthState>>,
    Json(req): Json<RegisterRequest>,
) -> Response {
    if req.redirect_uris.is_empty() || !req.redirect_uris.iter().all(|u| validate_redirect_uri(u)) {
        metrics::counter!("oauth_requests_total", "endpoint" => "register", "outcome" => "invalid")
            .increment(1);
        return error(
            "invalid_redirect_uri",
            "redirect_uris must be https, or http on a loopback host, without fragments or userinfo",
        );
    }
    let payload = Payload {
        redirect_uris: Some(req.redirect_uris.clone()),
        client_name: req.client_name.clone(),
        ..Default::default()
    };
    let Ok(client_id) = st.jwt.issue(TokenKind::Client, None, payload) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "token error").into_response();
    };
    metrics::counter!("oauth_requests_total", "endpoint" => "register", "outcome" => "ok")
        .increment(1);
    tracing::info!(
        client_name = req.client_name.as_deref().unwrap_or(""),
        "oauth client registered"
    );
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "client_id_issued_at": jsonwebtoken::get_current_timestamp(),
            "client_name": req.client_name,
            "redirect_uris": req.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })),
    )
        .into_response()
}
