use super::AuthState;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::sync::Arc;

pub async fn protected_resource(
    State(st): State<Arc<AuthState>>,
    Path(service): Path<String>,
) -> Response {
    if !st.has_service(&service) {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(json!({
        "resource": st.resource(&service),
        "authorization_servers": [st.settings.public_url],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [service],
    }))
    .into_response()
}

pub async fn authorization_server(State(st): State<Arc<AuthState>>) -> Json<Value> {
    let base = &st.settings.public_url;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "registration_endpoint": format!("{base}/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": st.services(),
    }))
}
