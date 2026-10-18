//! The bearer guard in front of services, and the whole OAuth flow end to end.
mod oauth_support;
use axum::Extension;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use mcp_server_core::credential::Credential;
use mcp_server_core::jwt::{Claims, Payload, TokenKind};
use mcp_server_core::server::build_app;
use oauth_support::*;
use serde_json::json;
use std::time::Duration;

/// Every enabled service of `st` (out of mail and calendar), each answering "<name>-ok".
fn full_app(st: std::sync::Arc<mcp_server_core::oauth::AuthState>) -> axum::Router {
    let services = ["mail", "calendar"]
        .into_iter()
        .filter(|name| st.has_service(name))
        .map(|name| {
            let body = format!("{name}-ok");
            (
                name,
                axum::Router::new().route("/", post(move || async move { body })),
            )
        })
        .collect();
    build_app(st, services)
}

fn call(path: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::post(path);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

fn mcp_call(token: Option<&str>) -> Request<Body> {
    call("/mail", token)
}

fn access_for(st: &mcp_server_core::oauth::AuthState, service: &str) -> String {
    st.jwt()
        .issue_for(
            TokenKind::Access,
            Some(Duration::from_secs(60)),
            Payload {
                client_id: Some("client-1".into()),
                credential: sealed(st),
                ..Default::default()
            },
            &st.resource(service),
        )
        .unwrap()
}

#[tokio::test]
async fn unauthenticated_service_gets_401_with_its_resource_metadata() {
    let app = full_app(state_two_services());
    for service in ["mail", "calendar"] {
        let res = send(&app, call(&format!("/{service}"), None)).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let h = res.headers()["www-authenticate"].to_str().unwrap();
        assert_eq!(
            h,
            format!(
                "Bearer resource_metadata=\"https://mail.example.com/.well-known/oauth-protected-resource/{service}\""
            )
        );
    }
}

#[tokio::test]
async fn access_token_reaches_its_own_service() {
    let st = state_two_services();
    let app = full_app(st.clone());
    let res = send(&app, call("/calendar", Some(&access_for(&st, "calendar")))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, "calendar-ok");
}

#[tokio::test]
async fn mail_token_is_rejected_on_calendar() {
    let st = state_two_services();
    let app = full_app(st.clone());
    let res = send(&app, call("/calendar", Some(&access_for(&st, "mail")))).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(
        res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .ends_with(", error=\"invalid_token\"")
    );
    let res = send(&app, call("/mail", Some(&access_for(&st, "calendar")))).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_without_a_resource_audience_is_rejected() {
    let st = state();
    let default_aud = st
        .jwt()
        .issue(
            TokenKind::Access,
            Some(Duration::from_secs(60)),
            Payload::default(),
        )
        .unwrap();
    assert_eq!(
        send(&full_app(st), mcp_call(Some(&default_aud)))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_credential_itself_works_as_a_bearer_on_every_service() {
    let app = full_app(state_two_services());
    for path in ["/mail", "/calendar"] {
        assert_eq!(
            send(&app, call(path, Some(KEY))).await.status(),
            StatusCode::OK,
            "{path}"
        );
    }
}

#[tokio::test]
async fn old_mcp_path_is_gone() {
    let app = full_app(state());
    assert_eq!(
        send(&app, call("/mcp", Some(KEY))).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn bearer_credentials_are_checked_once_then_cached() {
    let v = verifier();
    let app = full_app(state_with_verifier(v.clone()));
    for _ in 0..3 {
        assert_eq!(
            send(&app, mcp_call(Some(KEY))).await.status(),
            StatusCode::OK
        );
    }
    assert_eq!(v.checks(), 1);
    for _ in 0..2 {
        let res = send(&app, mcp_call(Some("wrong-key"))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert!(
            res.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .ends_with(", error=\"invalid_token\"")
        );
    }
    assert_eq!(v.checks(), 2, "a rejected credential is remembered too");
}

#[tokio::test]
async fn rejected_bearer_credentials_are_rate_limited_per_client() {
    let v = verifier();
    let app = full_app(state_with_verifier(v.clone()));
    let from = |token: &str| {
        Request::post("/mail")
            .header("authorization", format!("Bearer {token}"))
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [10, 0, 0, 7],
                5555,
            ))))
            .body(Body::empty())
            .unwrap()
    };
    for i in 0..5 {
        assert_eq!(
            send(&app, from(&format!("wrong-{i}"))).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let res = send(&app, from("wrong-5")).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(v.checks(), 5, "the blocked attempt is not sent upstream");
}

#[tokio::test]
async fn an_unavailable_check_is_503_with_retry_after() {
    let res = send(&full_app(state()), mcp_call(Some(DOWN_KEY))).await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.headers()["retry-after"], "30");
    assert!(
        body_text(res)
            .await
            .contains("could not be checked right now")
    );
}

#[tokio::test]
async fn implausible_or_expired_bearers_are_not_sent_upstream() {
    let v = verifier();
    let st = state_with_verifier(v.clone());
    let app = full_app(st.clone());
    let expired_looking = "aaa.bbb.ccc";
    for token in [expired_looking, "has space", &"x".repeat(300)] {
        let req = Request::post("/mail")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send(&app, req).await.status(),
            StatusCode::UNAUTHORIZED,
            "{token:?}"
        );
    }
    assert_eq!(v.checks(), 0);
}

#[tokio::test]
async fn access_tokens_without_a_valid_sealed_credential_are_rejected() {
    let st = state();
    let app = full_app(st.clone());
    let issue = |credential: Option<String>| {
        st.jwt()
            .issue_for(
                TokenKind::Access,
                Some(Duration::from_secs(60)),
                Payload {
                    client_id: Some("client-1".into()),
                    credential,
                    ..Default::default()
                },
                &st.resource("mail"),
            )
            .unwrap()
    };
    let other_key = mcp_server_core::credential::Sealer::new(b"some other signing key, 32 bytes")
        .seal(KEY)
        .unwrap();
    for credential in [None, Some("garbage".to_string()), Some(other_key)] {
        assert_eq!(
            send(&app, mcp_call(Some(&issue(credential.clone()))))
                .await
                .status(),
            StatusCode::UNAUTHORIZED,
            "{credential:?}"
        );
    }
}

#[tokio::test]
#[should_panic(expected = "service calendar is not registered with AuthState")]
async fn mounting_an_unregistered_service_panics() {
    let _ = build_app(
        state(),
        vec![(
            "calendar",
            axum::Router::new().route("/", post(|| async { "x" })),
        )],
    );
}

#[tokio::test]
async fn healthz_needs_no_auth() {
    let res = send(&full_app(state()), get("/healthz")).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn non_access_tokens_are_rejected() {
    let st = state();
    let app = full_app(st.clone());
    for kind in [TokenKind::Refresh, TokenKind::Code, TokenKind::Csrf] {
        let t = st
            .jwt()
            .issue(kind, Some(Duration::from_secs(60)), Payload::default())
            .unwrap();
        assert_eq!(
            send(&app, mcp_call(Some(&t))).await.status(),
            StatusCode::UNAUTHORIZED,
            "{kind:?}"
        );
    }
    let client = st
        .jwt()
        .issue(TokenKind::Client, None, Payload::default())
        .unwrap();
    assert_eq!(
        send(&app, mcp_call(Some(&client))).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn handler_gets_the_callers_credential_and_claims_only_for_oauth_tokens() {
    let st = state();
    let app = build_app(
        st.clone(),
        vec![(
            "mail",
            axum::Router::new().route(
                "/",
                post(
                    |claims: Option<Extension<Claims>>,
                     credential: Option<Extension<Credential>>| async move {
                        let who = match claims {
                            Some(Extension(c)) => c.payload.client_id.unwrap_or_default(),
                            None => "no-claims".to_string(),
                        };
                        let key = credential
                            .map(|Extension(c)| c.expose().to_string())
                            .unwrap_or_default();
                        format!("{who} {key}")
                    },
                ),
            ),
        )],
    );
    let access = access_for(&st, "mail");
    let res = send(&app, mcp_call(Some(&access))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, format!("client-1 {KEY}"));
    let res = send(&app, mcp_call(Some(KEY))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, format!("no-claims {KEY}"));
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let st = state();
    let req = Request::post("/register")
        .header("content-type", "application/json")
        .body(Body::from(vec![b' '; 2 * 1024 * 1024]))
        .unwrap();
    assert_eq!(
        send(&full_app(st), req).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn full_oauth_dance_reaches_the_requested_service_only() {
    let st = state_two_services();
    let app = full_app(st.clone());

    let reg = body_json(
        send(
            &app,
            json_post(
                "/register",
                json!({"redirect_uris": ["https://app.example.com/cb"]}),
            ),
        )
        .await,
    )
    .await;
    let cid = reg["client_id"].as_str().unwrap().to_string();

    let verifier = "dBjftJeZ4CVP-mJ92K9fwhzDHvM5HDkyX5Dw1mEtK8k";
    let challenge = mcp_server_core::pkce::s256(verifier);
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", cid.as_str()),
            ("redirect_uri", "https://app.example.com/cb"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", "s1"),
            ("resource", "https://mail.example.com/mail"),
        ])
        .finish();
    let html = body_text(send(&app, get(&format!("/authorize?{q}"))).await).await;
    let csrf_start = html.find("name=\"csrf\" value=\"").unwrap() + "name=\"csrf\" value=\"".len();
    let csrf = &html[csrf_start..csrf_start + html[csrf_start..].find('"').unwrap()];

    let res = send(
        &app,
        form_post(
            "/authorize",
            &[
                ("response_type", "code"),
                ("client_id", &cid),
                ("redirect_uri", "https://app.example.com/cb"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("state", "s1"),
                ("scope", "mail"),
                ("resource", "https://mail.example.com/mail"),
                ("csrf", csrf),
                ("credential", KEY),
            ],
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let code = loc
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();

    let tok = body_json(
        send(
            &app,
            form_post(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("client_id", &cid),
                    ("code_verifier", verifier),
                    ("redirect_uri", "https://app.example.com/cb"),
                ],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(tok["scope"], "mail");
    let access = tok["access_token"].as_str().unwrap();

    let res = send(&app, mcp_call(Some(access))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, "mail-ok");
    let res = send(&app, call("/calendar", Some(access))).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// A server whose owner signs in: OAuth tokens without a credential, and the static token.

/// Requests to `/mail` from one address.
fn from(token: &str, peer: [u8; 4]) -> Request<Body> {
    Request::post("/mail")
        .header("authorization", format!("Bearer {token}"))
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            peer, 5555,
        ))))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn the_static_token_works_on_every_service() {
    let app = full_app(owner_state(Some(STATIC_TOKEN), &["mail", "calendar"]));
    for path in ["/mail", "/calendar"] {
        assert_eq!(
            send(&app, call(path, Some(STATIC_TOKEN))).await.status(),
            StatusCode::OK,
            "{path}"
        );
    }
    assert_eq!(
        send(&app, call("/mcp", Some(STATIC_TOKEN))).await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn owner_access_tokens_need_no_credential_and_handlers_get_none() {
    let st = owner_state(None, &["mail"]);
    let app = build_app(
        st.clone(),
        vec![(
            "mail",
            axum::Router::new().route(
                "/",
                post(
                    |claims: Option<Extension<Claims>>,
                     credential: Option<Extension<Credential>>| async move {
                        format!("{} {}", claims.is_some(), credential.is_some())
                    },
                ),
            ),
        )],
    );
    let access = access_for(&st, "mail");
    let res = send(&app, mcp_call(Some(&access))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, "true false");
    let app = build_app(
        owner_state(Some(STATIC_TOKEN), &["mail"]),
        vec![(
            "mail",
            axum::Router::new().route(
                "/",
                post(
                    |claims: Option<Extension<Claims>>,
                     credential: Option<Extension<Credential>>| async move {
                        format!("{} {}", claims.is_some(), credential.is_some())
                    },
                ),
            ),
        )],
    );
    let res = send(&app, mcp_call(Some(STATIC_TOKEN))).await;
    assert_eq!(body_text(res).await, "false false");
}

#[tokio::test]
async fn the_owner_password_is_never_a_bearer_token() {
    let app = full_app(owner_state(None, &["mail"]));
    let res = send(&app, mcp_call(Some(PASSWORD))).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_static_tokens_are_rate_limited_and_then_even_the_right_one_waits() {
    let app = full_app(owner_state(Some(STATIC_TOKEN), &["mail"]));
    for i in 0..5 {
        assert_eq!(
            send(&app, from(&format!("guess-{i}"), [10, 0, 0, 8]))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let res = send(&app, from(STATIC_TOKEN, [10, 0, 0, 8])).await;
    assert_eq!(
        res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a blocked client cannot learn that a guess was right"
    );
    assert_eq!(res.headers()["retry-after"], "30");
    assert_eq!(
        send(&app, from(STATIC_TOKEN, [10, 0, 0, 9])).await.status(),
        StatusCode::OK,
        "other addresses are unaffected"
    );
}

#[tokio::test]
async fn expired_or_foreign_oauth_tokens_never_count_as_guesses() {
    let st = owner_state(Some(STATIC_TOKEN), &["mail"]);
    let app = full_app(st.clone());
    let foreign =
        mcp_server_core::jwt::Jwt::new(b"some other signing key, 32 bytes", PUBLIC_URL, PUBLIC_URL)
            .issue_for(
                TokenKind::Access,
                Some(Duration::from_secs(60)),
                Payload::default(),
                &st.resource("mail"),
            )
            .unwrap();
    for _ in 0..10 {
        assert_eq!(
            send(&app, from(&foreign, [10, 0, 0, 10])).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        send(&app, from(STATIC_TOKEN, [10, 0, 0, 10]))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
#[should_panic(
    expected = "a static token cannot be used when people sign in with their own credential"
)]
async fn a_static_token_with_carried_credentials_is_refused() {
    let _ = mcp_server_core::oauth::AuthState::new(
        mcp_server_core::oauth::OAuthSettings {
            public_url: PUBLIC_URL.into(),
            signing_key: "0123456789abcdef0123456789abcdef".to_string().into(),
            trusted_proxies: Vec::new(),
            static_token: Some(STATIC_TOKEN.to_string().into()),
        },
        &["mail"],
        verifier(),
    );
}
