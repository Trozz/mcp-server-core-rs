//! Grants end when the sign-in changes or grows old, tokens do not cross sign-in modes, the
//! registration endpoint caps its input, and responses carry the issuer and security headers.
mod oauth_support;
use axum::Extension;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use mcp_server_core::caller::{Caller, Via};
use mcp_server_core::credential::PasswordVerifier;
use mcp_server_core::jwt::{Payload, TokenKind};
use mcp_server_core::oauth::{AuthState, MAX_GRANT_AGE, OAuthSettings};
use mcp_server_core::server::build_app;
use oauth_support::*;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

const REDIRECT: &str = "https://app.example.com/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// `mail` on a server whose owner's password is `password`.
fn owner_with(password: &str) -> Arc<AuthState> {
    AuthState::new(
        OAuthSettings {
            public_url: PUBLIC_URL.into(),
            signing_key: "0123456789abcdef0123456789abcdef".to_string().into(),
            trusted_proxies: Vec::new(),
            static_token: None,
        },
        &["mail"],
        Arc::new(PasswordVerifier::new(password.to_string().into())),
    )
}

/// `/mail` answering with the caller's subject and how they got in.
fn echo_app(st: Arc<AuthState>) -> axum::Router {
    build_app(
        st,
        vec![(
            "mail",
            axum::Router::new().route(
                "/",
                post(|caller: Extension<Caller>| async move {
                    let via = match &caller.via {
                        Via::OAuth { client_id } => {
                            format!("oauth {}", client_id.as_deref().unwrap_or(""))
                        }
                        Via::Credential => "credential".into(),
                        Via::StaticToken => "static".into(),
                        _ => "other".into(),
                    };
                    format!("{} {via}", caller.subject)
                }),
            ),
        )],
    )
}

fn bearer(token: &str) -> Request<Body> {
    Request::post("/mail")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn client(st: &AuthState) -> String {
    st.jwt()
        .issue(
            TokenKind::Client,
            None,
            Payload {
                redirect_uris: Some(vec![REDIRECT.into()]),
                ..Default::default()
            },
        )
        .unwrap()
}

/// An authorization code for `mail`, minted by `st` with `payload` on top of a valid grant.
fn code(st: &AuthState, cid: &str, subject: &str, payload: Payload) -> String {
    st.jwt()
        .issue_as(
            TokenKind::Code,
            Some(Duration::from_secs(60)),
            Payload {
                client_id: Some(cid.into()),
                redirect_uri: Some(REDIRECT.into()),
                code_challenge: Some(CHALLENGE.into()),
                scope: Some("mail".into()),
                resource: Some(format!("{PUBLIC_URL}/mail")),
                ..payload
            },
            PUBLIC_URL,
            subject,
        )
        .unwrap()
}

fn exchange(code: &str, cid: &str) -> Request<Body> {
    form_post(
        "/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", cid),
            ("code_verifier", VERIFIER),
            ("redirect_uri", REDIRECT),
        ],
    )
}

fn refresh(token: &str, cid: &str) -> Request<Body> {
    form_post(
        "/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", token),
            ("client_id", cid),
        ],
    )
}

#[tokio::test]
async fn a_new_owner_password_ends_every_earlier_grant() {
    let before = owner_with("the first long password");
    let cid = client(&before);
    let tokens = body_json(
        send(
            &echo_app(before.clone()),
            exchange(&code(&before, &cid, "owner", grant(&before)), &cid),
        )
        .await,
    )
    .await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh_token = tokens["refresh_token"].as_str().unwrap();
    let res = send(&echo_app(before.clone()), bearer(access)).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, format!("owner oauth {cid}"));

    let after = owner_with("the second long password");
    assert_ne!(before.sign_in_version(), after.sign_in_version());
    let app = echo_app(after.clone());
    assert_eq!(
        send(&app, bearer(access)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let res = send(&app, refresh(refresh_token, &cid)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(res).await["error_description"], "sign in again");
    let old_code = code(&before, &cid, "owner", grant(&before));
    let res = send(&app, exchange(&old_code, &cid)).await;
    assert_eq!(body_json(res).await["error_description"], "sign in again");
}

#[tokio::test]
async fn tokens_from_per_person_sign_in_are_refused_by_an_owner_server() {
    let per_person = state();
    let owner = owner_with("a long password here");
    let access = per_person
        .jwt()
        .issue_as(
            TokenKind::Access,
            Some(Duration::from_secs(60)),
            grant(&per_person),
            &per_person.resource("mail"),
            "key:0123456789abcdef",
        )
        .unwrap();
    assert_eq!(
        send(&echo_app(per_person.clone()), bearer(&access))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&echo_app(owner), bearer(&access)).await.status(),
        StatusCode::UNAUTHORIZED,
        "same key and URL, other sign-in mode"
    );
}

#[tokio::test]
async fn grants_end_a_fixed_time_after_sign_in_however_often_they_are_refreshed() {
    let st = state();
    let cid = client(&st);
    let app = echo_app(st.clone());
    let signed_in = jsonwebtoken_now() - MAX_GRANT_AGE.as_secs() + 3600;
    let near_the_end = Payload {
        auth_time: Some(signed_in),
        ..grant(&st)
    };
    let tokens = body_json(
        send(
            &app,
            exchange(&code(&st, &cid, "key:x", near_the_end), &cid),
        )
        .await,
    )
    .await;
    let refresh_token = tokens["refresh_token"].as_str().unwrap();
    let claims = st.jwt().verify(refresh_token, TokenKind::Refresh).unwrap();
    let left = claims.exp.unwrap() - jsonwebtoken_now();
    assert!(
        left <= 3600,
        "the refresh token ends with the grant: {left}s"
    );
    assert_eq!(claims.payload.auth_time, Some(signed_in));
    assert_eq!(claims.sub, "key:x");

    let too_old = Payload {
        auth_time: Some(jsonwebtoken_now() - MAX_GRANT_AGE.as_secs() - 1),
        ..grant(&st)
    };
    let res = send(&app, exchange(&code(&st, &cid, "key:x", too_old), &cid)).await;
    assert_eq!(body_json(res).await["error_description"], "sign in again");
}

#[tokio::test]
async fn grants_without_a_version_or_sign_in_time_are_refused() {
    let st = owner_with("a long password here");
    let cid = client(&st);
    let app = echo_app(st.clone());
    for payload in [
        Payload {
            ver: None,
            ..grant(&st)
        },
        Payload {
            auth_time: None,
            ..grant(&st)
        },
        Payload {
            ver: Some("not-the-version".into()),
            ..grant(&st)
        },
    ] {
        let res = send(&app, exchange(&code(&st, &cid, "owner", payload), &cid)).await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn callers_are_named_without_revealing_credentials() {
    let app = echo_app(state());
    let res = send(&app, bearer(KEY)).await;
    let text = body_text(res).await;
    assert!(
        text.starts_with("key:") && text.ends_with(" credential"),
        "{text}"
    );
    assert!(!text.contains(KEY));
    let app = echo_app(owner_state(Some(STATIC_TOKEN), &["mail"]));
    assert_eq!(
        body_text(send(&app, bearer(STATIC_TOKEN)).await).await,
        "static static"
    );
}

#[tokio::test]
async fn sign_in_sends_the_issuer_with_the_code_and_as_the_tokens_subject() {
    let st = owner_with("a long password here");
    let app = oauth_router(st.clone());
    let cid = client(&st);
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", cid.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("resource", "https://mail.example.com/mail"),
        ])
        .finish();
    let html = body_text(send(&app, get(&format!("/authorize?{q}"))).await).await;
    let csrf_at = html.find("name=\"csrf\" value=\"").unwrap() + 19;
    let csrf = &html[csrf_at..csrf_at + html[csrf_at..].find('"').unwrap()];
    let res = send(
        &app,
        form_post(
            "/authorize",
            &[
                ("response_type", "code"),
                ("client_id", &cid),
                ("redirect_uri", REDIRECT),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
                ("resource", "https://mail.example.com/mail"),
                ("csrf", csrf),
                ("credential", "a long password here"),
            ],
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let q: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    assert_eq!(q["iss"], PUBLIC_URL);
    let code = st.jwt().verify(&q["code"], TokenKind::Code).unwrap();
    assert_eq!(code.sub, "owner");
    assert_eq!(code.payload.ver.as_deref(), Some(st.sign_in_version()));
    assert!(code.payload.auth_time.is_some());

    let bad = q_with(&cid, "plain");
    let res = send(&app, get(&format!("/authorize?{bad}"))).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(
        loc.query_pairs()
            .any(|(k, v)| k == "iss" && v == PUBLIC_URL)
    );

    let meta = body_json(send(&app, get("/.well-known/oauth-authorization-server")).await).await;
    assert_eq!(meta["authorization_response_iss_parameter_supported"], true);
}

fn q_with(cid: &str, method: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", cid),
            ("redirect_uri", REDIRECT),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", method),
            ("resource", "https://mail.example.com/mail"),
        ])
        .finish()
}

fn oauth_router(st: Arc<AuthState>) -> axum::Router {
    mcp_server_core::oauth::oauth_router(st)
}

#[tokio::test]
async fn registration_input_is_capped() {
    let app = echo_app(state());
    let uris = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| format!("https://app.example.com/{i}"))
            .collect()
    };
    for (body, ok) in [
        (json!({"redirect_uris": uris(10)}), true),
        (json!({"redirect_uris": uris(11)}), false),
        (
            json!({"redirect_uris": [format!("https://app.example.com/{}", "a".repeat(2100))]}),
            false,
        ),
        (
            json!({"redirect_uris": uris(1), "client_name": "x".repeat(200)}),
            true,
        ),
        (
            json!({"redirect_uris": uris(1), "client_name": "x".repeat(201)}),
            false,
        ),
        (
            json!({"redirect_uris": uris(1), "client_name": "bad\nname"}),
            false,
        ),
    ] {
        let res = send(&app, json_post("/register", body.clone())).await;
        assert_eq!(res.status().is_success(), ok, "{body}");
    }
}

#[tokio::test]
async fn every_response_says_nosniff() {
    let app = echo_app(state());
    for req in [
        get("/healthz"),
        bearer("nope"),
        get("/.well-known/oauth-authorization-server"),
    ] {
        let res = send(&app, req).await;
        assert_eq!(res.headers()["x-content-type-options"], "nosniff");
    }
}

#[tokio::test]
#[should_panic(expected = "MCP_AUTH_TOKEN cannot be used when people sign in with their own")]
async fn a_static_token_is_refused_next_to_a_verifier_that_takes_bearer_credentials() {
    use mcp_server_core::credential::{CheckFuture, CredentialCheck, CredentialVerifier};
    /// Not carried, but accepts bearer credentials: a wrong static token would be tried as one.
    struct Lenient;
    impl CredentialVerifier for Lenient {
        fn label(&self) -> &str {
            "pass"
        }
        fn check<'a>(&'a self, _: &'a str) -> CheckFuture<'a> {
            Box::pin(async { CredentialCheck::Invalid(None) })
        }
        fn carried(&self) -> bool {
            false
        }
        fn accepts_bearer(&self) -> bool {
            true
        }
    }
    let _ = AuthState::new(
        OAuthSettings {
            public_url: PUBLIC_URL.into(),
            signing_key: "0123456789abcdef0123456789abcdef".to_string().into(),
            trusted_proxies: Vec::new(),
            static_token: Some(STATIC_TOKEN.to_string().into()),
        },
        &["mail"],
        Arc::new(Lenient),
    );
}
