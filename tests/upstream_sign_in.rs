//! Signing in through an upstream OAuth provider, end to end: the consent page, the redirect to
//! the provider, `/callback`, the code exchange and tools receiving the provider's credential.
mod oauth_support;
use axum::Extension;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use mcp_server_core::credential::{Credential, CredentialVerifier};
use mcp_server_core::server::build_app;
use mcp_server_core::upstream::{
    Exchange, ExchangeFuture, UpstreamGrant, UpstreamSignIn, UpstreamVerifier,
};
use oauth_support::*;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const CLIENT_REDIRECT: &str = "https://app.example.com/cb";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mJ92K9fwhzDHvM5HDkyX5Dw1mEtK8k";

/// A provider that grants `refresh-<code>` for codes starting with `good`, refuses `bad` codes
/// and is down for `down` codes. Records the redirect URI it was given.
struct Provider {
    exchanges: AtomicUsize,
    subject: Option<&'static str>,
}

impl UpstreamSignIn for Provider {
    fn provider(&self) -> &str {
        "Ledger"
    }
    fn authorize_url(&self, redirect_uri: &str, state: &str) -> String {
        let mut url = url::Url::parse("https://ledger.example.com/approve").unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", "server-client")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state);
        url.into()
    }
    fn exchange<'a>(&'a self, code: &'a str, redirect_uri: &'a str) -> ExchangeFuture<'a> {
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        assert_eq!(redirect_uri, "https://mail.example.com/callback");
        let outcome = if code.starts_with("good") {
            let grant = UpstreamGrant::new(format!("refresh-{code}"));
            Exchange::Granted(match self.subject {
                Some(s) => grant.with_subject(s),
                None => grant,
            })
        } else if code == "down" {
            Exchange::Unavailable("the ledger is down".into())
        } else {
            Exchange::Refused("that code has expired.".into())
        };
        Box::pin(async move { outcome })
    }
}

fn provider_state(subject: Option<&'static str>) -> Arc<mcp_server_core::oauth::AuthState> {
    let verifier = UpstreamVerifier::new(
        "Ledger account",
        Provider {
            exchanges: AtomicUsize::new(0),
            subject,
        },
    )
    .with_help("Sign in with the Ledger account whose books you want to use.");
    state_for(Arc::new(verifier), &["mail"])
}

/// `/mail` answers with the credential its tools received.
fn full_app(st: Arc<mcp_server_core::oauth::AuthState>) -> axum::Router {
    let mail = axum::Router::new().route(
        "/",
        post(|Extension(c): Extension<Credential>| async move { c.expose().to_string() }),
    );
    build_app(st, vec![("mail", mail)])
}

async fn register(app: &axum::Router) -> String {
    let reg = body_json(
        send(
            app,
            json_post(
                "/register",
                json!({"redirect_uris": [CLIENT_REDIRECT], "client_name": "Test client"}),
            ),
        )
        .await,
    )
    .await;
    reg["client_id"].as_str().unwrap().to_string()
}

fn request_pairs<'a>(cid: &'a str, challenge: &'a str) -> Vec<(&'static str, &'a str)> {
    vec![
        ("response_type", "code"),
        ("client_id", cid),
        ("redirect_uri", CLIENT_REDIRECT),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", "client-state"),
        ("resource", "https://mail.example.com/mail"),
    ]
}

/// Opens the consent page and continues to the provider: the provider URL and the cookie set.
async fn leave_for_provider(app: &axum::Router, cid: &str) -> (url::Url, String) {
    let challenge = mcp_server_core::pkce::s256(PKCE_VERIFIER);
    let pairs = request_pairs(cid, &challenge);
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(&pairs)
        .finish();
    let html = body_text(send(app, get(&format!("/authorize?{q}"))).await).await;
    assert!(html.contains("Continue to Ledger"), "{html}");
    assert!(!html.contains("name=\"credential\""), "{html}");
    assert!(html.contains("Test client"), "{html}");
    assert!(html.contains("app.example.com"), "{html}");
    let csrf_start = html.find("name=\"csrf\" value=\"").unwrap() + "name=\"csrf\" value=\"".len();
    let csrf = html[csrf_start..csrf_start + html[csrf_start..].find('"').unwrap()].to_string();
    let mut form = pairs.clone();
    form.push(("scope", "mail"));
    form.push(("csrf", &csrf));
    let res = send(app, form_post("/authorize", &form)).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let to = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let set_cookie = res.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Lax"), "{set_cookie}");
    assert!(set_cookie.contains("Path=/callback"), "{set_cookie}");
    assert!(set_cookie.contains("Secure"), "{set_cookie}");
    let cookie = set_cookie.split(';').next().unwrap().to_string();
    (to, cookie)
}

fn param(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn callback(query: &[(&str, &str)], cookie: Option<&str>) -> Request<Body> {
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    let mut b = Request::get(format!("/callback?{q}")).extension(axum::extract::ConnectInfo(
        std::net::SocketAddr::from(([10, 0, 0, 1], 5555)),
    ));
    if let Some(c) = cookie {
        b = b.header("cookie", format!("other=1; {c}"));
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn people_sign_in_at_the_provider_and_tools_receive_its_credential() {
    let st = provider_state(Some("ledger:user:7"));
    let app = full_app(st.clone());
    let cid = register(&app).await;
    let (to, cookie) = leave_for_provider(&app, &cid).await;
    assert_eq!(to.host_str(), Some("ledger.example.com"));
    assert_eq!(
        param(&to, "redirect_uri").as_deref(),
        Some("https://mail.example.com/callback")
    );
    let state = param(&to, "state").unwrap();
    assert_eq!(state.len(), 43);

    let res = send(
        &app,
        callback(&[("code", "good-1"), ("state", &state)], Some(&cookie)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let cleared = res.headers()["set-cookie"].to_str().unwrap();
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    let back = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(back.as_str().starts_with(CLIENT_REDIRECT));
    assert_eq!(param(&back, "state").as_deref(), Some("client-state"));
    assert_eq!(
        param(&back, "iss").as_deref(),
        Some("https://mail.example.com")
    );
    let code = param(&back, "code").unwrap();

    let tok = body_json(
        send(
            &app,
            form_post(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("client_id", &cid),
                    ("code_verifier", PKCE_VERIFIER),
                    ("redirect_uri", CLIENT_REDIRECT),
                ],
            ),
        )
        .await,
    )
    .await;
    let access = tok["access_token"].as_str().unwrap();
    let claims = st
        .jwt()
        .verify_for(
            access,
            mcp_server_core::jwt::TokenKind::Access,
            "https://mail.example.com/mail",
        )
        .unwrap();
    assert_eq!(claims.sub, "ledger:user:7");
    assert!(
        !access.contains("refresh-good-1"),
        "the credential is sealed"
    );

    let res = send(
        &app,
        Request::post("/mail")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_text(res).await, "refresh-good-1");

    // The provider's code cannot be replayed: the pending sign-in is gone with its cookie, and
    // the cookie alone was single-use in the browser.
    let res = send(
        &app,
        callback(&[("code", "good-1"), ("state", &state)], None),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn without_a_subject_people_are_named_from_the_credential() {
    let st = provider_state(None);
    let app = full_app(st.clone());
    let cid = register(&app).await;
    let (to, cookie) = leave_for_provider(&app, &cid).await;
    let state = param(&to, "state").unwrap();
    let res = send(
        &app,
        callback(&[("code", "good-2"), ("state", &state)], Some(&cookie)),
    )
    .await;
    let back = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let code = param(&back, "code").unwrap();
    let claims = st
        .jwt()
        .verify(&code, mcp_server_core::jwt::TokenKind::Code)
        .unwrap();
    assert_eq!(claims.sub, st.subject_of("refresh-good-2"));
    assert!(claims.sub.starts_with("key:"));
}

#[tokio::test]
async fn a_callback_needs_the_browser_that_started_the_sign_in() {
    let st = provider_state(None);
    let app = full_app(st.clone());
    let cid = register(&app).await;
    let (to, cookie) = leave_for_provider(&app, &cid).await;
    let state = param(&to, "state").unwrap();
    // No cookie: another browser, or one that lost it.
    let res = send(&app, callback(&[("code", "good"), ("state", &state)], None)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_text(res)
            .await
            .contains("Start connecting the client again")
    );
    // This sign-in's cookie presented for another sign-in's state.
    let (to2, cookie2) = leave_for_provider(&app, &cid).await;
    let other_state = param(&to2, "state").unwrap();
    let renamed = format!(
        "{}={}",
        cookie2.split('=').next().unwrap(),
        cookie.split_once('=').unwrap().1
    );
    let res = send(
        &app,
        callback(&[("code", "good"), ("state", &other_state)], Some(&renamed)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // A tampered cookie.
    let tampered = format!("{cookie}A");
    let res = send(
        &app,
        callback(&[("code", "good"), ("state", &state)], Some(&tampered)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // A sealed credential from a token is not a pending sign-in.
    let name = cookie.split('=').next().unwrap();
    let credential = format!("{name}={}", st.sealer().seal("x").unwrap());
    let res = send(
        &app,
        callback(&[("code", "good"), ("state", &state)], Some(&credential)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    // No state at all.
    let res = send(&app, callback(&[("code", "good")], Some(&cookie))).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn declining_at_the_provider_is_reported_to_the_client() {
    let st = provider_state(None);
    let app = full_app(st.clone());
    let cid = register(&app).await;
    let (to, cookie) = leave_for_provider(&app, &cid).await;
    let state = param(&to, "state").unwrap();
    let res = send(
        &app,
        callback(
            &[("error", "access_denied"), ("state", &state)],
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let back = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(back.as_str().starts_with(CLIENT_REDIRECT));
    assert_eq!(param(&back, "error").as_deref(), Some("access_denied"));
    assert_eq!(param(&back, "state").as_deref(), Some("client-state"));
    assert!(param(&back, "code").is_none());
}

#[tokio::test]
async fn refused_and_unavailable_exchanges_say_why_and_grant_nothing() {
    let st = provider_state(None);
    let app = full_app(st.clone());
    let cid = register(&app).await;

    let (to, cookie) = leave_for_provider(&app, &cid).await;
    let state = param(&to, "state").unwrap();
    let res = send(
        &app,
        callback(&[("code", "bad"), ("state", &state)], Some(&cookie)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let text = body_text(res).await;
    assert!(
        text.contains("Ledger did not accept this sign-in"),
        "{text}"
    );
    assert!(text.contains("that code has expired."), "{text}");

    let (to, cookie) = leave_for_provider(&app, &cid).await;
    let state = param(&to, "state").unwrap();
    let res = send(
        &app,
        callback(&[("code", "down"), ("state", &state)], Some(&cookie)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(body_text(res).await.contains("the ledger is down"));
}

#[tokio::test]
async fn refused_exchanges_count_towards_the_sign_in_limit() {
    let st = provider_state(None);
    let app = full_app(st.clone());
    let cid = register(&app).await;
    let mut pending = Vec::new();
    for _ in 0..2 {
        let (to, cookie) = leave_for_provider(&app, &cid).await;
        pending.push((param(&to, "state").unwrap(), cookie));
    }
    for _ in 0..mcp_server_core::oauth::LOGIN_ATTEMPTS {
        let (to, cookie) = leave_for_provider(&app, &cid).await;
        let state = param(&to, "state").unwrap();
        let res = send(
            &app,
            callback(&[("code", "bad"), ("state", &state)], Some(&cookie)),
        )
        .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    // The address is now refused, both finishing a sign-in and starting one.
    let (state, cookie) = &pending[0];
    let res = send(
        &app,
        callback(&[("code", "good"), ("state", state)], Some(cookie)),
    )
    .await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_callback_exists_only_with_an_upstream_provider() {
    let app = full_app(state());
    let res = send(&app, get("/callback?code=x&state=y")).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[test]
fn plain_verifiers_have_no_upstream_provider() {
    assert!(verifier().upstream().is_none());
    assert!(owner().upstream().is_none());
}
