//! The sign-in page and `POST /authorize`, for both kinds of sign-in.
mod oauth_support;
use axum::http::StatusCode;
use mcp_server_core::jwt::{Payload, TokenKind};
use oauth_support::*;

const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn client_id(st: &mcp_server_core::oauth::AuthState) -> String {
    st.jwt()
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

fn query(client_id: &str, redirect: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", redirect),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", "st<ate>"),
        ])
        .finish()
}

fn extract_hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker).unwrap() + marker.len();
    let end = html[start..].find('"').unwrap() + start;
    html[start..end]
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

fn form_fields(html: &str, credential: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = [
        "response_type",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
        "state",
        "scope",
        "resource",
        "csrf",
    ]
    .iter()
    .map(|n| (n.to_string(), extract_hidden(html, n)))
    .collect();
    v.push(("credential".into(), credential.into()));
    v
}

async fn login_page(app: &axum::Router, cid: &str) -> String {
    let res = send(
        app,
        get(&format!(
            "/authorize?{}",
            query(cid, "https://app.example.com/cb")
        )),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["x-frame-options"], "DENY");
    assert_eq!(res.headers()["cache-control"], "no-store");
    assert_eq!(
        res.headers()["content-security-policy"],
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    );
    body_text(res).await
}

fn post(fields: &[(String, String)]) -> axum::http::Request<axum::body::Body> {
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    form_post("/authorize", &pairs)
}

#[tokio::test]
async fn login_page_escapes_parameters() {
    let st = state();
    let html = login_page(&app(st.clone()), &client_id(&st)).await;
    assert!(html.contains("st&lt;ate&gt;"));
    assert!(!html.contains("st<ate>"));
    assert!(html.contains("<form method=\"post\" action=\"/authorize\">"));
}

#[tokio::test]
async fn login_page_asks_for_the_credential_without_storing_it() {
    let st = state();
    let html = login_page(&app(st.clone()), &client_id(&st)).await;
    assert!(html.contains("name=\"credential\""), "{html}");
    assert!(html.contains("autocomplete=\"off\""), "{html}");
    assert!(html.contains("Sign in with your own API key"), "{html}");
    assert!(html.contains("The key for the test service."), "{html}");
    assert!(!html.contains("name=\"password\""), "{html}");
}

#[tokio::test]
async fn correct_credential_redirects_with_code_and_state() {
    let st = state();
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    let res = send(&app, post(&form_fields(&html, KEY))).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()["cache-control"], "no-store");
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(loc.host_str(), Some("app.example.com"));
    let q: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    assert_eq!(q["state"], "st<ate>");
    let code = st.jwt().verify(&q["code"], TokenKind::Code).unwrap();
    assert_eq!(code.payload.code_challenge.as_deref(), Some(CHALLENGE));
    assert_eq!(
        code.payload.redirect_uri.as_deref(),
        Some("https://app.example.com/cb")
    );
    assert!(code.exp.unwrap() - code.iat <= 60);
    // The credential travels sealed: the code (a JWT anyone can decode) never holds it in clear.
    let sealed = code.payload.credential.expect("a sealed credential");
    assert!(!q["code"].contains(KEY) && !sealed.contains(KEY));
    assert_eq!(st.sealer().open(&sealed).unwrap().expose(), KEY);
}

#[tokio::test]
async fn wrong_credential_rerenders_with_401() {
    let st = state();
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    let res = send(&app, post(&form_fields(&html, "nope"))).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(
        body_text(res)
            .await
            .contains("That API key was not accepted.")
    );
}

#[tokio::test]
async fn implausible_credentials_are_rejected_without_asking_upstream() {
    let v = verifier();
    let st = state_with_verifier(v.clone());
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    for bad in ["has space", "", &"x".repeat(300)] {
        let res = send(&app, post(&form_fields(&html, bad))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{bad:?}");
    }
    assert_eq!(v.checks(), 0);
    // None of that counts as a failed attempt, so the person can still sign in.
    for _ in 0..10 {
        send(&app, post(&form_fields(&html, "x y"))).await;
    }
    let res = send(&app, post(&form_fields(&html, KEY))).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn an_unavailable_check_is_503_and_not_a_failed_attempt() {
    let st = state();
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    for _ in 0..6 {
        let res = send(&app, post(&form_fields(&html, DOWN_KEY))).await;
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(res.headers()["retry-after"], "30");
        assert!(
            body_text(res)
                .await
                .contains("could not be checked right now")
        );
    }
    // Six unavailable checks did not use up the five allowed failures.
    let res = send(&app, post(&form_fields(&html, KEY))).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn sixth_attempt_is_rate_limited_even_with_a_valid_credential() {
    let st = state();
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    for _ in 0..5 {
        assert_eq!(
            send(&app, post(&form_fields(&html, "nope"))).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        send(&app, post(&form_fields(&html, KEY))).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn tampered_parameters_fail_csrf_binding() {
    let st = state();
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    let mut fields = form_fields(&html, KEY);
    for f in fields.iter_mut() {
        if f.0 == "state" {
            f.1 = "different".into();
        }
    }
    assert_eq!(
        send(&app, post(&fields)).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn unregistered_redirect_uri_renders_400_and_never_redirects() {
    let st = state();
    let res = send(
        &app(st.clone()),
        get(&format!(
            "/authorize?{}",
            query(&client_id(&st), "https://evil.example.com/cb")
        )),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert!(res.headers().get("location").is_none());
}

#[tokio::test]
async fn invalid_method_redirects_with_error() {
    let st = state();
    let q = query(&client_id(&st), "https://app.example.com/cb")
        .replace("code_challenge_method=S256", "code_challenge_method=plain");
    let res = send(&app(st), get(&format!("/authorize?{q}"))).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let loc = res.headers()["location"].to_str().unwrap();
    assert!(loc.starts_with("https://app.example.com/cb?"));
    assert!(loc.contains("error=invalid_request"));
}

fn post_from(
    fields: &[(String, String)],
    peer: [u8; 4],
    xff: &str,
) -> axum::http::Request<axum::body::Body> {
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    form_post_from("/authorize", &pairs, peer, Some(xff))
}

async fn fail_five_times_then_try(
    st: std::sync::Arc<mcp_server_core::oauth::AuthState>,
    first_xff: &str,
    second_xff: &str,
) -> StatusCode {
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    for _ in 0..5 {
        assert_eq!(
            send(
                &app,
                post_from(&form_fields(&html, "nope"), [10, 0, 0, 1], first_xff)
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    send(
        &app,
        post_from(&form_fields(&html, KEY), [10, 0, 0, 1], second_xff),
    )
    .await
    .status()
}

#[tokio::test]
async fn forwarded_for_is_ignored_without_trusted_proxy() {
    let status = fail_five_times_then_try(state(), "198.51.100.1", "198.51.100.2").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn forwarded_for_is_honoured_from_trusted_proxy() {
    let st = state_with_trusted_proxies(vec!["10.0.0.1".parse().unwrap()]);
    let status = fail_five_times_then_try(
        st.clone(),
        "203.0.113.9, 198.51.100.1",
        "203.0.113.9, 198.51.100.2, 10.0.0.1",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let status = fail_five_times_then_try(st, "198.51.100.3", "198.51.100.3").await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn login_page_shows_redirect_host_and_unverified_client_name() {
    let st = state();
    let cid = st
        .jwt()
        .issue(
            TokenKind::Client,
            None,
            Payload {
                redirect_uris: Some(vec!["https://app.example.com/cb".into()]),
                client_name: Some("Claude <b>".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let html = login_page(&app(st.clone()), &cid).await;
    assert!(
        html.contains("After you authorize, you will be sent to <strong>app.example.com</strong>."),
        "{html}"
    );
    assert!(html.contains("Claude &lt;b&gt;"), "{html}");
    assert!(!html.contains("Claude <b>"), "{html}");
    assert!(html.contains("self-reported, unverified"), "{html}");

    let html = login_page(&app(st.clone()), &client_id(&st)).await;
    assert!(!html.contains("unverified"), "{html}");
}

#[tokio::test]
async fn login_page_names_the_service() {
    let st = state();
    let html = login_page(&app(st.clone()), &client_id(&st)).await;
    assert!(
        html.contains("requesting access to the <strong>mail</strong> service"),
        "{html}"
    );
}

#[tokio::test]
async fn the_combined_endpoint_is_named_as_every_service() {
    let st = state_with_combined();
    let q = format!(
        "{}&resource={}",
        query(&client_id(&st), "https://app.example.com/cb"),
        "https%3A%2F%2Fmail.example.com%2Fmcp"
    );
    let res = send(&app(st.clone()), get(&format!("/authorize?{q}"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(
        html.contains(
            "requesting access to <strong>every service</strong> on this server, through <code>/mcp</code>."
        ),
        "{html}"
    );
}

#[tokio::test]
async fn granted_scope_is_the_resource_service() {
    let st = state();
    let app = app(st.clone());
    let q = format!(
        "{}&scope=evil",
        query(&client_id(&st), "https://app.example.com/cb")
    );
    let res = send(&app, get(&format!("/authorize?{q}"))).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    let mut fields = form_fields(&html, KEY);
    for f in fields.iter_mut() {
        if f.0 == "scope" {
            f.1 = "evil".into();
        }
    }
    let res = send(&app, post(&fields)).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let q: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    let code = st.jwt().verify(&q["code"], TokenKind::Code).unwrap();
    assert_eq!(code.payload.scope.as_deref(), Some("mail"));
    assert_eq!(
        code.payload.resource.as_deref(),
        Some("https://mail.example.com/mail")
    );
}

#[tokio::test]
async fn empty_state_is_omitted_from_redirect() {
    let st = state();
    let app = app(st.clone());
    let q =
        query(&client_id(&st), "https://app.example.com/cb").replace("state=st%3Cate%3E", "state=");
    let html = body_text(send(&app, get(&format!("/authorize?{q}"))).await).await;
    let res = send(&app, post(&form_fields(&html, KEY))).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(loc.query_pairs().any(|(k, _)| k == "code"));
    assert!(!loc.query_pairs().any(|(k, _)| k == "state"), "{loc}");

    let q = q.replace("code_challenge_method=S256", "code_challenge_method=plain");
    let res = send(&app, get(&format!("/authorize?{q}"))).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    assert!(!loc.query_pairs().any(|(k, _)| k == "state"), "{loc}");
}

// The owner's password instead of each person's own credential.

#[tokio::test]
async fn the_owner_signs_in_with_the_password_which_tokens_never_carry() {
    let st = owner_state(None, &["mail"]);
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    assert!(
        html.contains("Sign in with this server's password."),
        "{html}"
    );
    assert!(html.contains(">Password<input"), "{html}");
    assert!(
        html.contains("autocomplete=\"current-password\""),
        "password managers may fill it: {html}"
    );
    assert!(!html.contains("encrypted form"), "{html}");
    let res = send(&app, post(&form_fields(&html, PASSWORD))).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let loc = url::Url::parse(res.headers()["location"].to_str().unwrap()).unwrap();
    let q: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    let code = st.jwt().verify(&q["code"], TokenKind::Code).unwrap();
    assert_eq!(
        code.payload.credential, None,
        "the password stays out of tokens"
    );
    assert_eq!(code.payload.scope.as_deref(), Some("mail"));
}

#[tokio::test]
async fn the_owner_password_is_compared_exactly() {
    let st = owner_state(None, &["mail"]);
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    for wrong in [
        "correct horse battery stapl",
        " correct horse battery staple",
        "Correct horse battery staple",
    ] {
        let res = send(&app, post(&form_fields(&html, wrong))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{wrong:?}");
        assert!(
            body_text(res)
                .await
                .contains("That password was not accepted."),
            "{wrong:?}"
        );
    }
    assert_eq!(
        send(&app, post(&form_fields(&html, PASSWORD)))
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn sixth_owner_attempt_is_rate_limited_even_with_the_right_password() {
    let st = owner_state(None, &["mail"]);
    let app = app(st.clone());
    let html = login_page(&app, &client_id(&st)).await;
    for _ in 0..5 {
        assert_eq!(
            send(&app, post(&form_fields(&html, "nope"))).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let res = send(&app, post(&form_fields(&html, PASSWORD))).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()["retry-after"], "30");
}
