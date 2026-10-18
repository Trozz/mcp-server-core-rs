//! Limits on bearer credentials: per-address and global failure limits, shared checks.
mod oauth_support;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use mcp_server_core::credential::{CheckFuture, CredentialCheck, CredentialVerifier};
use mcp_server_core::server::build_app;
use oauth_support::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tower::ServiceExt;

const GOOD: &str = "good-key-0123456789";

/// Accepts keys starting `good-` (such as `GOOD`), after a delay, counting its checks.
struct Slow {
    checks: AtomicUsize,
}

impl CredentialVerifier for Slow {
    fn label(&self) -> &str {
        "API key"
    }
    fn help(&self) -> &str {
        ""
    }
    fn check<'a>(&'a self, credential: &'a str) -> CheckFuture<'a> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let ok = credential.starts_with("good-");
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if ok {
                CredentialCheck::Valid
            } else {
                CredentialCheck::Invalid(None)
            }
        })
    }
}

fn setup() -> (axum::Router, Arc<Slow>) {
    let v = Arc::new(Slow {
        checks: AtomicUsize::new(0),
    });
    let st = state_for(v.clone(), &["mail"]);
    let app = build_app(
        st,
        vec![(
            "mail",
            axum::Router::new().route("/", post(|| async { "ok" })),
        )],
    );
    (app, v)
}

fn bearer(scheme_and_token: &str, peer: [u8; 4]) -> Request<Body> {
    Request::post("/mail")
        .header("authorization", scheme_and_token)
        .extension(ConnectInfo(SocketAddr::from((peer, 4000))))
        .body(Body::empty())
        .unwrap()
}

async fn concurrently(app: &axum::Router, reqs: Vec<Request<Body>>) -> Vec<StatusCode> {
    let tasks: Vec<_> = reqs
        .into_iter()
        .map(|r| {
            let app = app.clone();
            tokio::spawn(async move { app.oneshot(r).await.unwrap().status() })
        })
        .collect();
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

#[tokio::test]
async fn concurrent_bad_keys_from_one_client_stay_within_its_limit() {
    let (app, v) = setup();
    let reqs = (0..50)
        .map(|i| bearer(&format!("Bearer bad-key-{i:04}"), [10, 0, 0, 1]))
        .collect();
    let statuses = concurrently(&app, reqs).await;
    let checked = v.checks.load(Ordering::SeqCst);
    assert!(checked <= 5, "{checked} upstream checks");
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::UNAUTHORIZED)
            .count(),
        checked
    );
    assert!(
        statuses
            .iter()
            .all(|s| *s == StatusCode::UNAUTHORIZED || *s == StatusCode::TOO_MANY_REQUESTS)
    );
}

#[tokio::test]
async fn concurrent_requests_with_one_new_key_share_one_check() {
    let (app, v) = setup();
    let reqs = (0..20)
        .map(|_| bearer(&format!("Bearer {GOOD}"), [10, 0, 0, 2]))
        .collect();
    let statuses = concurrently(&app, reqs).await;
    assert!(
        statuses.iter().all(|s| *s == StatusCode::OK),
        "{statuses:?}"
    );
    assert_eq!(v.checks.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn other_peoples_failures_never_block_a_clean_client() {
    let (app, _) = setup();
    for ip in 1..=6u8 {
        for i in 0..5 {
            let res = app
                .clone()
                .oneshot(bearer(&format!("Bearer bad-{ip}-{i}-key"), [10, ip, 1, 1]))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
    }
    let res = app
        .clone()
        .oneshot(bearer(&format!("Bearer {GOOD}"), [192, 0, 2, 9]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "a fresh client signs in");
    // A client that failed itself is blocked, even with a working key.
    let (app, _) = setup();
    for ip in 1..=6u8 {
        for i in 0..5 {
            app.clone()
                .oneshot(bearer(&format!("Bearer bad-{ip}-{i}-key"), [10, ip, 1, 1]))
                .await
                .unwrap();
        }
    }
    let res = app
        .oneshot(bearer(&format!("Bearer {GOOD}"), [10, 1, 1, 1]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()["retry-after"], "30");
}

#[tokio::test]
async fn a_check_abandoned_by_the_client_is_not_counted_as_a_rejection() {
    let (app, v) = setup();
    // Six people behind one address give up on their requests while the keys are checked.
    for i in 0..6 {
        let req = bearer(&format!("Bearer good-key-{i:04}-abcdef"), [10, 0, 2, 1]);
        let gave_up =
            tokio::time::timeout(Duration::from_millis(10), app.clone().oneshot(req)).await;
        assert!(gave_up.is_err(), "the request was abandoned mid-check");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        v.checks.load(Ordering::SeqCst),
        6,
        "the checks still finished"
    );
    let res = app
        .clone()
        .oneshot(bearer("Bearer good-key-9999-abcdef", [10, 0, 2, 1]))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "nothing was counted against the address"
    );
    let res = app
        .oneshot(bearer("Bearer good-key-0001-abcdef", [10, 0, 2, 1]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        v.checks.load(Ordering::SeqCst),
        7,
        "the abandoned key's verdict was cached"
    );
}

#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive() {
    let (app, _) = setup();
    for header in [format!("bearer {GOOD}"), format!("BEARER {GOOD}")] {
        let res = app
            .clone()
            .oneshot(bearer(&header, [10, 0, 0, 3]))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{header}");
    }
}

#[tokio::test]
async fn one_network_cannot_spread_checks_over_many_addresses() {
    let (app, v) = setup();
    // 300 addresses in one /24, one new key each.
    for host in 0..300u16 {
        let peer = [203, 0, 113, (host % 256) as u8];
        let key = format!("Bearer bad-spread-{host}");
        app.clone().oneshot(bearer(&key, peer)).await.unwrap();
    }
    let checked = v.checks.load(Ordering::SeqCst);
    assert!(
        checked <= mcp_server_core::guards::BLOCK_MAX_ATTEMPTS,
        "{checked} upstream checks from one /24"
    );
    // Nobody outside that network is affected, whatever their key.
    let res = app
        .clone()
        .oneshot(bearer(&format!("Bearer {GOOD}"), [198, 51, 100, 7]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn many_networks_failing_never_lock_out_a_new_key_elsewhere() {
    let (app, _) = setup();
    // One junk key from each of 120 networks: more than any global allowance would admit.
    for net in 0..120u8 {
        app.clone()
            .oneshot(bearer(&format!("Bearer bad-net-{net}"), [100, 64, net, 1]))
            .await
            .unwrap();
    }
    let res = app
        .oneshot(bearer(&format!("Bearer {GOOD}"), [192, 0, 2, 50]))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a new valid key still gets in"
    );
}
