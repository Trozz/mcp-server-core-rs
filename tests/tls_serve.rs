//! Serving over TLS and plain HTTP, and the healthcheck.
use axum::Router;
use axum::routing::get;
use mcp_server_core::tls::{TlsMode, generate_self_signed, healthcheck, serve};
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn app() -> Router {
    Router::new().route("/healthz", get(|| async { "ok" }))
}

async fn wait_healthy(port: u16, tls: bool) -> bool {
    for _ in 0..50 {
        if healthcheck(port, tls).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn self_signed_mode_serves_https() {
    mcp_server_core::install_crypto_provider();
    let port = free_port();
    let ct = CancellationToken::new();
    let mode = TlsMode::select(false, None, None, "localhost").unwrap();
    let task = tokio::spawn(serve(
        app(),
        SocketAddr::from(([127, 0, 0, 1], port)),
        mode,
        ct.clone(),
    ));
    assert!(wait_healthy(port, true).await);
    assert!(!healthcheck(port, false).await);
    ct.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn insecure_mode_serves_http() {
    let port = free_port();
    let ct = CancellationToken::new();
    let task = tokio::spawn(serve(
        app(),
        SocketAddr::from(([127, 0, 0, 1], port)),
        TlsMode::Insecure,
        ct.clone(),
    ));
    assert!(wait_healthy(port, false).await);
    ct.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn file_mode_serves_https() {
    mcp_server_core::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let s = generate_self_signed(&["localhost".into()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, &s.cert_pem).unwrap();
    std::fs::write(&key, &s.key_pem).unwrap();
    let port = free_port();
    let ct = CancellationToken::new();
    let task = tokio::spawn(serve(
        app(),
        SocketAddr::from(([127, 0, 0, 1], port)),
        TlsMode::Files { cert, key },
        ct.clone(),
    ));
    assert!(wait_healthy(port, true).await);
    ct.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn missing_cert_file_fails_instead_of_falling_back() {
    mcp_server_core::install_crypto_provider();
    let mode = TlsMode::Files {
        cert: "/nope/cert.pem".into(),
        key: "/nope/key.pem".into(),
    };
    let res = serve(
        app(),
        SocketAddr::from(([127, 0, 0, 1], free_port())),
        mode,
        CancellationToken::new(),
    )
    .await;
    let err = res.unwrap_err().to_string();
    assert!(err.contains("/nope/cert.pem"), "{err}");
}
