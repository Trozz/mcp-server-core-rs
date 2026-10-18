//! Serving HTTP or HTTPS, and the container healthcheck.

use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

/// How the server listens.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TlsMode {
    /// Plain HTTP (`INSECURE_HTTP`), behind a proxy that terminates TLS.
    Insecure,
    /// A PEM certificate chain and key, reloaded when either file changes.
    Files {
        /// `TLS_CERT_PATH`.
        cert: PathBuf,
        /// `TLS_KEY_PATH`.
        key: PathBuf,
    },
    /// A certificate generated in memory at startup, for these subject alternative names.
    SelfSigned {
        /// The public host and loopback names.
        sans: Vec<String>,
    },
}

impl TlsMode {
    /// The mode for the given settings; an error when only one of `cert` and `key` is set.
    pub fn select(
        insecure: bool,
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
        public_host: &str,
    ) -> Result<Self, String> {
        if insecure {
            return Ok(TlsMode::Insecure);
        }
        match (cert, key) {
            (Some(cert), Some(key)) => Ok(TlsMode::Files { cert, key }),
            (None, None) => {
                let mut sans = vec![public_host.to_string()];
                for s in ["localhost", "127.0.0.1", "::1"] {
                    if !sans.iter().any(|x| x == s) {
                        sans.push(s.to_string());
                    }
                }
                Ok(TlsMode::SelfSigned { sans })
            }
            _ => Err("TLS_CERT_PATH and TLS_KEY_PATH must be set together".into()),
        }
    }

    /// Whether the server speaks TLS.
    pub fn is_tls(&self) -> bool {
        !matches!(self, TlsMode::Insecure)
    }
}

/// A generated certificate.
pub struct SelfSigned {
    /// The certificate, PEM.
    pub cert_pem: String,
    /// Its private key, PEM.
    pub key_pem: String,
    /// The certificate's SHA-256 fingerprint, colon-separated hex, to compare with what clients see.
    pub fingerprint: String,
}

/// A self-signed certificate for `sans`.
pub fn generate_self_signed(sans: &[String]) -> anyhow::Result<SelfSigned> {
    let ck = rcgen::generate_simple_self_signed(sans.to_vec())?;
    let digest = Sha256::digest(ck.cert.der());
    let fingerprint = digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(SelfSigned {
        cert_pem: ck.cert.pem(),
        key_pem: ck.signing_key.serialize_pem(),
        fingerprint,
    })
}

fn mtime(p: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

async fn watch_certs(
    config: RustlsConfig,
    cert: PathBuf,
    key: PathBuf,
    shutdown: CancellationToken,
    interval: Duration,
) {
    let mut last = (mtime(&cert), mtime(&key));
    let mut tick = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tick.tick() => {}
        }
        let now = (mtime(&cert), mtime(&key));
        if now == last {
            continue;
        }
        match config.reload_from_pem_file(&cert, &key).await {
            Ok(()) => {
                tracing::info!("tls certificate reloaded");
                last = now;
            }
            Err(e) => {
                tracing::warn!(error = %e, "tls certificate reload failed, keeping previous certificate")
            }
        }
    }
}

const CERT_RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// Serves `app` on `addr` until `shutdown` is cancelled, then drains connections for up to ten
/// seconds. Handlers see the peer address as `ConnectInfo<SocketAddr>`.
pub async fn serve(
    app: Router,
    addr: SocketAddr,
    mode: TlsMode,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    serve_with_reload_interval(app, addr, mode, shutdown, CERT_RELOAD_INTERVAL).await
}

pub(crate) async fn serve_with_reload_interval(
    app: Router,
    addr: SocketAddr,
    mode: TlsMode,
    shutdown: CancellationToken,
    reload_interval: Duration,
) -> anyhow::Result<()> {
    let handle: Handle<SocketAddr> = Handle::new();
    let h = handle.clone();
    let ct = shutdown.clone();
    tokio::spawn(async move {
        ct.cancelled().await;
        h.graceful_shutdown(Some(Duration::from_secs(10)));
    });
    let make = app.into_make_service_with_connect_info::<SocketAddr>();
    match mode {
        TlsMode::Insecure => {
            tracing::warn!(%addr, "INSECURE_HTTP=true: serving plaintext HTTP without TLS");
            axum_server::bind(addr).handle(handle).serve(make).await?;
        }
        TlsMode::Files { cert, key } => {
            let config = RustlsConfig::from_pem_file(&cert, &key)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "cannot load TLS certificate {} / key {}: {e}",
                        cert.display(),
                        key.display()
                    )
                })?;
            tokio::spawn(watch_certs(
                config.clone(),
                cert,
                key,
                shutdown.clone(),
                reload_interval,
            ));
            tracing::info!(%addr, "serving HTTPS with certificate from files");
            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(make)
                .await?;
        }
        TlsMode::SelfSigned { sans } => {
            let s = generate_self_signed(&sans)?;
            tracing::warn!(
                %addr,
                fingerprint_sha256 = %s.fingerprint,
                sans = ?sans,
                "no TLS_CERT_PATH/TLS_KEY_PATH set: serving HTTPS with an in-memory self-signed certificate (not trusted by claude.ai)"
            );
            let config =
                RustlsConfig::from_pem(s.cert_pem.into_bytes(), s.key_pem.into_bytes()).await?;
            axum_server::bind_rustls(addr, config)
                .handle(handle)
                .serve(make)
                .await?;
        }
    }
    Ok(())
}

#[derive(Debug)]
struct AcceptAnyCert(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn http_get_healthz<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
) -> bool {
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .is_err()
    {
        return false;
    }
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    buf.starts_with(b"HTTP/1.1 200")
}

/// Liveness probe for the container HEALTHCHECK. Certificate verification is
/// skipped because it only ever connects to 127.0.0.1.
pub async fn healthcheck(port: u16, tls: bool) -> bool {
    let fut = async {
        let Ok(tcp) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
            return false;
        };
        if !tls {
            return http_get_healthz(tcp).await;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let Ok(builder) = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
        else {
            return false;
        };
        let cfg = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        let Ok(name) = ServerName::try_from("localhost") else {
            return false;
        };
        let Ok(stream) = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
        else {
            return false;
        };
        http_get_healthz(stream).await
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn insecure_wins() {
        assert!(matches!(
            TlsMode::select(true, None, None, "h").unwrap(),
            TlsMode::Insecure
        ));
    }

    #[test]
    fn both_paths_select_files() {
        let m = TlsMode::select(
            false,
            Some(PathBuf::from("/c")),
            Some(PathBuf::from("/k")),
            "h",
        )
        .unwrap();
        assert!(matches!(m, TlsMode::Files { .. }));
    }

    #[test]
    fn one_path_is_an_error() {
        assert!(TlsMode::select(false, Some(PathBuf::from("/c")), None, "h").is_err());
        assert!(TlsMode::select(false, None, Some(PathBuf::from("/k")), "h").is_err());
    }

    #[test]
    fn no_paths_select_self_signed_with_sans() {
        let TlsMode::SelfSigned { sans } =
            TlsMode::select(false, None, None, "mail.example.com").unwrap()
        else {
            panic!()
        };
        assert_eq!(
            sans,
            vec!["mail.example.com", "localhost", "127.0.0.1", "::1"]
        );
    }

    #[test]
    fn localhost_public_host_is_not_duplicated() {
        let TlsMode::SelfSigned { sans } = TlsMode::select(false, None, None, "localhost").unwrap()
        else {
            panic!()
        };
        assert_eq!(sans, vec!["localhost", "127.0.0.1", "::1"]);
    }

    async fn served_fingerprint(port: u16) -> Option<String> {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider)))
            .with_no_client_auth();
        let name = ServerName::try_from("localhost").ok()?;
        let stream = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .ok()?;
        let der = stream.get_ref().1.peer_certificates()?.first()?.clone();
        Some(
            Sha256::digest(der.as_ref())
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }

    fn write_cert(cert: &Path, key: &Path, s: &SelfSigned, mtime: std::time::SystemTime) {
        for (path, pem) in [(cert, &s.cert_pem), (key, &s.key_pem)] {
            std::fs::write(path, pem).unwrap();
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        }
    }

    #[tokio::test]
    async fn file_mode_hot_reloads_rewritten_certificate() {
        crate::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        let first = generate_self_signed(&["localhost".into()]).unwrap();
        let start = std::time::SystemTime::now();
        write_cert(&cert, &key, &first, start);
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let ct = CancellationToken::new();
        let task = tokio::spawn(serve_with_reload_interval(
            Router::new(),
            SocketAddr::from(([127, 0, 0, 1], port)),
            TlsMode::Files {
                cert: cert.clone(),
                key: key.clone(),
            },
            ct.clone(),
            Duration::from_millis(100),
        ));
        let mut served = None;
        for _ in 0..50 {
            served = served_fingerprint(port).await;
            if served.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(served.as_deref(), Some(first.fingerprint.as_str()));

        let second = generate_self_signed(&["reloaded.example.com".into()]).unwrap();
        assert_ne!(first.fingerprint, second.fingerprint);
        write_cert(&cert, &key, &second, start + Duration::from_secs(10));
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            served = served_fingerprint(port).await;
            if served.as_deref() == Some(second.fingerprint.as_str()) {
                break;
            }
        }
        assert_eq!(served.as_deref(), Some(second.fingerprint.as_str()));
        ct.cancel();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn self_signed_generates_pem_and_fingerprint() {
        let s = generate_self_signed(&["localhost".into(), "127.0.0.1".into()]).unwrap();
        assert!(s.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(s.key_pem.contains("PRIVATE KEY"));
        assert_eq!(s.fingerprint.len(), 32 * 3 - 1);
        assert!(
            s.fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':')
        );
    }
}
