//! Who may sign in, and the credentials people bring with them.
//!
//! A [`CredentialVerifier`] decides what the sign-in page asks for and checks it. There are two
//! shapes, told apart by [`CredentialVerifier::carried`]:
//!
//! - **A password** that only proves who may sign in, such as the owner's password
//!   ([`PasswordVerifier`]). Tools act with the server's own upstream configuration, and nothing
//!   about the password is kept in tokens.
//! - **The person's own credential for the upstream service** the tools call, such as an API key,
//!   so one server can serve many people. The server stores no credential: it is checked once
//!   upstream when the person signs in, then sealed (encrypted and authenticated with a key derived
//!   from `OAUTH_SIGNING_KEY`, see [`Sealer`]) into their OAuth tokens, and opened again on every
//!   request, where tools find it as a [`Credential`] in the request extensions. A client that can
//!   send a header may instead send the credential itself as its bearer token; that is checked
//!   upstream too, and the verdict is cached briefly under the credential's SHA-256, never the
//!   credential.
//!
//! Reading the caller's credential in an rmcp tool:
//!
//! ```
//! use mcp_server_core::axum::http::request::Parts;
//! use mcp_server_core::credential::Credential;
//!
//! fn api_key(parts: &Parts) -> Option<&str> {
//!     parts.extensions.get::<Credential>().map(Credential::expose)
//! }
//! ```
//!
//! The `Parts` come from rmcp's `Extension<Parts>` tool argument.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, watch};

/// Longest credential accepted by [`plausible`], as a bound on what is sent upstream and sealed.
pub const MAX_CREDENTIAL_LEN: usize = 256;

/// The caller's credential, placed in the request extensions by the bearer guard when the
/// verifier's credentials are [carried](CredentialVerifier::carried). Its `Debug` output never
/// shows the secret.
#[derive(Clone)]
pub struct Credential(SecretString);

impl Credential {
    /// Wraps a secret.
    pub fn new(secret: impl Into<String>) -> Self {
        Credential(SecretString::from(secret.into()))
    }

    /// The secret itself, to send upstream. Never log it.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// SHA-256 of the credential: safe to keep as a map key or compare, never to log.
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(self.expose())
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential(..)")
    }
}

/// SHA-256 of `secret`, used to key caches and sessions without keeping the secret.
pub fn fingerprint(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// A verifier's verdict on a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialCheck {
    /// Accepted.
    Valid,
    /// Rejected, with a reason to show the person when there is a more useful one than "not
    /// accepted". Counts as a failed attempt for the sign-in limits.
    Invalid(Option<String>),
    /// Could not be checked now (upstream down, rate limited): say why. It does not count as a
    /// failed attempt.
    Unavailable(String),
}

/// The future returned by [`CredentialVerifier::check`].
pub type CheckFuture<'a> = Pin<Box<dyn Future<Output = CredentialCheck> + Send + 'a>>;

/// Decides what people sign in with and checks it. The server asks it when someone submits the
/// sign-in page and, when [`accepts_bearer`](Self::accepts_bearer), for bearer tokens that are
/// not this server's own OAuth tokens.
///
/// Checks run with a timeout, at most a few at once, and only once at a time per credential:
/// concurrent requests with the same credential share one check.
///
/// ```
/// use mcp_server_core::credential::{CheckFuture, CredentialCheck, CredentialVerifier};
///
/// /// Accepts keys the upstream API accepts.
/// struct ApiKeys;
///
/// impl CredentialVerifier for ApiKeys {
///     fn label(&self) -> &str {
///         "Example API key"
///     }
///     fn help(&self) -> &str {
///         "Create one under Settings, API keys at example.com."
///     }
///     fn check<'a>(&'a self, key: &'a str) -> CheckFuture<'a> {
///         Box::pin(async move {
///             // Make one cheap authenticated request upstream with `key` here.
///             if key.starts_with("ex_") {
///                 CredentialCheck::Valid
///             } else {
///                 CredentialCheck::Invalid(None)
///             }
///         })
///     }
/// }
/// ```
pub trait CredentialVerifier: Send + Sync + 'static {
    /// The credential's name in lower case, as it reads in a sentence and on the sign-in page,
    /// e.g. "password" or "Companies House API key". It also tells verifiers apart in the
    /// sign-in version, so changing it signs everyone out.
    fn label(&self) -> &str;
    /// One sentence of help under the field, plain text: what it is and where to get one.
    fn help(&self) -> &str {
        ""
    }
    /// Turns what was typed on the sign-in page into the credential to check. Defaults to
    /// trimming surrounding whitespace, which pasted keys often carry; a password keeps it.
    fn prepare<'a>(&self, entered: &'a str) -> &'a str {
        entered.trim()
    }
    /// Whether `credential` has the shape of one, checked before anything else. Defaults to
    /// [`plausible`]; narrow it when the upstream service's credentials have a known form, so
    /// other tokens are refused locally instead of being forwarded. Implausible input is refused
    /// without counting as a failed attempt.
    fn plausible(&self, credential: &str) -> bool {
        plausible(credential)
    }
    /// Checks `credential`.
    fn check<'a>(&'a self, credential: &'a str) -> CheckFuture<'a>;
    /// Whether the credential is the person's own key to the upstream service: sealed into their
    /// tokens and handed to tools as a [`Credential`]. `false` for a password that only proves
    /// who may sign in. Defaults to `true`.
    fn carried(&self) -> bool {
        true
    }
    /// Whether a client may send the credential itself as its bearer token instead of signing in
    /// with OAuth. Defaults to [`carried`](Self::carried).
    fn accepts_bearer(&self) -> bool {
        self.carried()
    }
    /// Who signed in with `credential`: the `sub` of their tokens, the audit log's subject and a
    /// [`Caller`](crate::caller::Caller)'s subject. It must not reveal the credential, and is
    /// readable by anyone who sees a token or a log line. Defaults to `None`, which lets the
    /// server name them: `key:` and 16 hex digits of a hash of the credential keyed by
    /// `OAUTH_SIGNING_KEY` when credentials are carried (one subject per person), and `owner`
    /// otherwise.
    fn subject(&self, credential: &str) -> Option<String> {
        let _ = credential;
        None
    }
    /// Bytes that change whenever every earlier sign-in should end, such as a hash of the
    /// password, or a new upstream service or environment. Tokens carry a keyed hash of them and
    /// of [`label`](Self::label), so a change to either signs everyone out. Defaults to none.
    fn generation(&self) -> &[u8] {
        &[]
    }
    /// The upstream OAuth provider people sign in through instead of typing a credential, if
    /// any: the sign-in page then sends them to the provider, and the credential it grants is
    /// sealed into their tokens. Defaults to `None`. [`UpstreamVerifier`](crate::upstream::UpstreamVerifier)
    /// builds a verifier around one; see [`crate::upstream`].
    fn upstream(&self) -> Option<&dyn crate::upstream::UpstreamSignIn> {
        None
    }
}

/// Whether `s` has the shape of a credential: non-empty, at most [`MAX_CREDENTIAL_LEN`] bytes,
/// visible ASCII without spaces.
pub fn plausible(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_CREDENTIAL_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Longest password [`PasswordVerifier`] considers.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// One password that proves the person signing in is the server's owner, compared in constant
/// time. It is not [carried](CredentialVerifier::carried): tools use the server's own upstream
/// configuration. This is what [`SignIn::OwnerPassword`](crate::app::SignIn::OwnerPassword)
/// builds from `OAUTH_ADMIN_PASSWORD`.
pub struct PasswordVerifier {
    password: SecretString,
    generation: [u8; 32],
}

impl PasswordVerifier {
    /// Accepts exactly `password`. Changing it signs everyone out.
    pub fn new(password: SecretString) -> Self {
        let generation = Sha256::new()
            .chain_update(b"mcp-server-core owner password\0")
            .chain_update(password.expose_secret().as_bytes())
            .finalize()
            .into();
        PasswordVerifier {
            password,
            generation,
        }
    }
}

impl std::fmt::Debug for PasswordVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordVerifier(..)")
    }
}

impl CredentialVerifier for PasswordVerifier {
    fn label(&self) -> &str {
        "password"
    }

    fn prepare<'a>(&self, entered: &'a str) -> &'a str {
        entered
    }

    fn plausible(&self, credential: &str) -> bool {
        !credential.is_empty() && credential.len() <= MAX_PASSWORD_LEN
    }

    fn check<'a>(&'a self, credential: &'a str) -> CheckFuture<'a> {
        let ok = crate::pkce::ct_eq(credential, self.password.expose_secret());
        Box::pin(async move {
            if ok {
                CredentialCheck::Valid
            } else {
                CredentialCheck::Invalid(None)
            }
        })
    }

    fn carried(&self) -> bool {
        false
    }

    fn generation(&self) -> &[u8] {
        &self.generation
    }
}

/// Why a credential could not be sealed or opened.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealError {
    /// The random nonce or the encryption failed.
    #[error("sealing failed")]
    Seal,
    /// Not a credential sealed under this key.
    #[error("the sealed credential is invalid")]
    Open,
}

/// Seals credentials into tokens with ChaCha20-Poly1305 under a key derived (HKDF-SHA256) from
/// the OAuth signing key, so rotating `OAUTH_SIGNING_KEY` also invalidates every sealed
/// credential.
pub struct Sealer {
    key: LessSafeKey,
    rng: SystemRandom,
    aad: &'static [u8],
}

const SEAL_SALT: &[u8] = b"mcp-server-core credential sealing";
const SEAL_INFO: &[u8] = b"v1";
const SEAL_AAD: &[u8] = b"mcp-server-core credential v1";

impl Sealer {
    /// A sealer whose key is derived from `signing_key`.
    pub fn new(signing_key: &[u8]) -> Self {
        Self::for_purpose(signing_key, SEAL_INFO, SEAL_AAD)
    }

    /// A sealer for something other than credentials, under its own key (HKDF `info`) and
    /// associated data, so what it seals can never be opened as a credential or the reverse.
    pub(crate) fn for_purpose(signing_key: &[u8], info: &[u8], aad: &'static [u8]) -> Self {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, SEAL_SALT).extract(signing_key);
        let info = [info];
        let okm = prk
            .expand(&info, &CHACHA20_POLY1305)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Sealer {
            key: LessSafeKey::new(UnboundKey::from(okm)),
            rng: SystemRandom::new(),
            aad,
        }
    }

    /// `base64url(nonce || ciphertext || tag)` of `credential`, with a random nonce.
    pub fn seal(&self, credential: &str) -> Result<String, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).map_err(|_| SealError::Seal)?;
        let mut data = credential.as_bytes().to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(self.aad),
                &mut data,
            )
            .map_err(|_| SealError::Seal)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&data);
        Ok(URL_SAFE_NO_PAD.encode(out))
    }

    /// The credential sealed in `sealed`, if it was sealed under this key and not altered.
    pub fn open(&self, sealed: &str) -> Result<Credential, SealError> {
        let raw = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| SealError::Open)?;
        if raw.len() < NONCE_LEN {
            return Err(SealError::Open);
        }
        let (nonce, rest) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| SealError::Open)?;
        let mut data = rest.to_vec();
        let plain = self
            .key
            .open_in_place(nonce, Aad::from(self.aad), &mut data)
            .map_err(|_| SealError::Open)?;
        let text = std::str::from_utf8(plain).map_err(|_| SealError::Open)?;
        Ok(Credential::new(text))
    }
}

/// Recent verdicts on bearer credentials, keyed by fingerprint. Valid ones are remembered longer
/// than rejected ones, so a fixed key is not rechecked upstream on every request.
pub(crate) struct CheckCache {
    entries: Mutex<HashMap<[u8; 32], (Instant, bool)>>,
    valid_for: Duration,
    invalid_for: Duration,
    max_entries: usize,
}

impl CheckCache {
    pub fn new(valid_for: Duration, invalid_for: Duration, max_entries: usize) -> Self {
        CheckCache {
            entries: Mutex::new(HashMap::new()),
            valid_for,
            invalid_for,
            max_entries,
        }
    }

    /// The cached verdict, if one has not expired.
    pub fn get(&self, fingerprint: &[u8; 32]) -> Option<bool> {
        let now = Instant::now();
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .get(fingerprint)
            .filter(|(expires, _)| *expires > now)
            .map(|(_, valid)| *valid)
    }

    pub fn put(&self, fingerprint: [u8; 32], valid: bool) {
        let now = Instant::now();
        let ttl = if valid {
            self.valid_for
        } else {
            self.invalid_for
        };
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= self.max_entries && !entries.contains_key(&fingerprint) {
            entries.retain(|_, (expires, _)| *expires > now);
            // Rejected keys go first, so a burst of junk never pushes out keys that work.
            if entries.len() >= self.max_entries {
                entries.retain(|_, (_, valid)| *valid);
            }
            if entries.len() >= self.max_entries {
                if !valid {
                    return;
                }
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, (expires, _))| *expires)
                    .map(|(k, _)| *k)
                {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(fingerprint, (now + ttl, valid));
    }
}

/// Runs upstream credential checks: one check at a time per credential, at most `max_running`
/// at once, each bounded by `timeout`. A check that finds every slot taken waits up to `wait`
/// for one before giving up as busy.
///
/// The first request for a credential [`join`](Self::join)s as the [`Lead`] and runs the check;
/// requests arriving while it runs follow it and get its verdict. Only a lead ever calls the
/// upstream service, so the caller decides once, when the request arrives, whether it is the
/// attempt that counts.
pub(crate) struct CheckRunner {
    permits: Semaphore,
    timeout: Duration,
    wait: Duration,
    running: Mutex<HashMap<[u8; 32], watch::Receiver<Option<CredentialCheck>>>>,
}

/// How a request takes part in a credential check.
pub(crate) enum Ticket {
    /// Run the check ([`CheckRunner::lead`]) or end it ([`CheckRunner::finish`]).
    Lead(Lead),
    /// Wait for the lead's verdict ([`CheckRunner::follow`]).
    Follow(watch::Receiver<Option<CredentialCheck>>),
}

/// The request responsible for one credential's check.
pub(crate) struct Lead {
    fingerprint: [u8; 32],
    tx: watch::Sender<Option<CredentialCheck>>,
}

impl CheckRunner {
    /// At most `max_running` checks at once, each bounded by `timeout`; a check waits up to
    /// `wait` for a free slot.
    pub fn new(max_running: usize, timeout: Duration, wait: Duration) -> Self {
        CheckRunner {
            permits: Semaphore::new(max_running),
            timeout,
            wait,
            running: Mutex::new(HashMap::new()),
        }
    }

    /// Joins the check of the credential with this fingerprint: as its lead when none is
    /// running, otherwise as a follower.
    pub fn join(&self, fingerprint: [u8; 32]) -> Ticket {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        // A lead that went away without finishing leaves a closed channel: start afresh.
        if let Some(rx) = running.get(&fingerprint)
            && rx.has_changed().is_ok()
        {
            return Ticket::Follow(rx.clone());
        }
        let (tx, rx) = watch::channel(None);
        running.insert(fingerprint, rx);
        Ticket::Lead(Lead { fingerprint, tx })
    }

    /// Runs the upstream check for `lead` and hands the verdict to its followers.
    pub async fn lead(
        &self,
        lead: Lead,
        verifier: &dyn CredentialVerifier,
        credential: &str,
    ) -> CredentialCheck {
        let verdict = match tokio::time::timeout(self.wait, self.permits.acquire()).await {
            Ok(Ok(_permit)) => {
                match tokio::time::timeout(self.timeout, verifier.check(credential)).await {
                    Ok(verdict) => verdict,
                    Err(_) => CredentialCheck::Unavailable("the check timed out".into()),
                }
            }
            _ => CredentialCheck::Unavailable(
                "the server is checking too many credentials at once".into(),
            ),
        };
        self.finish(lead, verdict.clone());
        verdict
    }

    /// Ends `lead` with `verdict` without checking upstream, for example when its client is
    /// refused for too many attempts. Followers get `verdict`.
    pub fn finish(&self, lead: Lead, verdict: CredentialCheck) {
        let mut running = self.running.lock().unwrap_or_else(|e| e.into_inner());
        if running
            .get(&lead.fingerprint)
            .is_some_and(|rx| rx.same_channel(&lead.tx.subscribe()))
        {
            running.remove(&lead.fingerprint);
        }
        lead.tx.send_replace(Some(verdict));
    }

    /// The verdict of the check a follower joined.
    pub async fn follow(mut rx: watch::Receiver<Option<CredentialCheck>>) -> CredentialCheck {
        match rx.wait_for(Option::is_some).await {
            Ok(v) => v.clone().unwrap_or_else(|| unreachable!("waited for Some")),
            Err(_) => CredentialCheck::Unavailable("the check was abandoned".into()),
        }
    }

    /// Joins and runs or follows the check of `credential`.
    #[cfg(test)]
    pub async fn check(
        &self,
        verifier: &dyn CredentialVerifier,
        credential: &str,
    ) -> CredentialCheck {
        match self.join(fingerprint(credential)) {
            Ticket::Lead(lead) => self.lead(lead, verifier, credential).await,
            Ticket::Follow(rx) => Self::follow(rx).await,
        }
    }

    #[cfg(test)]
    fn is_running(&self, fingerprint: &[u8; 32]) -> bool {
        self.running
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn sealed_credentials_open_with_the_same_signing_key_only() {
        let a = Sealer::new(KEY);
        let sealed = a.seal("my-api-key").unwrap();
        assert!(!sealed.contains("my-api-key"));
        assert_eq!(a.open(&sealed).unwrap().expose(), "my-api-key");
        let b = Sealer::new(b"another signing key of 32 bytes!");
        assert_eq!(b.open(&sealed).unwrap_err(), SealError::Open);
    }

    #[test]
    fn sealing_uses_a_fresh_nonce() {
        let s = Sealer::new(KEY);
        assert_ne!(s.seal("k").unwrap(), s.seal("k").unwrap());
    }

    #[test]
    fn tampered_or_malformed_seals_do_not_open() {
        let s = Sealer::new(KEY);
        let sealed = s.seal("my-api-key").unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(s.open(&URL_SAFE_NO_PAD.encode(raw)).is_err());
        for bad in [
            "",
            "not base64!",
            "AAAA",
            &URL_SAFE_NO_PAD.encode([0u8; 12]),
        ] {
            assert!(s.open(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn credentials_never_print() {
        let c = Credential::new("secret-value");
        assert_eq!(format!("{c:?}"), "Credential(..)");
        assert_eq!(c.fingerprint(), fingerprint("secret-value"));
        assert_ne!(c.fingerprint(), fingerprint("secret-valuf"));
    }

    #[tokio::test]
    async fn the_owner_password_is_compared_exactly_and_never_carried() {
        let v = PasswordVerifier::new("correct horse battery staple ".to_string().into());
        assert!(!v.carried());
        assert!(!v.accepts_bearer());
        assert_eq!(
            v.prepare(" a b "),
            " a b ",
            "passwords keep their whitespace"
        );
        assert!(v.plausible("with spaces and ünïcode"));
        assert!(!v.plausible(""));
        assert!(!v.plausible(&"x".repeat(MAX_PASSWORD_LEN + 1)));
        assert_eq!(
            v.check("correct horse battery staple ").await,
            CredentialCheck::Valid
        );
        for wrong in [
            "correct horse battery staple",
            "",
            "Correct horse battery staple ",
        ] {
            assert_eq!(
                v.check(wrong).await,
                CredentialCheck::Invalid(None),
                "{wrong:?}"
            );
        }
        assert_eq!(format!("{v:?}"), "PasswordVerifier(..)");
    }

    #[test]
    fn upstream_credentials_are_carried_and_trimmed_by_default() {
        struct Key;
        impl CredentialVerifier for Key {
            fn label(&self) -> &str {
                "key"
            }
            fn check<'a>(&'a self, _: &'a str) -> CheckFuture<'a> {
                Box::pin(async { CredentialCheck::Valid })
            }
        }
        assert!(Key.carried());
        assert!(Key.accepts_bearer());
        assert_eq!(Key.help(), "");
        assert_eq!(Key.prepare("  k-1 \n"), "k-1");
    }

    #[test]
    fn plausible_credentials() {
        assert!(plausible("0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0"));
        for bad in [
            "",
            "has space",
            "tab\tkey",
            "ключ",
            &"x".repeat(MAX_CREDENTIAL_LEN + 1),
        ] {
            assert!(!plausible(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_full_cache_drops_rejected_keys_before_working_ones() {
        let c = CheckCache::new(Duration::from_secs(600), Duration::from_secs(60), 3);
        c.put([1; 32], true);
        c.put([2; 32], false);
        c.put([3; 32], false);
        c.put([4; 32], false);
        assert_eq!(
            c.get(&[1; 32]),
            Some(true),
            "junk never pushes out a working key"
        );
        c.put([5; 32], true);
        c.put([6; 32], true);
        c.put([7; 32], true);
        assert!(c.entries.lock().unwrap().len() <= 3);
        assert_eq!(c.get(&[7; 32]), Some(true));
        c.put([8; 32], false);
        assert_eq!(
            c.get(&[8; 32]),
            None,
            "a full cache of working keys keeps them"
        );
        assert_eq!(c.get(&[7; 32]), Some(true));
    }

    struct Slow {
        checks: std::sync::atomic::AtomicUsize,
        delay: Duration,
    }

    impl CredentialVerifier for Slow {
        fn label(&self) -> &'static str {
            "key"
        }
        fn help(&self) -> &'static str {
            ""
        }
        fn check<'a>(&'a self, credential: &'a str) -> CheckFuture<'a> {
            self.checks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let ok = credential == "good";
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                if ok {
                    CredentialCheck::Valid
                } else {
                    CredentialCheck::Invalid(None)
                }
            })
        }
    }

    fn slow(ms: u64) -> Slow {
        Slow {
            checks: Default::default(),
            delay: Duration::from_millis(ms),
        }
    }

    #[tokio::test]
    async fn concurrent_checks_of_one_credential_share_one_upstream_call() {
        let runner = CheckRunner::new(4, Duration::from_secs(5), Duration::ZERO);
        let v = slow(50);
        let all = futures_join(&runner, &v, &["good"; 8]).await;
        assert!(all.iter().all(|c| *c == CredentialCheck::Valid));
        assert_eq!(v.checks.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!runner.is_running(&fingerprint("good")));
    }

    #[tokio::test]
    async fn running_checks_are_capped_and_timed_out() {
        let runner = CheckRunner::new(2, Duration::from_millis(100), Duration::ZERO);
        let v = slow(300);
        let all = futures_join(&runner, &v, &["a", "b", "c"]).await;
        assert_eq!(v.checks.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(
            all.iter()
                .all(|c| matches!(c, CredentialCheck::Unavailable(_))),
            "{all:?}"
        );
    }

    #[tokio::test]
    async fn followers_of_a_refused_lead_never_check_upstream() {
        let runner = CheckRunner::new(4, Duration::from_secs(5), Duration::ZERO);
        let v = slow(10);
        let Ticket::Lead(lead) = runner.join(fingerprint("good")) else {
            panic!("the first request leads");
        };
        let Ticket::Follow(rx) = runner.join(fingerprint("good")) else {
            panic!("the second follows");
        };
        runner.finish(lead, CredentialCheck::Unavailable("refused".into()));
        assert_eq!(
            CheckRunner::follow(rx).await,
            CredentialCheck::Unavailable("refused".into())
        );
        assert_eq!(v.checks.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(matches!(runner.join(fingerprint("good")), Ticket::Lead(_)));
    }

    #[tokio::test]
    async fn a_lead_that_disappears_does_not_block_the_credential() {
        let runner = CheckRunner::new(4, Duration::from_secs(5), Duration::ZERO);
        let Ticket::Lead(lead) = runner.join(fingerprint("k")) else {
            panic!();
        };
        let Ticket::Follow(rx) = runner.join(fingerprint("k")) else {
            panic!();
        };
        drop(lead);
        assert!(matches!(
            CheckRunner::follow(rx).await,
            CredentialCheck::Unavailable(_)
        ));
        assert!(matches!(runner.join(fingerprint("k")), Ticket::Lead(_)));
    }

    #[test]
    fn subjects_and_generations_default_sensibly() {
        struct Key;
        impl CredentialVerifier for Key {
            fn label(&self) -> &str {
                "key"
            }
            fn check<'a>(&'a self, _: &'a str) -> CheckFuture<'a> {
                Box::pin(async { CredentialCheck::Valid })
            }
        }
        assert_eq!(Key.subject("secret-key-1"), None, "the server names them");
        assert!(Key.generation().is_empty());
        let owner = PasswordVerifier::new("a long password".to_string().into());
        assert_eq!(owner.subject("a long password"), None);
        let other = PasswordVerifier::new("another password".to_string().into());
        assert_ne!(owner.generation(), other.generation());
        assert_eq!(owner.generation().len(), 32);
    }

    #[tokio::test]
    async fn a_check_waits_briefly_for_a_free_slot() {
        let runner = CheckRunner::new(1, Duration::from_secs(5), Duration::from_secs(2));
        let v = slow(50);
        let all = futures_join(&runner, &v, &["good", "good-too", "good"]).await;
        assert_eq!(v.checks.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(all[0], CredentialCheck::Valid);
        assert_eq!(all[2], CredentialCheck::Valid);
        assert_eq!(
            all[1],
            CredentialCheck::Invalid(None),
            "ran after waiting, not busy"
        );
    }

    async fn futures_join(runner: &CheckRunner, v: &Slow, creds: &[&str]) -> Vec<CredentialCheck> {
        let futs = creds.iter().map(|c| runner.check(v, c));
        let mut out = Vec::new();
        let handles: Vec<_> = futs.collect();
        for verdict in join_all(handles).await {
            out.push(verdict);
        }
        out
    }

    async fn join_all<F: Future>(futs: Vec<F>) -> Vec<F::Output> {
        let mut pinned: Vec<Pin<Box<F>>> = futs.into_iter().map(Box::pin).collect();
        let mut done: Vec<Option<F::Output>> = (0..pinned.len()).map(|_| None).collect();
        std::future::poll_fn(|cx| {
            let mut pending = false;
            for (i, f) in pinned.iter_mut().enumerate() {
                if done[i].is_none() {
                    match f.as_mut().poll(cx) {
                        std::task::Poll::Ready(v) => done[i] = Some(v),
                        std::task::Poll::Pending => pending = true,
                    }
                }
            }
            if pending {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(())
            }
        })
        .await;
        done.into_iter().map(|d| d.unwrap()).collect()
    }

    #[test]
    fn the_cache_expires_and_stays_bounded() {
        let c = CheckCache::new(Duration::from_secs(60), Duration::ZERO, 2);
        c.put([1; 32], true);
        c.put([2; 32], false);
        assert_eq!(c.get(&[1; 32]), Some(true));
        assert_eq!(c.get(&[2; 32]), None, "a zero ttl expires at once");
        c.put([3; 32], true);
        c.put([4; 32], true);
        assert!(c.entries.lock().unwrap().len() <= 2);
        assert_eq!(c.get(&[4; 32]), Some(true));
    }
}
