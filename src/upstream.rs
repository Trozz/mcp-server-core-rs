//! Signing in through the upstream service's own OAuth: the person approves access at the
//! provider (FreeAgent, GitHub, Google and the like) instead of pasting a key, and the credential
//! the provider grants is sealed into their tokens like any other carried credential.
//!
//! A [`CredentialVerifier`] opts in by returning an
//! [`UpstreamSignIn`] from [`upstream`](crate::credential::CredentialVerifier::upstream). The
//! sign-in page then asks the person to approve the MCP client and continue to the provider, and
//! the server, acting as the provider's OAuth client, finishes the sign-in at
//! [`CALLBACK_PATH`]:
//!
//! 1. `GET /authorize` shows which client is asking and where it will be sent, with a button to
//!    continue to the provider. Consent is asked here for every client, because every client
//!    reaches the provider under this server's one OAuth client id.
//! 2. `POST /authorize` sets a short-lived cookie holding the pending authorization request,
//!    encrypted and bound to a random `state`, and sends the browser to
//!    [`UpstreamSignIn::authorize_url`].
//! 3. The provider sends the browser back to `PUBLIC_URL/callback` with a code and the `state`.
//!    The server checks the `state` against the cookie, calls [`UpstreamSignIn::exchange`], seals
//!    the [`UpstreamGrant`]'s credential into an authorization code and sends the browser on to the
//!    MCP client, which redeems the code at `/token` as usual.
//!
//! Nothing is stored on the server: the pending request lives in the person's browser, and the
//! credential in their tokens. Register `PUBLIC_URL/callback` as a redirect URI with the provider.
//!
//! The credential is usually the provider's refresh token, from which tools obtain access tokens
//! as they need them; it is handed to tools as a [`Credential`](crate::credential::Credential)
//! exactly as a pasted key would be.

use crate::credential::{CheckFuture, CredentialCheck, CredentialVerifier};
use std::future::Future;
use std::pin::Pin;

/// Where the provider sends people back to, below `PUBLIC_URL`. A service cannot be named
/// `callback` when people sign in through an upstream provider.
pub const CALLBACK_PATH: &str = "/callback";

/// How long a person has to approve access at the provider, from leaving the sign-in page.
pub const PENDING_TTL_SECS: u64 = 600;

/// Longest credential an exchange may return, in bytes. It travels sealed in every access token,
/// so it is kept small.
pub const MAX_UPSTREAM_CREDENTIAL_LEN: usize = 2048;

/// Longest subject an exchange may name, in characters.
pub const MAX_SUBJECT_CHARS: usize = 200;

/// What the provider granted: the credential to seal into the person's tokens and, optionally,
/// who they are.
#[derive(Clone)]
#[non_exhaustive]
pub struct UpstreamGrant {
    /// The credential tools receive, such as the provider's refresh token. Never logged.
    pub credential: String,
    /// Who signed in, as the `sub` of their tokens and the audit log's subject, such as the
    /// provider's user id. It must not reveal the credential, and is readable by anyone who sees
    /// a token or a log line. `None` lets the server name them from the credential
    /// ([`AuthState::subject_of`](crate::oauth::AuthState::subject_of)), which changes every time
    /// the provider grants a new credential.
    pub subject: Option<String>,
}

impl UpstreamGrant {
    /// A grant of `credential`, named by the server.
    pub fn new(credential: impl Into<String>) -> Self {
        UpstreamGrant {
            credential: credential.into(),
            subject: None,
        }
    }

    /// The same grant, naming who signed in.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

impl std::fmt::Debug for UpstreamGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamGrant")
            .field("credential", &"[redacted]")
            .field("subject", &self.subject)
            .finish()
    }
}

/// The outcome of exchanging the provider's authorization code.
#[derive(Debug)]
#[non_exhaustive]
pub enum Exchange {
    /// The provider granted access.
    Granted(UpstreamGrant),
    /// The provider refused the code (expired, already used, or for another client), with a reason
    /// to show the person. Counts as a failed attempt for the sign-in limits.
    Refused(String),
    /// The provider could not be reached or answered unexpectedly: say why. It does not count as
    /// a failed attempt.
    Unavailable(String),
}

/// The future returned by [`UpstreamSignIn::exchange`].
pub type ExchangeFuture<'a> = Pin<Box<dyn Future<Output = Exchange> + Send + 'a>>;

/// The upstream provider's side of the sign-in: where to send people and how to turn the code the
/// provider sends back into a credential.
///
/// ```
/// use mcp_server_core::upstream::{Exchange, ExchangeFuture, UpstreamGrant, UpstreamSignIn};
///
/// struct Example;
///
/// impl UpstreamSignIn for Example {
///     fn provider(&self) -> &str {
///         "Example"
///     }
///     fn authorize_url(&self, redirect_uri: &str, state: &str) -> String {
///         let mut url = url::Url::parse("https://example.com/oauth/authorize").unwrap();
///         url.query_pairs_mut()
///             .append_pair("response_type", "code")
///             .append_pair("client_id", "my-client-id")
///             .append_pair("redirect_uri", redirect_uri)
///             .append_pair("state", state);
///         url.into()
///     }
///     fn exchange<'a>(&'a self, code: &'a str, _redirect_uri: &'a str) -> ExchangeFuture<'a> {
///         Box::pin(async move {
///             // POST the code to the provider's token endpoint here.
///             Exchange::Granted(UpstreamGrant::new(format!("refresh-token-for-{code}")))
///         })
///     }
/// }
/// # fn main() {}
/// ```
pub trait UpstreamSignIn: Send + Sync + 'static {
    /// The provider's name as it reads in a sentence, e.g. "FreeAgent": the sign-in page's button
    /// says "Continue to FreeAgent".
    fn provider(&self) -> &str;
    /// The provider's authorization URL for this sign-in: its authorization endpoint with at least
    /// `response_type=code`, the server's OAuth client id, `redirect_uri` and `state`, each passed
    /// on exactly as given. `redirect_uri` is `PUBLIC_URL/callback`.
    fn authorize_url(&self, redirect_uri: &str, state: &str) -> String;
    /// Exchanges the authorization `code` the provider sent back, at its token endpoint, sending
    /// the same `redirect_uri`. Runs with a timeout.
    fn exchange<'a>(&'a self, code: &'a str, redirect_uri: &'a str) -> ExchangeFuture<'a>;
}

/// A [`CredentialVerifier`] for people who sign in through `upstream`, labelled `label` (such as
/// "FreeAgent account"). Its credentials are carried and never accepted as bearer tokens, and it
/// changes every sign-in's version with `generation` (pass the bytes that should sign everyone out
/// when they change, such as the provider's environment and client id).
pub struct UpstreamVerifier<U> {
    label: String,
    help: String,
    generation: Vec<u8>,
    upstream: U,
}

impl<U: UpstreamSignIn> UpstreamVerifier<U> {
    /// People sign in through `upstream`; `label` names what they sign in with.
    pub fn new(label: impl Into<String>, upstream: U) -> Self {
        UpstreamVerifier {
            label: label.into(),
            help: String::new(),
            generation: Vec::new(),
            upstream,
        }
    }

    /// One sentence of help on the sign-in page.
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = help.into();
        self
    }

    /// Bytes that sign everyone out when they change. See
    /// [`CredentialVerifier::generation`].
    pub fn with_generation(mut self, generation: impl Into<Vec<u8>>) -> Self {
        self.generation = generation.into();
        self
    }

    /// The provider.
    pub fn provider(&self) -> &U {
        &self.upstream
    }
}

impl<U: UpstreamSignIn> CredentialVerifier for UpstreamVerifier<U> {
    fn label(&self) -> &str {
        &self.label
    }
    fn help(&self) -> &str {
        &self.help
    }
    /// Never asked: nothing is typed, and bearer credentials are not accepted.
    fn check<'a>(&'a self, _credential: &'a str) -> CheckFuture<'a> {
        Box::pin(async { CredentialCheck::Invalid(None) })
    }
    fn accepts_bearer(&self) -> bool {
        false
    }
    fn generation(&self) -> &[u8] {
        &self.generation
    }
    fn upstream(&self) -> Option<&dyn UpstreamSignIn> {
        Some(&self.upstream)
    }
}

/// Whether `subject` can name a person: non-empty, at most [`MAX_SUBJECT_CHARS`], no control
/// characters.
pub(crate) fn valid_subject(subject: &str) -> bool {
    !subject.trim().is_empty()
        && subject.chars().count() <= MAX_SUBJECT_CHARS
        && !subject.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake;

    impl UpstreamSignIn for Fake {
        fn provider(&self) -> &str {
            "Fake"
        }
        fn authorize_url(&self, _redirect_uri: &str, _state: &str) -> String {
            "https://fake.example.com/authorize".into()
        }
        fn exchange<'a>(&'a self, _code: &'a str, _redirect_uri: &'a str) -> ExchangeFuture<'a> {
            Box::pin(async { Exchange::Refused("no".into()) })
        }
    }

    #[test]
    fn the_verifier_carries_credentials_but_never_takes_them_as_bearer_tokens() {
        let v = UpstreamVerifier::new("Fake account", Fake)
            .with_help("Sign in at Fake.")
            .with_generation(b"live".to_vec());
        assert_eq!(v.label(), "Fake account");
        assert_eq!(v.help(), "Sign in at Fake.");
        assert!(v.carried());
        assert!(!v.accepts_bearer());
        assert_eq!(v.generation(), b"live");
        assert_eq!(v.upstream().map(|u| u.provider()), Some("Fake"));
    }

    #[tokio::test]
    async fn the_verifier_rejects_anything_checked() {
        let v = UpstreamVerifier::new("Fake account", Fake);
        assert_eq!(v.check("anything").await, CredentialCheck::Invalid(None));
    }

    #[test]
    fn grants_never_show_their_credential() {
        let g = UpstreamGrant::new("secret-refresh-token").with_subject("user:1");
        let shown = format!("{g:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains("user:1"), "{shown}");
    }

    #[test]
    fn subjects_are_short_printable_names() {
        assert!(valid_subject("freeagent:user:123"));
        for bad in ["", "   ", "a\nb", &"x".repeat(MAX_SUBJECT_CHARS + 1)] {
            assert!(!valid_subject(bad), "{bad:?}");
        }
    }
}
