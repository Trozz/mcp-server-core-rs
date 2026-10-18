//! Who made a request. The bearer guard adds a [`Caller`] to every request it lets through.
//!
//! ```
//! use mcp_server_core::axum::http::request::Parts;
//! use mcp_server_core::caller::Caller;
//!
//! /// The subject to attribute a change to, from a tool's `Extension<Parts>` argument.
//! fn who(parts: &Parts) -> Option<&str> {
//!     parts.extensions.get::<Caller>().map(|c| c.subject.as_str())
//! }
//! ```

/// Who made a request, and how they proved it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Caller {
    /// Who signed in: `owner` for the owner's password, `key:<16 hex digits>` for a person's own
    /// credential, `static` for the static token, or what a custom verifier names
    /// ([`CredentialVerifier::subject`](crate::credential::CredentialVerifier::subject)).
    pub subject: String,
    /// How the request was authenticated.
    pub via: Via,
}

/// How a request was authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Via {
    /// An OAuth access token this server issued, to this client.
    OAuth {
        /// The client the token was issued to.
        client_id: Option<String>,
    },
    /// The person's credential sent directly as the bearer token.
    Credential,
    /// The static token (`MCP_AUTH_TOKEN`).
    StaticToken,
}

/// The subject of requests made with the static token.
pub const STATIC_SUBJECT: &str = "static";

impl Caller {
    /// A caller, for middleware of your own or tests.
    pub fn new(subject: impl Into<String>, via: Via) -> Self {
        Caller {
            subject: subject.into(),
            via,
        }
    }

    /// How the audit log names the way in: `oauth:<client_id>`, `oauth`, `credential` or
    /// `static`.
    pub fn audit_label(&self) -> String {
        match &self.via {
            Via::OAuth {
                client_id: Some(id),
            } => format!("oauth:{id}"),
            Via::OAuth { client_id: None } => "oauth".into(),
            Via::Credential => "credential".into(),
            Via::StaticToken => STATIC_SUBJECT.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_labels_name_the_way_in() {
        let c = |via| Caller::new("owner", via).audit_label();
        assert_eq!(
            c(Via::OAuth {
                client_id: Some("c1".into())
            }),
            "oauth:c1"
        );
        assert_eq!(c(Via::OAuth { client_id: None }), "oauth");
        assert_eq!(c(Via::Credential), "credential");
        assert_eq!(c(Via::StaticToken), "static");
    }
}
