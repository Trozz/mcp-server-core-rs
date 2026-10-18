//! The server's own tokens: HS256 JWTs signed with `OAUTH_SIGNING_KEY`.

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Seconds a token is still accepted after its `exp`, for clock skew.
pub const LEEWAY_SECS: u64 = 5;

/// What a token is for, in its `typ` claim; a token of one kind is never accepted as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// A registered client: the `client_id` itself. Does not expire.
    Client,
    /// Binds a sign-in form to its authorization request.
    Csrf,
    /// An authorization code, used once.
    Code,
    /// An access token for one service.
    Access,
    /// A refresh token.
    Refresh,
}

/// The claims that depend on the token's kind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// The client a code, access or refresh token was issued to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// A client's registered redirect URIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,
    /// A client's self-reported name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// The redirect URI a code was issued for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// A code's PKCE challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    /// The service granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The resource URL granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// A CSRF token's hash of its authorization request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    /// The person's credential, sealed by `credential::Sealer` (code, access and refresh tokens).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// A token's claims. The bearer guard adds an access token's claims to the request extensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer: `PUBLIC_URL`.
    pub iss: String,
    /// Audience: a service's resource URL for access tokens, `PUBLIC_URL` otherwise.
    pub aud: String,
    /// Subject.
    pub sub: String,
    /// The token's kind.
    pub typ: TokenKind,
    /// Unique id.
    pub jti: String,
    /// Issued at, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds; client tokens have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// The kind-specific claims.
    #[serde(flatten)]
    pub payload: Payload,
}

/// Why a token was refused.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    /// Malformed, badly signed, expired, or for another issuer or audience.
    #[error("invalid token")]
    Invalid,
    /// Valid, but of another [`TokenKind`].
    #[error("wrong token kind")]
    WrongKind,
}

/// A random token id: 128 bits, base64url.
fn new_jti() -> Result<String, JwtError> {
    use base64::Engine as _;
    use ring::rand::SecureRandom as _;
    let mut id = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| JwtError::Invalid)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id))
}

/// Issues and verifies the server's tokens.
pub struct Jwt {
    enc: EncodingKey,
    dec: DecodingKey,
    issuer: String,
    audience: String,
}

impl Jwt {
    /// Signs with `secret`, as `issuer`, for the default `audience`.
    pub fn new(secret: &[u8], issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            enc: EncodingKey::from_secret(secret),
            dec: DecodingKey::from_secret(secret),
            issuer: issuer.into(),
            audience: audience.into(),
        }
    }

    /// Issues a token for the default audience (the authorization server itself).
    pub fn issue(
        &self,
        typ: TokenKind,
        ttl: Option<Duration>,
        payload: Payload,
    ) -> Result<String, JwtError> {
        self.issue_for(typ, ttl, payload, &self.audience)
    }

    /// Issues a token whose `aud` is `audience`, e.g. an access token bound to one resource.
    pub fn issue_for(
        &self,
        typ: TokenKind,
        ttl: Option<Duration>,
        payload: Payload,
        audience: &str,
    ) -> Result<String, JwtError> {
        let now = get_current_timestamp();
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: audience.to_string(),
            sub: "owner".into(),
            typ,
            jti: new_jti()?,
            iat: now,
            exp: ttl.map(|d| now + d.as_secs()),
            payload,
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.enc).map_err(|_| JwtError::Invalid)
    }

    /// Verifies a token issued for the default audience.
    pub fn verify(&self, token: &str, typ: TokenKind) -> Result<Claims, JwtError> {
        self.verify_for(token, typ, &self.audience)
    }

    /// Verifies a token and requires its `aud` to be exactly `audience`.
    pub fn verify_for(
        &self,
        token: &str,
        typ: TokenKind,
        audience: &str,
    ) -> Result<Claims, JwtError> {
        let mut v = Validation::new(Algorithm::HS256);
        v.set_audience(&[audience]);
        v.set_issuer(&[&self.issuer]);
        v.leeway = LEEWAY_SECS;
        if typ == TokenKind::Client {
            v.validate_exp = false;
            v.set_required_spec_claims(&["iss", "aud", "sub"]);
        } else {
            v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        }
        let claims = decode::<Claims>(token, &self.dec, &v)
            .map_err(|_| JwtError::Invalid)?
            .claims;
        if claims.typ != typ {
            return Err(JwtError::WrongKind);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn jwt() -> Jwt {
        Jwt::new(
            KEY,
            "https://mail.example.com",
            "https://mail.example.com/mcp",
        )
    }

    #[test]
    fn roundtrip_access_token() {
        let j = jwt();
        let payload = Payload {
            client_id: Some("c1".into()),
            scope: Some("mail".into()),
            ..Default::default()
        };
        let t = j
            .issue(
                TokenKind::Access,
                Some(Duration::from_secs(60)),
                payload.clone(),
            )
            .unwrap();
        let c = j.verify(&t, TokenKind::Access).unwrap();
        assert_eq!(c.payload, payload);
        assert_eq!(c.typ, TokenKind::Access);
        assert!(c.exp.is_some());
    }

    #[test]
    fn every_token_gets_a_fresh_random_id() {
        let j = jwt();
        let ids: std::collections::HashSet<String> = (0..100)
            .map(|_| {
                let t = j
                    .issue(TokenKind::Client, None, Payload::default())
                    .unwrap();
                j.verify(&t, TokenKind::Client).unwrap().jti
            })
            .collect();
        assert_eq!(ids.len(), 100);
        assert!(ids.iter().all(|id| id.len() == 22), "{ids:?}");
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let j = jwt();
        for kind in [TokenKind::Refresh, TokenKind::Code, TokenKind::Csrf] {
            let t = j
                .issue(kind, Some(Duration::from_secs(60)), Payload::default())
                .unwrap();
            assert!(matches!(
                j.verify(&t, TokenKind::Access),
                Err(JwtError::WrongKind)
            ));
        }
        let client = j
            .issue(TokenKind::Client, None, Payload::default())
            .unwrap();
        assert!(j.verify(&client, TokenKind::Access).is_err());
    }

    #[test]
    fn client_tokens_have_no_expiry_and_verify() {
        let j = jwt();
        let t = j
            .issue(
                TokenKind::Client,
                None,
                Payload {
                    redirect_uris: Some(vec!["https://a/cb".into()]),
                    ..Default::default()
                },
            )
            .unwrap();
        let c = j.verify(&t, TokenKind::Client).unwrap();
        assert_eq!(c.exp, None);
    }

    #[test]
    fn non_client_tokens_require_expiry() {
        let j = jwt();
        let t = j
            .issue(TokenKind::Access, None, Payload::default())
            .unwrap();
        assert!(j.verify(&t, TokenKind::Access).is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        let j = jwt();
        let claims = Claims {
            iss: "https://mail.example.com".into(),
            aud: "https://mail.example.com/mcp".into(),
            sub: "owner".into(),
            typ: TokenKind::Access,
            jti: "x".into(),
            iat: get_current_timestamp() - 200,
            exp: Some(get_current_timestamp() - 100),
            payload: Payload::default(),
        };
        let t = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(KEY),
        )
        .unwrap();
        assert!(j.verify(&t, TokenKind::Access).is_err());
    }

    #[test]
    fn other_audience_is_rejected() {
        let other = Jwt::new(
            KEY,
            "https://mail.example.com",
            "https://cal.example.com/mcp",
        );
        let t = other
            .issue(
                TokenKind::Access,
                Some(Duration::from_secs(60)),
                Payload::default(),
            )
            .unwrap();
        assert!(jwt().verify(&t, TokenKind::Access).is_err());
    }

    #[test]
    fn audience_bound_token_verifies_only_for_that_audience() {
        let j = jwt();
        let t = j
            .issue_for(
                TokenKind::Access,
                Some(Duration::from_secs(60)),
                Payload::default(),
                "https://mail.example.com/mail",
            )
            .unwrap();
        let c = j
            .verify_for(&t, TokenKind::Access, "https://mail.example.com/mail")
            .unwrap();
        assert_eq!(c.aud, "https://mail.example.com/mail");
        assert!(
            j.verify_for(&t, TokenKind::Access, "https://mail.example.com/calendar")
                .is_err()
        );
        assert!(j.verify(&t, TokenKind::Access).is_err());
    }

    #[test]
    fn other_issuer_is_rejected() {
        let other = Jwt::new(
            KEY,
            "https://other.example.com",
            "https://mail.example.com/mcp",
        );
        let t = other
            .issue(
                TokenKind::Access,
                Some(Duration::from_secs(60)),
                Payload::default(),
            )
            .unwrap();
        assert!(jwt().verify(&t, TokenKind::Access).is_err());
    }

    #[test]
    fn other_key_is_rejected() {
        let other = Jwt::new(
            b"ffffffffffffffffffffffffffffffff",
            "https://mail.example.com",
            "https://mail.example.com/mcp",
        );
        let t = other
            .issue(
                TokenKind::Access,
                Some(Duration::from_secs(60)),
                Payload::default(),
            )
            .unwrap();
        assert!(jwt().verify(&t, TokenKind::Access).is_err());
    }

    #[test]
    fn token_without_aud_is_rejected() {
        #[derive(Serialize)]
        struct NoAud {
            iss: String,
            sub: String,
            typ: TokenKind,
            jti: String,
            iat: u64,
            exp: u64,
        }
        let t = encode(
            &Header::new(Algorithm::HS256),
            &NoAud {
                iss: "https://mail.example.com".into(),
                sub: "owner".into(),
                typ: TokenKind::Access,
                jti: "x".into(),
                iat: get_current_timestamp(),
                exp: get_current_timestamp() + 60,
            },
            &EncodingKey::from_secret(KEY),
        )
        .unwrap();
        assert!(jwt().verify(&t, TokenKind::Access).is_err());
    }
}
