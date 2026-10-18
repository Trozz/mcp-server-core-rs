//! PKCE (RFC 7636) and constant-time comparison.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// `BASE64URL(SHA256(input))`, the S256 code challenge of a verifier.
pub fn s256(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

/// Compares two secrets in constant time (of their SHA-256 digests, so length leaks nothing).
pub fn ct_eq(a: &str, b: &str) -> bool {
    Sha256::digest(a.as_bytes())
        .as_slice()
        .ct_eq(Sha256::digest(b.as_bytes()).as_slice())
        .into()
}

fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Whether `verifier` is a well-formed code verifier whose S256 challenge is `challenge`.
pub fn verify(verifier: &str, challenge: &str) -> bool {
    if !valid_verifier(verifier) {
        return false;
    }
    ct_eq(&s256(verifier), challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            s256(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(verify(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn rejects_wrong_verifier() {
        assert!(!verify(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXx",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn rejects_verifier_with_bad_length_or_charset() {
        let short = "a".repeat(42);
        assert!(!verify(&short, &s256(&short)));
        let long = "a".repeat(129);
        assert!(!verify(&long, &s256(&long)));
        let bad = format!("{}!", "a".repeat(42));
        assert!(!verify(&bad, &s256(&bad)));
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }
}
