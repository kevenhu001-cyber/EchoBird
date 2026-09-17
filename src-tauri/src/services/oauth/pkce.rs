// PKCE (Proof Key for Code Exchange, RFC 7636) generator.
//
// Used by every PKCE-based OAuth provider in this crate (Codex, Claude, Gemini,
// Antigravity). Kimi uses RFC 8628 device-code grant instead (no PKCE).
// xAI uses a static API key (no OAuth, no PKCE).
//
// The verifier is 64 URL-safe base64 chars (96 random bytes → 128 chars without
// padding). RFC 7636 only requires 43–128 chars; 128 leaves us well within the
// spec and gives extra entropy. The challenge is the SHA-256 of the verifier,
// URL-safe base64 without padding ("S256" method), which is what every provider
// we target expects.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Verifier + challenge + method, ready to be plugged into the auth URL.
#[derive(Debug, Clone)]
pub struct PkceCodes {
    pub verifier: String,
    pub challenge: String,
    /// Always "S256" — none of our providers accept "plain".
    pub method: &'static str,
}

/// Generate a fresh PKCE pair. Re-call for each new login attempt; reusing
/// the verifier across two parallel logins would let the wrong tab exchange it.
pub fn generate_pkce() -> PkceCodes {
    let mut buf = [0u8; 96];
    rand::thread_rng().fill_bytes(&mut buf);
    let verifier = URL_SAFE_NO_PAD.encode(buf);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    PkceCodes {
        verifier,
        challenge,
        method: "S256",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_url_safe_and_within_rfc_range() {
        let p = generate_pkce();
        // RFC 7636 §4.1: verifier is 43-128 unreserved-char ASCII
        assert!(p.verifier.len() >= 43 && p.verifier.len() <= 128);
        assert!(p
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'));
    }

    #[test]
    fn challenge_is_sha256_of_verifier() {
        let p = generate_pkce();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, expected);
        assert_eq!(p.method, "S256");
    }

    #[test]
    fn two_consecutive_calls_yield_different_verifiers() {
        let a = generate_pkce();
        let b = generate_pkce();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
    }
}