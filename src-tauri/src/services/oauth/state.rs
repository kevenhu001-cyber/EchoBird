// OAuth `state` parameter — a random, single-use anti-CSRF string.
//
// All PKCE providers (Codex, Claude, Gemini, Antigravity) require the auth URL
// to carry a `state` we generate ourselves and verify against the callback.
// The callback handler compares what came back to what we sent; mismatch means
// the redirect was forged or wrong, so we drop it.
//
// We deliberately do NOT put data in state (e.g. provider name). Providers all
// pick a distinct callback path (e.g. /auth/callback vs /callback), and the
// running task list knows which provider started which server, so we just need
// a globally-unique token to bind the redirect back to the waiting task.

use rand::RngCore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// 32 random bytes → 43 URL-safe base64 chars. Plenty of entropy for CSRF.
pub fn generate_state() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_url_safe_and_long_enough() {
        let s = generate_state();
        assert_eq!(s.len(), 43);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn two_states_are_different() {
        assert_ne!(generate_state(), generate_state());
    }
}