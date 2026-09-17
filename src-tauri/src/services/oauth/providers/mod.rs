// Provider implementations — one module per OAuth flow. Every provider
// exposes a uniform `login` + `refresh` pair so the dispatcher above
// (`refresh::refresh_if_needed`, `mod.rs::login`) can route by enum without
// per-provider `match` arms at the call site.
//
// New providers add: a new file in this directory, a new `OAuthProvider`
// variant, and one more arm in the two `match` blocks below.

use super::account::{OAuthAccount, OAuthProvider};

pub mod claude;
pub mod codex;
pub mod xai;

/// Begin a fresh OAuth login for `provider`.
///
/// `pkce_codes` is `Some` for PKCE providers (Codex, Claude, future
/// Gemini/Antigravity), `None` for device-flow or API-key providers. The
/// callback-server port comes from `provider.callback_port()` — `None` means
/// the provider doesn't use a browser redirect (Kimi device flow, xAI key
/// paste).
///
/// Returns the auth URL the caller must open in the user's browser. The
/// provider module runs the local callback server internally; the caller
/// passes the resulting authorization code to `complete_login` to exchange
/// it for tokens.
///
/// This split exists so the React frontend can drive the browser-open step
/// via `shell_open` and surface the URL even when the user wants to copy it
/// to a phone or remote machine — the local callback server still works
/// because the redirect URI is just `http://localhost:<port>/...`.
pub async fn start_login(
    provider: OAuthProvider,
    pkce_codes: Option<&super::pkce::PkceCodes>,
    state: &str,
) -> Result<
    (
        String,
        tokio::sync::oneshot::Receiver<super::callback_server::CallbackResult>,
    ),
    String,
> {
    match provider {
        OAuthProvider::Codex => {
            codex::start_login(pkce_codes.expect("codex requires PKCE"), state).await
        }
        OAuthProvider::Claude => {
            claude::start_login(pkce_codes.expect("claude requires PKCE"), state).await
        }
        OAuthProvider::Xai => {
            // xAI doesn't use a callback server. The frontend collects the
            // API key directly via a text input and calls submit_xai_key.
            Err("xAI uses API-key input, not OAuth login".to_string())
        }
        // Implemented in M4.
        OAuthProvider::Gemini | OAuthProvider::Antigravity | OAuthProvider::Kimi => Err(format!(
            "{} OAuth login not yet implemented (M4)",
            provider.as_str()
        )),
    }
}

/// Exchange an authorization code (received by the local callback server)
/// for tokens and return the fully-formed account. Persists via
/// `token_store::save_account` before returning.
///
/// `redirect_uri` is the exact URI the provider saw in the auth request
/// (MUST match). For Claude/Codex it's the fixed per-provider localhost URL.
pub async fn complete_login(
    provider: OAuthProvider,
    code: &str,
    state: &str,
    pkce_codes: Option<&super::pkce::PkceCodes>,
    redirect_uri: &str,
) -> Result<OAuthAccount, String> {
    match provider {
        OAuthProvider::Codex => {
            codex::complete_login(code, pkce_codes.expect("codex requires PKCE"), redirect_uri)
                .await
        }
        OAuthProvider::Claude => {
            claude::complete_login(code, state, pkce_codes.expect("claude requires PKCE")).await
        }
        OAuthProvider::Xai => Err("xAI uses submit_xai_key".to_string()),
        OAuthProvider::Gemini | OAuthProvider::Antigravity | OAuthProvider::Kimi => Err(format!(
            "{} OAuth login not yet implemented (M4)",
            provider.as_str()
        )),
    }
}

/// Refresh an existing account's token in place. `account.token` is mutated;
/// `account.expires_at` and `account.last_refresh` get updated by the caller.
pub async fn refresh(provider: OAuthProvider, account: &mut OAuthAccount) -> Result<(), String> {
    match provider {
        OAuthProvider::Codex => codex::refresh(account).await,
        OAuthProvider::Claude => claude::refresh(account).await,
        OAuthProvider::Xai => {
            // xAI API keys don't refresh. Marking Valid so the caller doesn't
            // keep retrying.
            Ok(())
        }
        OAuthProvider::Gemini | OAuthProvider::Antigravity | OAuthProvider::Kimi => Err(format!(
            "{} refresh not yet implemented (M4)",
            provider.as_str()
        )),
    }
}
