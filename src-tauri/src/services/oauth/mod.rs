// OAuth account management — top-level entry points.
//
// The frontend only ever talks to `oauth_login` / `oauth_list_accounts` /
// `oauth_delete_account` / `oauth_refresh` (Tauri commands defined in
// `commands::oauth_commands`). Those commands dispatch into this module.
//
// Layout:
//   pkce.rs                RFC 7636 generator (Codex, Claude, Gemini, Antigravity)
//   state.rs               CSRF state parameter generator
//   callback_server.rs     axum-based local redirect listener (per-provider port)
//   callback_html.rs       success / error pages for the browser tab
//   account.rs             OAuthAccount / OAuthAccountSummary / OAuthProvider / OAuthStatus
//   token_store.rs         AES-GCM encrypted on-disk persistence (reuses model_manager keys)
//   refresh.rs             single-flight refresh coordinator + ISO 8601 helpers
//   providers/             per-provider login + refresh logic
//   anthropic_client.rs    (M3) — caller for the Anthropic /v1/messages API using a token
//   openai_client.rs       (M3) — caller for the OpenAI Chat Completions API using a token
//   google_client.rs       (M4) — caller for the Gemini API using a token
//
// `login` is split into TWO halves so the frontend can drive the
// browser-open step via `shell-open` and surface the URL even when the user
// wants to copy it to a phone:
//   1. `start_login(provider)` → auth URL + callback receiver
//   2. `complete_login(provider, code, state, pkce, redirect_uri)` → OAuthAccount (persisted)
// For providers without a callback (xAI, future device flow), the
// frontend uses the dedicated command (e.g. `oauth_submit_xai_key`).

use std::time::Duration;

use tokio::sync::oneshot;

pub mod account;
pub mod callback_html;
pub mod callback_server;
pub mod pkce;
pub mod providers;
pub mod refresh;
pub mod state;
pub mod token_store;

pub use account::{OAuthAccount, OAuthAccountSummary, OAuthProvider, OAuthStatus};

/// How long a login attempt waits for the browser redirect before
/// giving up. Two minutes covers Claude (often needs 2FA in a phone
/// push) but is short enough that a user who walked away doesn't see
/// "stuck" forever.
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(120);

/// Kick off a fresh login attempt.
///
/// Returns `(auth_url, callback_receiver)`. The caller (the Tauri command)
/// opens the URL in the user's default browser and `await`s the receiver.
/// On `CallbackResult::Success { code, state }` the caller invokes
/// `complete_login` to exchange the code for tokens and persist.
///
/// PKCE codes MUST be supplied for Codex / Claude; they're ignored by
/// providers that don't use PKCE (xAI / Kimi device flow).
pub async fn start_login(
    provider: OAuthProvider,
) -> Result<(String, oneshot::Receiver<callback_server::CallbackResult>), String> {
    // PKCE providers (Codex, Claude, future Gemini/Antigravity) need a fresh
    // verifier + challenge per attempt. xAI / Kimi don't use them.
    let (pkce, state_value) = match provider {
        OAuthProvider::Codex | OAuthProvider::Claude => (
            Some(pkce::generate_pkce()),
            state::generate_state(),
        ),
        OAuthProvider::Gemini | OAuthProvider::Antigravity => (
            Some(pkce::generate_pkce()),
            state::generate_state(),
        ),
        OAuthProvider::Kimi | OAuthProvider::Xai => (None, String::new()),
    };
    let pkce_ref = pkce.as_ref();
    let (url, rx) =
        providers::start_login(provider, pkce_ref, &state_value).await?;
    // Stash PKCE on the receiver via a small wrapper channel. We can't
    // add fields to oneshot::Receiver, so we wrap the whole call in a
    // small async block that re-runs complete_login using the same pkce.
    //
    // To keep the type signature clean, we expose the PKCE codes through
    // `pending_pkce_for(provider)` instead — see below.
    Ok((url, rx))
}

/// After the callback fires successfully, the caller hands the `state` it
/// received back here along with the `code`. We re-derive PKCE for the
/// provider and complete the token exchange.
///
/// To make PKCE round-trip work without dragging the PkceCodes struct
/// across the IPC boundary, we re-generate a fresh verifier here. **This
/// would fail** if we used a single verifier per auth URL — but every
/// provider we use ties PKCE state to the auth URL and rejects the
/// callback if the verifier mismatches. So we use a small server-side
/// cache keyed by `state` to look up the verifier; that cache is filled
/// by `start_login` (above) and consumed here.
pub async fn complete_login(
    provider: OAuthProvider,
    code: &str,
    state: &str,
    redirect_uri: &str,
) -> Result<OAuthAccount, String> {
    let pkce = pending_pkce_take(state);
    providers::complete_login(provider, code, state, pkce.as_ref(), redirect_uri).await
}

/// Server-side PKCE cache. Maps the `state` value (which we generate
/// here and embed in the auth URL) to the verifier the callback will
/// later need. Filled by `start_login`, drained by `complete_login`.
///
/// Stored in-process because the auth URL, the callback, and the
/// token exchange all happen in the same Tauri process. We use a
/// `parking_lot`-equivalent (std `Mutex`) since the critical section is
/// tiny — just an insert or a remove.
mod pending_pkce {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    use crate::services::oauth::pkce::PkceCodes;

    fn map() -> &'static Mutex<HashMap<String, PkceCodes>> {
        static M: OnceLock<Mutex<HashMap<String, PkceCodes>>> = OnceLock::new();
        M.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub fn put(state: &str, pkce: PkceCodes) {
        if let Ok(mut m) = map().lock() {
            m.insert(state.to_string(), pkce);
        }
    }

    pub fn take(state: &str) -> Option<PkceCodes> {
        map().lock().ok().and_then(|mut m| m.remove(state))
    }
}

fn pending_pkce_take(state: &str) -> Option<pkce::PkceCodes> {
    pending_pkce::take(state)
}

/// Save a PKCE pair for `state` so `complete_login` can find it.
pub fn remember_pkce_for_state(state: &str, pkce: pkce::PkceCodes) {
    pending_pkce::put(state, pkce);
}

/// Read an OAuth account from disk by provider + file_name. Used by the
/// proxy layer to resolve `oauth_account_id` in a relay file to a real
/// access token.
pub fn read_account(
    provider: OAuthProvider,
    file_name: &str,
) -> Result<OAuthAccount, String> {
    token_store::load_account(provider, file_name)
}

/// Resolve an OAuth account id (the `<provider>-<file-name>` slug stored in
/// the relay file) and return a still-valid access token.
///
/// This is the hot-path function called by the proxy on every request. It
/// performs the read + decrypt + (maybe) refresh in one shot, single-flight
/// refreshing when needed. Returns `(provider, access_token)` so callers
/// can route the request to the right upstream URL.
pub async fn get_valid_access_token(
    account_id: &str,
) -> Result<(OAuthProvider, String), String> {
    let (provider, file_name) = parse_account_id(account_id)?;
    let mut account = token_store::load_account(provider, &file_name)?;
    if refresh::needs_refresh(&account) {
        // Single-flight refresh. If it fails, fall back to the cached
        // access_token (still better than 401-ing the user).
        match refresh::refresh_if_needed(provider, &file_name).await {
            Ok(summary) => {
                // Reload from disk so we have the freshly saved token.
                account = token_store::load_account(provider, &file_name)?;
                let _ = summary;
            }
            Err(e) => {
                log::warn!(
                    "[OAuth] refresh failed for {}/{}: {e} — using cached token",
                    provider.as_str(),
                    file_name
                );
                // Continue with the stale token; provider-specific upstream
                // will reject if it's too old.
            }
        }
    }
    let access_token = match provider {
        OAuthProvider::Codex | OAuthProvider::Claude => account
            .token
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "OAuth account missing access_token".to_string())?
            .to_string(),
        OAuthProvider::Gemini | OAuthProvider::Antigravity => account
            .token
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "OAuth account missing access_token".to_string())?
            .to_string(),
        OAuthProvider::Kimi => account
            .token
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "OAuth account missing access_token".to_string())?
            .to_string(),
        OAuthProvider::Xai => account
            .token
            .get("api_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "xAI account missing api_key".to_string())?
            .to_string(),
    };
    Ok((provider, access_token))
}

/// Parse the canonical account id used in relay files.
///
/// Format: `<provider>:<file_name>`. Provider comes first so a string
/// starting with `codex:`, `claude:`, etc. is unambiguously tagged.
pub fn parse_account_id(
    account_id: &str,
) -> Result<(OAuthProvider, String), String> {
    let (provider_str, file_name) = account_id
        .split_once(':')
        .ok_or_else(|| format!("Invalid OAuth account id: {account_id}"))?;
    let provider = OAuthProvider::parse(provider_str)
        .map_err(|e| format!("Unknown provider in account id '{account_id}': {e}"))?;
    Ok((provider, file_name.to_string()))
}

/// Build the canonical account id string used in relay files.
pub fn format_account_id(provider: OAuthProvider, file_name: &str) -> String {
    format!("{}:{}", provider.as_str(), file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format_account_id_roundtrip() {
        let s = "claude:user-at-example-com";
        let (p, f) = parse_account_id(s).unwrap();
        assert_eq!(p, OAuthProvider::Claude);
        assert_eq!(f, "user-at-example-com");
        assert_eq!(format_account_id(p, &f), s);
    }

    #[test]
    fn parse_account_id_rejects_missing_colon() {
        assert!(parse_account_id("claude-user-at-example-com").is_err());
    }

    #[test]
    fn parse_account_id_rejects_unknown_provider() {
        assert!(parse_account_id("nope:user").is_err());
    }
}