// xAI (Grok) account. They don't expose OAuth; users paste an API key from
// https://console.x.ai/ → API Keys. We persist it the same way as OAuth
// tokens (encrypted on disk, never sent back to the frontend) so the rest
// of the system can treat xAI as just another OAuth account.
//
// "Login" here is just: validate the key with a tiny `GET /v1/api-key`
// request, then persist. "Refresh" is a no-op (keys don't expire).

use super::super::account::{OAuthAccount, OAuthProvider, OAuthStatus};
use super::super::refresh::now_iso8601;
use super::super::token_store;

pub const DISPLAY_LABEL: &str = "xAI";

/// Validate the key and persist as an xAI OAuth account.
///
/// `api_key` is what the user pasted. We prefix a stable identifier onto
/// `display_name` so two xAI keys both end up in the list (rather than
/// overwriting each other). The "primary" account uses just the email; if
/// the user wants a second one, they can pick a different file name in the
/// advanced settings dialog (out of scope for M1).
pub async fn submit_api_key(
    api_key: &str,
    display_name: Option<&str>,
) -> Result<OAuthAccount, String> {
    let trimmed = api_key.trim();
    if trimmed.is_empty() {
        return Err("xAI API key is empty".to_string());
    }
    // Quick validation: hit a cheap endpoint and confirm 200.
    let resp = reqwest::Client::new()
        .get("https://api.x.ai/v1/api-key")
        .bearer_auth(trimmed)
        .send()
        .await
        .map_err(|e| format!("xAI key validation request failed: {e}"))?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err("xAI rejected the API key (HTTP 401/403). Check the key.".to_string());
    }
    // Even a non-200 is fine — the key might lack `api-key:read` scope but
    // still be a valid chat key. We only fail on 401/403 which are auth.
    let _ = status;

    let identifier = display_name.unwrap_or("primary").to_string();
    let account = OAuthAccount {
        provider: OAuthProvider::Xai,
        file_name: token_store::file_name_for(OAuthProvider::Xai, &identifier),
        account_id: identifier.clone(),
        display_name: format!("xAI · {identifier}"),
        created_at: now_iso8601(),
        last_refresh: now_iso8601(),
        expires_at: None,
        status: OAuthStatus::Valid,
        token: serde_json::json!({
            "api_key": trimmed,
        }),
    };
    token_store::save_account(&account)?;
    Ok(account)
}

// Stub for the provider dispatcher. xAI doesn't refresh, but the dispatcher
// calls us anyway so we still need to implement it.
