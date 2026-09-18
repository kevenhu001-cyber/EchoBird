//! Typed client for the managed engine's `/v0/management/*` API.
//!
//! Covers exactly what the Account Hub needs: headless OAuth login
//! (`<provider>-auth-url` → browser → poll `get-auth-status`), account
//! list/delete (`auth-files`). Tokens never cross this boundary — only
//! summaries. Every call requires the engine to be running; the key comes
//! from the 0600 secret file (the server hashes its own copy on boot, our
//! plaintext still verifies).

use std::time::Duration;

use super::config::ensure_secret;
use super::management_base;

/// Map EchoBird's provider ids to CLIProxyAPI's `-auth-url` names.
pub fn auth_endpoint(provider: &str) -> Result<String, String> {
    let mapped = match provider {
        "codex" | "openai" => "codex",
        "claude" | "anthropic" => "anthropic",
        // Served by the server's plugin auth-provider path when the
        // backing plugin is installed; otherwise the call 404s and the
        // error surfaces honestly in the UI.
        "gemini" => "gemini-cli",
        "antigravity" => "antigravity",
        "kimi" => "kimi",
        "xai" | "grok" => "xai",
        "devin" | "cognition" => "devin",
        other => return Err(format!("Unknown provider: {other}")),
    };
    Ok(format!("{}/{mapped}-auth-url", management_base()))
}

/// `GET <provider>-auth-url` → `{url, state[, flow, user_code, …]}`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthUrl {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub user_code: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
}

/// `GET get-auth-status?state=` → `ok` (done) / `wait` / `error`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthStatus {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub error: Option<String>,
}

/// One row of `GET auth-files` — display fields only, everything optional
/// so server-side shape drift can't break deserialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AccountEntry {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub disabled: Option<bool>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct AuthFilesResponse {
    #[serde(default)]
    files: Vec<AccountEntry>,
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client failed: {e}"))
}

async fn get_json<T: serde::de::DeserializeOwned>(path_or_url: &str) -> Result<T, String> {
    let secret = ensure_secret()?;
    let url = if path_or_url.starts_with("http") {
        path_or_url.to_string()
    } else {
        format!("{}{path_or_url}", management_base())
    };
    let body = client()?
        .get(&url)
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|e| format!("Engine not reachable ({e}) — is it running?"))?;
    let status = body.status();
    let text = body.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(management_error(&text, status.as_u16()));
    }
    serde_json::from_str(&text).map_err(|e| format!("Cannot parse engine reply: {e}"))
}

async fn delete_req(path: &str) -> Result<(), String> {
    let secret = ensure_secret()?;
    let body = client()?
        .delete(format!("{}{path}", management_base()))
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|e| format!("Engine not reachable ({e}) — is it running?"))?;
    let status = body.status();
    if !status.is_success() {
        let text = body.text().await.unwrap_or_default();
        return Err(management_error(&text, status.as_u16()));
    }
    Ok(())
}

/// Surface the server's own error message when it bothers to send one.
fn management_error(text: &str, status: u16) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(msg) = v
            .get("error")
            .and_then(|e| e.as_str())
            .filter(|s| !s.is_empty())
        {
            return format!("Engine rejected the request ({status}): {msg}");
        }
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        format!("Engine rejected the request ({status})")
    } else {
        format!(
            "Engine rejected the request ({status}): {}",
            trimmed.chars().take(300).collect::<String>()
        )
    }
}

/// Begin a login: returns the URL to open + the session `state` to poll.
pub async fn auth_url(provider: &str) -> Result<AuthUrl, String> {
    get_json(&auth_endpoint(provider)?).await
}

/// Poll one login session. `status` is `ok` / `wait` / `error`.
pub async fn auth_status(state: &str) -> Result<AuthStatus, String> {
    get_json(&format!("/get-auth-status?state={state}")).await
}

/// Cancel a pending login session. Best-effort — the session may already
/// be gone, which still counts as cancelled.
pub async fn auth_cancel(state: &str) -> Result<(), String> {
    delete_req(&format!("/oauth-session?state={state}")).await
}

/// List saved subscription accounts.
pub async fn list_accounts() -> Result<Vec<AccountEntry>, String> {
    Ok(get_json::<AuthFilesResponse>("/auth-files").await?.files)
}

/// Delete one account file by server-side `name`.
pub async fn delete_account(name: &str) -> Result<(), String> {
    delete_req(&format!("/auth-files?name={name}")).await
}
