// CLIProxyAPI Commands — Tauri IPC for the Account Hub.
// The managed engine (services::cliproxy) holds the subscription accounts;
// these commands are thin IPC wrappers plus the tool-pointing helper.

use tauri::State;

use crate::services::cliproxy::management::{self, AccountEntry, AuthStatus, AuthUrl};
use crate::services::cliproxy::{base_url, config, CliproxyState, CliproxyStatus};

/// Installed? Which release? Alive?
#[tauri::command]
pub async fn cliproxy_status(state: State<'_, CliproxyState>) -> Result<CliproxyStatus, String> {
    Ok(state.status())
}

/// Download the latest engine release when missing (long: shows as a
/// spinner in the UI). Returns the installed tag.
#[tauri::command]
pub async fn cliproxy_download(state: State<'_, CliproxyState>) -> Result<String, String> {
    state.ensure_binary().await
}

/// Start the managed engine (idempotent).
#[tauri::command]
pub async fn cliproxy_start(state: State<'_, CliproxyState>) -> Result<(), String> {
    state.start().await
}

/// Stop the managed engine (idempotent).
#[tauri::command]
pub async fn cliproxy_stop(state: State<'_, CliproxyState>) -> Result<(), String> {
    state.stop()
}

/// Begin a subscription login. Returns the URL to open in the browser plus
/// the session `state` the frontend polls via `cliproxy_auth_status`.
/// Device flows (Kimi/xAI) additionally return `flow: "device"` and may
/// include `user_code` to display.
#[tauri::command]
pub async fn cliproxy_auth_url(provider: String) -> Result<AuthUrl, String> {
    management::auth_url(provider.trim()).await
}

/// Poll one login session: `ok` (saved) / `wait` / `error`.
#[tauri::command]
pub async fn cliproxy_auth_status(state: String) -> Result<AuthStatus, String> {
    management::auth_status(state.trim()).await
}

/// Cancel a pending login session (best-effort).
#[tauri::command]
pub async fn cliproxy_auth_cancel(state: String) -> Result<(), String> {
    management::auth_cancel(state.trim()).await
}

/// List saved subscription accounts (summaries only — tokens stay server-side).
#[tauri::command]
pub async fn cliproxy_accounts() -> Result<Vec<AccountEntry>, String> {
    management::list_accounts().await
}

/// Delete one account by server-side file name.
#[tauri::command]
pub async fn cliproxy_delete_account(name: String) -> Result<(), String> {
    management::delete_account(name.trim()).await
}

/// Point a Claude-family tool directly at the managed engine (relay mode —
/// single hop, no EchoBird proxy in between). `tool_id` is `claudecode`
/// or `claudedesktop`; `model` is the Anthropic model id to pin, passed
/// through to the engine verbatim (it routes across all pooled accounts).
#[tauri::command]
pub async fn cliproxy_apply_to_tool(tool_id: String, model: String) -> Result<String, String> {
    if tool_id != "claudecode" && tool_id != "claudedesktop" {
        return Err(format!(
            "Only claudecode/claudedesktop can be pointed at the engine yet (got {tool_id})"
        ));
    }
    let model = model.trim();
    if model.is_empty() {
        return Err("Model id is empty".to_string());
    }
    let api_key = config::ensure_api_key()?;
    let info = crate::services::tool_config_manager::ModelInfo {
        name: Some(model.to_string()),
        model: Some(model.to_string()),
        base_url: Some(base_url()),
        api_key: Some(api_key),
        anthropic_url: None,
        protocol: Some("anthropic".to_string()),
        display_model: None,
        relay_mode: Some(true),
        one_m_context: None,
    };
    let result =
        crate::services::tool_config_manager::apply_model_to_tool(&tool_id, info).await;
    if result.success {
        Ok(result.message)
    } else {
        Err(result.message)
    }
}
