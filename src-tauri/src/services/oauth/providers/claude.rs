// Anthropic Claude OAuth2 PKCE provider.
//
// Public client id and redirect URI come from the official Claude Code CLI
// (we cross-checked with CLIProxyAPI/internal/auth/claude). Same caveats as
// Codex: they're public identifiers, not secrets.
//
// Field order on the token-exchange request matters: the upstream server
// logs the JSON key order for fingerprint checks. We marshal via a typed
// struct so the order matches what the native CLI sends.

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use super::super::account::{OAuthAccount, OAuthProvider, OAuthStatus};
use super::super::callback_server::{self, CallbackResult};
use super::super::pkce::PkceCodes;
use super::super::refresh::{expiry_from_now, now_iso8601};
use super::super::token_store;

pub const AUTH_URL: &str = "https://claude.ai/oauth/authorize";
pub const TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const REDIRECT_URI: &str = "http://localhost:54545/callback";
pub const SCOPE: &str =
    "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";
pub const CALLBACK_PORT: u16 = 54545;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct CodeExchangeRequest<'a> {
    grant_type: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    client_id: &'a str,
    code_verifier: &'a str,
    state: &'a str,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    #[serde(default)]
    account: Option<AccountBlock>,
    #[serde(default)]
    organization: Option<OrgBlock>,
}

#[derive(Deserialize, Default)]
struct AccountBlock {
    #[serde(default)]
    uuid: String,
    #[serde(default, rename = "email_address")]
    email_address: String,
}

#[derive(Deserialize, Default)]
struct OrgBlock {
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    name: String,
}

pub async fn start_login(
    pkce: &PkceCodes,
    state: &str,
) -> Result<(String, oneshot::Receiver<CallbackResult>), String> {
    let port = CALLBACK_PORT;
    callback_server::preflight_port(port).await?;
    let (tx, rx) = oneshot::channel();
    let label = "Claude";
    let state_clone = state.to_string();
    tokio::spawn(async move {
        if let Err(e) = callback_server::run(port, label, &state_clone, tx).await {
            log::error!("[OAuthClaude] callback server error: {e}");
        }
    });
    Ok((build_auth_url(state, &pkce.challenge), rx))
}

pub fn build_auth_url(state: &str, challenge: &str) -> String {
    // The `code=true` quirk comes from the upstream CLI's trace — server
    // appears to look at it but ignoring it is harmless.
    let params = [
        ("code", "true"),
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", SCOPE),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
    ];
    let qs: String = params
        .into_iter()
        .map(|(k, v)| format!("{k}={}", url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()))
        .collect::<Vec<_>>()
        .join("&");
    format!("{AUTH_URL}?{qs}")
}

pub async fn complete_login(
    code: &str,
    state: &str,
    pkce: &PkceCodes,
) -> Result<OAuthAccount, String> {
    // The `code` parameter from Claude can carry an extra `#state` fragment;
    // strip it so we don't send back a malformed token-exchange body.
    let (pure_code, fragment_state) = split_code_state(code);
    let effective_state = if !fragment_state.is_empty() {
        fragment_state
    } else {
        state.to_string()
    };

    let req_body = CodeExchangeRequest {
        grant_type: "authorization_code",
        code: pure_code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: &pkce.verifier,
        state: &effective_state,
    };

    let resp = reqwest::Client::new()
        .post(TOKEN_URL)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&req_body)
        .send()
        .await
        .map_err(|e| format!("Claude token exchange request failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Read Claude token response: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "Claude token exchange failed (HTTP {}): {}",
            status, text
        ));
    }
    let tr: TokenResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Parse Claude token response: {e}"))?;

    let account_id = tr.account.as_ref().and_then(|a| {
        if a.uuid.is_empty() {
            None
        } else {
            Some(a.uuid.clone())
        }
    })
    .unwrap_or_default();
    let email = tr
        .account
        .as_ref()
        .map(|a| a.email_address.clone())
        .unwrap_or_default();
    let org_uuid = tr
        .organization
        .as_ref()
        .map(|o| o.uuid.clone())
        .unwrap_or_default();
    let org_name = tr
        .organization
        .as_ref()
        .map(|o| o.name.clone())
        .unwrap_or_default();

    let account_id = if account_id.is_empty() {
        if email.is_empty() {
            // Fallback: dump the whole access token's first 8 chars so the
            // user can at least distinguish two Claude accounts in the list.
            format!("anon-{}", &tr.access_token[..8.min(tr.access_token.len())])
        } else {
            email.clone()
        }
    } else {
        account_id
    };
    let display_name = if !email.is_empty() {
        email
    } else {
        account_id.clone()
    };

    let account = OAuthAccount {
        provider: OAuthProvider::Claude,
        file_name: token_store::file_name_for(OAuthProvider::Claude, &account_id),
        account_id,
        display_name,
        created_at: now_iso8601(),
        last_refresh: now_iso8601(),
        expires_at: Some(expiry_from_now(tr.expires_in)),
        status: OAuthStatus::Valid,
        token: serde_json::json!({
            "access_token": tr.access_token,
            "refresh_token": tr.refresh_token,
            "expires_in": tr.expires_in,
            "organization_uuid": org_uuid,
            "organization_name": org_name,
        }),
    };
    token_store::save_account(&account)?;
    Ok(account)
}

pub async fn refresh(account: &mut OAuthAccount) -> Result<(), String> {
    let refresh_token = account
        .token
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Claude account missing refresh_token".to_string())?
        .to_string();

    #[derive(Serialize)]
    struct RefreshBody<'a> {
        client_id: &'a str,
        grant_type: &'a str,
        refresh_token: &'a str,
        scope: &'a str,
    }
    let body = RefreshBody {
        client_id: CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: &refresh_token,
        scope: SCOPE,
    };
    let resp = reqwest::Client::new()
        .post(TOKEN_URL)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Claude refresh request failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Read Claude refresh response: {e}"))?;
    if !status.is_success() {
        // 429 specifically signals rate-limit; mark the account as still
        // valid for now (we'll retry on the next request) but warn loudly.
        if status.as_u16() == 429 {
            log::warn!("[Claude] refresh rate-limited (429); keeping current token");
            return Err("Claude refresh rate-limited (HTTP 429)".to_string());
        }
        if status.as_u16() == 401 || status.as_u16() == 400 {
            // Refresh token rejected — user must re-login.
            account.status = OAuthStatus::RefreshFailed;
        }
        return Err(format!(
            "Claude refresh failed (HTTP {}): {}",
            status, text
        ));
    }
    let tr: TokenResponse = serde_json::from_str(&text)
        .map_err(|e| format!("Parse Claude refresh response: {e}"))?;
    account.token["access_token"] = serde_json::Value::String(tr.access_token);
    // Some refresh responses omit refresh_token; keep the old one.
    if !tr.refresh_token.is_empty() {
        account.token["refresh_token"] = serde_json::Value::String(tr.refresh_token);
    }
    account.token["expires_in"] = serde_json::Value::Number(tr.expires_in.into());
    account.expires_at = Some(expiry_from_now(tr.expires_in));
    Ok(())
}

fn split_code_state(code: &str) -> (&str, &str) {
    // Anthropic sometimes sends the callback as
    //   ?code=ABC#xyz
    // where the fragment is a SECOND state value. We split on '#' and
    // treat anything after as the more-recent state.
    match code.split_once('#') {
        Some((pure, fragment)) => (pure, fragment),
        None => (code, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_auth_url_contains_pkce_state_and_scope() {
        let url = build_auth_url("state_x", "challenge_y");
        assert!(url.starts_with(AUTH_URL));
        assert!(url.contains("code_challenge=challenge_y"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state_x"));
        assert!(url.contains("client_id=9d1c250a"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn split_code_state_handles_fragment() {
        assert_eq!(split_code_state("ABC#state2"), ("ABC", "state2"));
        assert_eq!(split_code_state("ABC"), ("ABC", ""));
    }
}