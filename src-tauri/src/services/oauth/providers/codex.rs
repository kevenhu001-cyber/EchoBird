// Codex (OpenAI) OAuth2 PKCE provider.
//
// Public client id and redirect URI are baked into the official Codex CLI —
// they're not secrets, just identifiers. We use the same values as the
// upstream CLI so a login from EchoBird produces a token that's identical
// in shape to one produced by `codex login` from the official CLI.
//
// Endpoints + flow mirror CLIProxyAPI/internal/auth/codex (we cross-check
// during development to keep the on-disk token shape compatible).
//
// The token response includes an `id_token` (JWT) carrying the account id
// and email; we parse that out so the UI can show "Signed in as foo@bar"
// without an extra round-trip.

use serde::Deserialize;
use tokio::sync::oneshot;

use super::super::account::{OAuthAccount, OAuthProvider, OAuthStatus};
use super::super::callback_server::{self, CallbackResult};
use super::super::pkce::PkceCodes;
use super::super::refresh::{expiry_from_now, now_iso8601};
use super::super::token_store;

pub const AUTH_URL: &str = "https://auth.openai.com/oauth/authorize";
pub const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
pub const SCOPE: &str = "openid email profile offline_access";
pub const CALLBACK_PORT: u16 = 1455;

/// Start the local callback server and return the auth URL + a receiver
/// that fires when the browser redirects back.
pub async fn start_login(
    pkce: &PkceCodes,
    state: &str,
) -> Result<(String, oneshot::Receiver<CallbackResult>), String> {
    let port = CALLBACK_PORT;
    callback_server::preflight_port(port).await?;
    let (tx, rx) = oneshot::channel();
    let label = "Codex";
    let state_clone = state.to_string();
    tokio::spawn(async move {
        if let Err(e) = callback_server::run(port, label, &state_clone, tx).await {
            log::error!("[OAuthCodex] callback server error: {e}");
        }
    });
    let url = build_auth_url(state, &pkce.challenge);
    Ok((url, rx))
}

/// Compose the `/oauth/authorize` URL with PKCE + state.
pub fn build_auth_url(state: &str, challenge: &str) -> String {
    // Order matches the official CLI's wire trace, in case OpenAI's server
    // logs the parameter order for fraud detection.
    let mut params: Vec<(&str, String)> = vec![
        ("client_id", CLIENT_ID.to_string()),
        ("response_type", "code".to_string()),
        ("redirect_uri", REDIRECT_URI.to_string()),
        ("scope", SCOPE.to_string()),
        ("state", state.to_string()),
        ("code_challenge", challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
        ("prompt", "login".to_string()),
        ("id_token_add_organizations", "true".to_string()),
        ("codex_cli_simplified_flow", "true".to_string()),
    ];
    // Sort by key for stable test output — server doesn't care about order
    // but reproducible URLs make debugging easier.
    params.sort_by(|a, b| a.0.cmp(b.0));
    let qs: String = params
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding(&v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{AUTH_URL}?{qs}")
}

/// Exchange the auth code (with PKCE verifier) for tokens, persist, return.
pub async fn complete_login(
    code: &str,
    pkce: &PkceCodes,
    redirect_uri: &str,
) -> Result<OAuthAccount, String> {
    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        refresh_token: String,
        id_token: String,
        expires_in: i64,
    }
    let body = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={}",
        urlencoding(CLIENT_ID),
        urlencoding(code),
        urlencoding(redirect_uri),
        urlencoding(&pkce.verifier),
    );
    let resp = reqwest::Client::new()
        .post(TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Codex token exchange request failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Read Codex token response: {e}"))?;
    if !status.is_success() {
        return Err(format!(
            "Codex token exchange failed (HTTP {}): {}",
            status, text
        ));
    }
    let tr: TokenResp =
        serde_json::from_str(&text).map_err(|e| format!("Parse Codex token response: {e}"))?;

    // Decode id_token JWT (no signature verification — we trust the TLS channel
    // to OpenAI's auth server). We only need `sub` (account id) and `email`.
    let (account_id, email) = parse_jwt_claims(&tr.id_token);

    let account_id = if account_id.is_empty() {
        email.clone()
    } else {
        account_id
    };
    let display_name = if email.is_empty() {
        account_id.clone()
    } else {
        email.clone()
    };

    let account = OAuthAccount {
        provider: OAuthProvider::Codex,
        file_name: token_store::file_name_for(OAuthProvider::Codex, &account_id),
        account_id,
        display_name,
        created_at: now_iso8601(),
        last_refresh: now_iso8601(),
        expires_at: Some(expiry_from_now(tr.expires_in)),
        status: OAuthStatus::Valid,
        token: serde_json::json!({
            "id_token": tr.id_token,
            "access_token": tr.access_token,
            "refresh_token": tr.refresh_token,
            "expires_in": tr.expires_in,
        }),
    };
    token_store::save_account(&account)?;
    Ok(account)
}

/// Use the stored refresh_token to mint a new access_token. Mutates `account`
/// in place; caller is responsible for `token_store::save_account`.
pub async fn refresh(account: &mut OAuthAccount) -> Result<(), String> {
    let refresh_token = account
        .token
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Codex account missing refresh_token".to_string())?
        .to_string();

    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        refresh_token: Option<String>,
        id_token: String,
        expires_in: i64,
    }
    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}&scope=openid+profile+email",
        urlencoding(CLIENT_ID),
        urlencoding(&refresh_token),
    );
    let resp = reqwest::Client::new()
        .post(TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Codex refresh request failed: {e}"))?;
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Read Codex refresh response: {e}"))?;
    if !status.is_success() {
        // "refresh_token_reused" is a hard error: OpenAI rejects further
        // refreshes once a refresh_token is replayed. User must re-auth.
        let lower = text.to_lowercase();
        if lower.contains("refresh_token_reused") {
            account.status = OAuthStatus::RefreshFailed;
        }
        return Err(format!("Codex refresh failed (HTTP {}): {}", status, text));
    }
    let tr: TokenResp =
        serde_json::from_str(&text).map_err(|e| format!("Parse Codex refresh response: {e}"))?;
    account.token["access_token"] = serde_json::Value::String(tr.access_token);
    account.token["id_token"] = serde_json::Value::String(tr.id_token);
    account.token["expires_in"] = serde_json::Value::Number(tr.expires_in.into());
    if let Some(rt) = tr.refresh_token {
        account.token["refresh_token"] = serde_json::Value::String(rt);
    }
    account.expires_at = Some(expiry_from_now(tr.expires_in));
    Ok(())
}

/// Cheap JWT payload extraction. We decode the middle segment (base64url JSON)
/// without verifying the signature — that's acceptable here because we already
/// trust the token came from the OpenAI auth server over TLS. If you ever
/// need to verify signatures, swap in `jsonwebtoken`.
fn parse_jwt_claims(jwt: &str) -> (String, String) {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return (String::new(), String::new());
    }
    let payload = parts[1];
    // base64url -> bytes -> JSON
    let bytes = match base64_url_decode(payload) {
        Ok(b) => b,
        Err(_) => return (String::new(), String::new()),
    };
    let v: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return (String::new(), String::new()),
    };
    // OpenAI's id_token puts `sub` = account id, `email` = email. Some
    // shapes nest the account id instead — try the plain string first,
    // then the known nested locations.
    let sub = v
        .get("sub")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .or_else(|| {
            v.get("chatgpt_account_id")
                .or_else(|| {
                    v.get("https://api.openai.com/auth")
                        .and_then(|x| x.get("chatgpt_account_id"))
                })
                .and_then(|x| x.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    let email = v
        .get("email")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    (sub, email)
}

fn base64_url_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url decode failed: {e}"))
}

fn urlencoding(s: &str) -> String {
    // We can't pull the `url` crate's `form_urlencoded` here without a new
    // dep — `urlencoding` is part of the existing dep tree through Tauri's
    // webview bindings. The most-stable approach is to use `url::form_urlencoded`
    // via the `url` crate, which is already a direct dep.
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>()
}

/// Test-only helper for JWT fixtures (encodes the payload half).
#[cfg(test)]
fn base64_url_encode(s: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_auth_url_contains_pkce_state_and_scope() {
        let url = build_auth_url("state123", "challengeabc");
        assert!(url.starts_with(AUTH_URL));
        assert!(url.contains("client_id="));
        assert!(url.contains("code_challenge=challengeabc"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=state123"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"));
    }

    #[test]
    fn parse_jwt_extracts_sub_and_email() {
        // Header.Payload.Signature — payload encodes
        // {"sub":"acct_42","email":"u@example.com"}
        let payload = base64_url_encode(r#"{"sub":"acct_42","email":"u@example.com"}"#);
        let jwt = format!("header.{payload}.sig");
        let (sub, email) = parse_jwt_claims(&jwt);
        assert_eq!(sub, "acct_42");
        assert_eq!(email, "u@example.com");
    }

    #[test]
    fn parse_jwt_returns_empty_for_garbage() {
        let (s, e) = parse_jwt_claims("not.a.jwt");
        assert!(s.is_empty());
        assert!(e.is_empty());
    }
}
