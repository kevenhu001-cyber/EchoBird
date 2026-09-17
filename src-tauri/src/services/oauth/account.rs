// OAuth account model + status.
//
// An OAuth account is what we persist after a successful login: the provider
// (which endpoint, which client_id, etc.), the bits we display in the UI
// (email / nickname), the encrypted token payload (kept opaque — schema differs
// per provider, so we carry it as `serde_json::Value`), and bookkeeping fields
// (`created_at`, `last_refresh`, `expires_at`, `status`).
//
// Token storage is in `token_store.rs`; this module is the shape only.
//
// `OAuthAccountSummary` is the same record WITHOUT the token payload — that's
// what we hand to the frontend. The token never crosses the Tauri IPC boundary.

use serde::{Deserialize, Serialize};

/// Provider enum. Serialized as kebab-case for the wire protocol, with the
/// default being `codex` to keep the JSON tidy for the most common case.
///
/// `Xai` is API-key based, not OAuth — but we keep it in the same struct so
/// the Account Hub UI doesn't need a special case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthProvider {
    Codex,
    Claude,
    Gemini,
    Antigravity,
    Kimi,
    Xai,
}

impl OAuthProvider {
    /// Stable string id (kebab-case). What we accept on the IPC boundary.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Gemini => "gemini",
            Self::Antigravity => "antigravity",
            Self::Kimi => "kimi",
            Self::Xai => "xai",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "codex" | "openai" => Ok(Self::Codex),
            "claude" | "anthropic" => Ok(Self::Claude),
            "gemini" => Ok(Self::Gemini),
            "antigravity" => Ok(Self::Antigravity),
            "kimi" => Ok(Self::Kimi),
            "xai" | "grok" => Ok(Self::Xai),
            other => Err(format!("Unknown OAuth provider: {other}")),
        }
    }

    /// Friendly display name, used by the Account Hub LoginCards. Kept short —
    /// the provider logo does most of the visual work.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Codex => "Codex",
            Self::Claude => "Claude",
            Self::Gemini => "Gemini",
            Self::Antigravity => "Antigravity",
            Self::Kimi => "Kimi",
            Self::Xai => "xAI",
        }
    }

    /// One-line tagline shown on the LoginCard. Helps the user pick the right
    /// provider when they have multiple subscriptions.
    pub fn tagline(&self) -> &'static str {
        match self {
            Self::Codex => "ChatGPT Plus / Pro subscription",
            Self::Claude => "Claude Pro / Max subscription",
            Self::Gemini => "Google Gemini Advanced",
            Self::Antigravity => "Google Antigravity (free Claude/GPT)",
            Self::Kimi => "Moonshot Kimi membership",
            Self::Xai => "xAI SuperGrok (API key)",
        }
    }

    /// Local OAuth callback port. Each provider gets its own port so two
    /// concurrent logins don't collide. Empty for providers that don't use a
    /// browser callback (Kimi device flow, xAI API key).
    pub fn callback_port(&self) -> Option<u16> {
        match self {
            Self::Codex => Some(1455),
            Self::Claude => Some(54545),
            Self::Gemini => Some(51181),
            Self::Antigravity => Some(51121),
            Self::Kimi => None,
            Self::Xai => None,
        }
    }
}

/// Lifecycle status of an account. We surface this in the UI so the user can
/// tell at a glance whether they need to re-login.
///
/// Token freshness check itself (computing Expired vs Valid) happens in
/// `refresh::status_of()`; this is what gets persisted in the on-disk file
/// after a refresh attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthStatus {
    /// Access token is good for at least `REFRESH_LEAD_SECONDS` more.
    Valid,
    /// Access token expired; last refresh failed or no refresh attempt yet.
    Expired,
    /// Refresh token itself was rejected (revoked / scope changed). User must
    /// re-login.
    RefreshFailed,
    /// Kimi device-flow only: user has not yet entered the code.
    Pending,
}

/// Full account record. Persisted (encrypted) to disk by `token_store`.
/// **Never** sent to the frontend — see `OAuthAccountSummary` for that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccount {
    pub provider: OAuthProvider,
    /// e.g. `claude-user@example.com.json`. Uniqueness within a provider is
    /// enforced by the file-name rule in `token_store::file_name_for`.
    pub file_name: String,
    /// Stable identifier from the provider (e.g. ChatGPT `account_id`,
    /// Anthropic `account_uuid`, Google `sub`). Falls back to email if the
    /// provider didn't issue one (Kimi, xAI).
    pub account_id: String,
    /// What we show in the UI — email when the provider returns one, else
    /// account_id. For Kimi device flow this is filled after token exchange.
    pub display_name: String,
    /// ISO 8601 (UTC). Set once at first save.
    pub created_at: String,
    /// ISO 8601 (UTC). Updated every time `refresh::refresh_if_needed()` runs.
    pub last_refresh: String,
    /// ISO 8601 (UTC). `None` for providers without an expiring token (xAI API
    /// keys don't expire unless revoked). Drives the Valid/Expired badge.
    pub expires_at: Option<String>,
    pub status: OAuthStatus,
    /// Opaque per-provider token payload. Kept inside the encrypted file and
    /// never crosses the IPC boundary — `#[serde(skip_serializing)]` is set on
    /// the summary type below so it can't leak by accident.
    ///
    /// Codex: { id_token, access_token, refresh_token, account_id, expires }
    /// Claude: { access_token, refresh_token, expires }
    /// Gemini/Antigravity: { access_token, refresh_token, expires, project_id? }
    /// Kimi: { access_token, refresh_token, expires, device_id }
    /// xAI: { api_key }
    #[serde(default = "serde_json::Value::default")]
    pub token: serde_json::Value,
}

/// IPC-safe view of an account. Strips the token so it can't leak across the
/// Tauri boundary even by accident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccountSummary {
    pub provider: OAuthProvider,
    pub file_name: String,
    pub account_id: String,
    pub display_name: String,
    pub created_at: String,
    pub last_refresh: String,
    pub expires_at: Option<String>,
    pub status: OAuthStatus,
}

impl From<&OAuthAccount> for OAuthAccountSummary {
    fn from(a: &OAuthAccount) -> Self {
        Self {
            provider: a.provider,
            file_name: a.file_name.clone(),
            account_id: a.account_id.clone(),
            display_name: a.display_name.clone(),
            created_at: a.created_at.clone(),
            last_refresh: a.last_refresh.clone(),
            expires_at: a.expires_at.clone(),
            status: a.status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_roundtrips_through_kebab_case() {
        for p in [
            OAuthProvider::Codex,
            OAuthProvider::Claude,
            OAuthProvider::Gemini,
            OAuthProvider::Antigravity,
            OAuthProvider::Kimi,
            OAuthProvider::Xai,
        ] {
            let s = serde_json::to_string(&p).unwrap();
            let back: OAuthProvider = serde_json::from_str(&s).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn provider_parse_accepts_legacy_aliases() {
        assert_eq!(OAuthProvider::parse("codex").unwrap(), OAuthProvider::Codex);
        assert_eq!(OAuthProvider::parse("openai").unwrap(), OAuthProvider::Codex);
        assert_eq!(OAuthProvider::parse("claude").unwrap(), OAuthProvider::Claude);
        assert_eq!(OAuthProvider::parse("anthropic").unwrap(), OAuthProvider::Claude);
        assert_eq!(OAuthProvider::parse("xai").unwrap(), OAuthProvider::Xai);
        assert_eq!(OAuthProvider::parse("grok").unwrap(), OAuthProvider::Xai);
        assert!(OAuthProvider::parse("nope").is_err());
    }

    #[test]
    fn summary_strips_token_field() {
        let acct = OAuthAccount {
            provider: OAuthProvider::Claude,
            file_name: "claude-x.json".into(),
            account_id: "x".into(),
            display_name: "x".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            last_refresh: "2026-01-01T00:00:00Z".into(),
            expires_at: None,
            status: OAuthStatus::Valid,
            token: serde_json::json!({ "secret": "abc" }),
        };
        let summary: OAuthAccountSummary = (&acct).into();
        let s = serde_json::to_string(&summary).unwrap();
        assert!(!s.contains("secret"));
        assert!(!s.contains("token"));
    }
}