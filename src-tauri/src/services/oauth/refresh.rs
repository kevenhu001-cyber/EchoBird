// Single-flight token refresh coordinator.
//
// Each token refresh issues an HTTP call to the provider and updates the
// on-disk encrypted file. Without coordination, a burst of inbound proxy
// requests for the same account can trigger N concurrent refreshes — wasteful
// and racy (last writer wins, others overwrite an updated `last_refresh`
// with stale timestamps). We collapse N concurrent callers onto one actual
// refresh, and have the rest wait for that one to finish.
//
// Implementation: one `tokio::sync::Mutex` per account key. First caller
// locks + runs refresh + releases; later callers arriving mid-refresh
// `lock().await` (they queue behind the first), then re-read the freshly
// saved account from disk. No map-eviction needed because the mutex itself
// is keyed on account identity — when all waiters finish, no one holds
// the lock and the next refresh creates a fresh one.
//
// We keep the in-process map behind a `parking_lot::Mutex` for cheap
// lookups (refresh map access happens on the proxy hot path) and use
// `tokio::sync::Mutex` for the per-account waiters so refreshes can run
// concurrently across DIFFERENT accounts.
//
// Note: this is NOT a cache. After refreshing, we don't hand back the
// in-memory token — every caller re-reads the disk file, so updates from
// elsewhere (e.g. user manually clicking refresh in the UI) are picked up
// on the next call. The disk read is one fs::read + AES-GCM decrypt —
// cheaper than a refresh round-trip to the provider.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};

use tokio::sync::Mutex as TokioMutex;

use super::account::{OAuthAccount, OAuthAccountSummary, OAuthProvider, OAuthStatus};
use super::token_store;

/// Refresh the account's access token if it's due. Idempotent — calling this
/// twice in quick succession still results in one upstream call.
//
// Returns:
///   - Ok(summary) on success; the saved account has updated last_refresh
///     and a fresh expires_at (or None for providers that don't expire).
///   - Err(msg) when refresh fails. The caller decides whether to surface
///     the error to the user or fall back to the still-cached access_token
///     (some providers issue 1-hour access tokens with valid refresh for
///     days — better to keep using a 5-min-ago token than to nuke it).
pub async fn refresh_if_needed(
    provider: OAuthProvider,
    file_name: &str,
) -> Result<OAuthAccountSummary, String> {
    let key = account_key(provider, file_name);
    let guard = refresh_lock_for(&key).clone();
    let _held = guard.lock().await;

    // Reload from disk in case another task refreshed between the caller's
    // load and our lock acquisition.
    let mut account = token_store::load_account(provider, file_name)?;

    if !needs_refresh(&account) {
        account.status = OAuthStatus::Valid;
        return Ok((&account).into());
    }

    super::providers::refresh(provider, &mut account)
        .await
        .map_err(|e| {
            log::warn!(
                "[OAuthRefresh] Refresh failed for {}/{}: {}",
                provider.as_str(),
                file_name,
                e
            );
            e
        })?;

    account.status = OAuthStatus::Valid;
    account.last_refresh = now_iso8601();
    token_store::save_account(&account)?;
    log::info!(
        "[OAuthRefresh] Refreshed {}/{} (status={:?})",
        provider.as_str(),
        file_name,
        account.status
    );
    Ok((&account).into())
}

/// Cheaply tell whether an access token is about to expire. Used to avoid
/// triggering a refresh on the proxy hot path until it's actually needed.
///
/// `REFRESH_LEAD_SECONDS = 300` (5 minutes): chosen to be wider than the
/// round-trip variance for any provider (Codex issues 1h tokens, Claude
/// issues 1h, Google issues 1h). 5 minutes is enough headroom that the
/// token will not expire mid-request even on a slow connection.
pub const REFRESH_LEAD_SECONDS: i64 = 300;

pub fn needs_refresh(account: &OAuthAccount) -> bool {
    let Some(expires) = &account.expires_at else {
        // No expiry tracked → API key (xAI) or unknown. Caller decides.
        // For Kimi / Codex / Claude / Google we always have one. If missing
        // here it means a corrupted file; treat as needing attention.
        return account.status != OAuthStatus::Valid;
    };
    match chrono::DateTime::parse_from_rfc3339(expires) {
        Ok(when) => {
            let now = chrono::Utc::now();
            let lead = chrono::Duration::seconds(REFRESH_LEAD_SECONDS);
            when - lead <= now
        }
        Err(_) => true,
    }
}

/// Same key construction used by `refresh_lock_for` and any external caller
/// that wants to monitor or test the lock map directly. Format: `<provider>:<file_name>`.
pub fn account_key(provider: OAuthProvider, file_name: &str) -> String {
    format!("{}:{}", provider.as_str(), file_name)
}

/// Acquire the per-account refresh lock, creating it on first use.
fn refresh_lock_for(key: &str) -> Arc<TokioMutex<()>> {
    static LOCKS: OnceLock<StdMutex<HashMap<String, Arc<TokioMutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut map = map.lock().expect("refresh lock map poisoned");
    map.entry(key.to_string())
        .or_insert_with(|| Arc::new(TokioMutex::new(())))
        .clone()
}

/// ISO 8601 UTC timestamp with `Z` suffix (e.g. `2026-09-17T08:15:30Z`).
/// Used for `created_at` / `last_refresh` / `expires_at`. We deliberately
/// avoid fractional seconds — every comparison on the UI side parses this
/// back, and precision <1s doesn't help anyone.
pub fn now_iso8601() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Compute the ISO 8601 expiry string from `expires_in` seconds (what the
/// provider returns in the token response). Provider-agnostic.
pub fn expiry_from_now(secs_in: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs_in))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(provider: OAuthProvider, expires: Option<&str>) -> OAuthAccount {
        OAuthAccount {
            provider,
            file_name: "user.json".into(),
            account_id: "u".into(),
            display_name: "u".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            last_refresh: "2026-01-01T00:00:00Z".into(),
            expires_at: expires.map(str::to_string),
            status: OAuthStatus::Valid,
            token: serde_json::Value::Null,
        }
    }

    #[test]
    fn needs_refresh_returns_false_when_far_from_expiry() {
        let in_one_hour = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let acct = mk(OAuthProvider::Claude, Some(&in_one_hour));
        assert!(!needs_refresh(&acct));
    }

    #[test]
    fn needs_refresh_returns_true_within_lead_window() {
        let in_two_minutes = (chrono::Utc::now() + chrono::Duration::minutes(2))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let acct = mk(OAuthProvider::Claude, Some(&in_two_minutes));
        assert!(needs_refresh(&acct));
    }

    #[test]
    fn needs_refresh_returns_true_for_expired_token() {
        let past = (chrono::Utc::now() - chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let acct = mk(OAuthProvider::Claude, Some(&past));
        assert!(needs_refresh(&acct));
    }

    #[test]
    fn needs_refresh_handles_missing_expiry() {
        // API-key style account → no expiry. Refresh needed only when status
        // is not Valid (i.e. an upstream caller marked it stale).
        let fresh = mk(OAuthProvider::Xai, None);
        assert!(!needs_refresh(&fresh));
        let mut stale = fresh.clone();
        stale.status = OAuthStatus::Expired;
        assert!(needs_refresh(&stale));
    }

    #[test]
    fn needs_refresh_handles_unparseable_expiry() {
        // Garbage expires_at → treat as needs refresh so the proxy fails
        // closed (better to re-login than to silently use a token we can't
        // reason about).
        let acct = mk(OAuthProvider::Claude, Some("not-a-date"));
        assert!(needs_refresh(&acct));
    }

    #[test]
    fn now_iso8601_is_rfc3339_utc() {
        let s = now_iso8601();
        assert!(s.ends_with('Z'));
        assert!(chrono::DateTime::parse_from_rfc3339(&s).is_ok());
    }

    #[test]
    fn expiry_from_now_adds_seconds() {
        let now = chrono::Utc::now().fixed_offset();
        let s = expiry_from_now(3600);
        let parsed = chrono::DateTime::parse_from_rfc3339(&s).unwrap();
        let delta = (parsed - now).num_seconds();
        // Allow ±5s slack for clock granularity / execution time.
        assert!((delta - 3600).abs() < 5);
    }

    #[test]
    fn account_key_is_provider_scoped() {
        assert_eq!(
            account_key(OAuthProvider::Claude, "x.json"),
            "claude:x.json"
        );
        assert_eq!(account_key(OAuthProvider::Codex, "x.json"), "codex:x.json");
    }
}
