// Encrypted on-disk storage for OAuth accounts.
//
// Files live under `~/.echobird/oauth/<file_name>.json` and are encrypted with
// the same AES-256-GCM scheme as model API keys
// (`services::model_manager::encrypt_api_key` / `decrypt_api_key`). We reuse
// the key derivation unchanged so the same machine fingerprint unlocks both —
// a fresh install on a new box self-destructs API keys AND OAuth tokens
// together, which is the intended user experience.
//
// File name rule: `<provider>-<sanitized-account-id-or-email>.json`. The
// provider prefix lets `load_accounts_by_provider` skip non-matching files
// without parsing their (encrypted!) JSON. We sanitize to a conservative
// filesystem-safe charset because account_id / email can contain '+', '@',
// dots, etc. that are fine on most platforms but break Windows reserved
// names like `CON`, `PRN`, etc.

use std::fs;
use std::path::{Path, PathBuf};

use crate::services::model_manager;

use super::account::{OAuthAccount, OAuthProvider};

/// Subdirectory under `~/.echobird/`.
const OAUTH_DIR: &str = "oauth";

/// `~/.echobird/oauth`. Created on first save if missing.
fn oauth_dir() -> PathBuf {
    model_manager_echobird_dir().join(OAUTH_DIR)
}

// model_manager doesn't expose `echobird_dir`; reuse the same crate path so
// any future home-dir change (Android, etc.) stays consistent.
fn model_manager_echobird_dir() -> PathBuf {
    crate::utils::platform::echobird_dir()
}

/// Make sure `~/.echobird/oauth` exists. Idempotent; safe to call from every
/// write path.
pub fn ensure_dir() {
    let dir = oauth_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        log::error!("[OAuthStore] Failed to create oauth dir {:?}: {}", dir, e);
    }
}

/// Compute the file_name string from provider + a human identifier (email /
/// account_id / device_id). Same logic is used by every provider's login
/// path so different providers don't collide and the same provider's
/// re-login updates the existing record rather than creating a duplicate.
///
/// We sanitize for the filesystem (not for display): lowercase, replace
/// every non `[a-z0-9-]` with `-`, collapse runs of `-`, trim leading/trailing
/// `-`, then cap at 64 chars. Windows reserved names are sidestepped by the
/// provider prefix + the leading character always being a letter (since
/// every provider string starts with a letter).
pub fn file_name_for(provider: OAuthProvider, identifier: &str) -> String {
    let raw = format!("{}-{}", provider.as_str(), identifier);
    let mut out = String::with_capacity(raw.len());
    let mut prev_dash = false;
    for ch in raw.chars() {
        let lower = ch.lower();
        let is_safe = lower.is_ascii_alphanumeric() || lower == '-';
        if is_safe {
            out.push(lower);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        // Fallback for pathological identifiers — use a stable hash so the
        // file is still writeable and re-logins overwrite it.
        let hash = simple_hash(identifier);
        format!("{}-{}", provider.as_str(), hash)
    } else if trimmed.len() > 64 {
        trimmed[..64].trim_end_matches('-').to_string()
    } else {
        trimmed
    }
}

fn simple_hash(s: &str) -> String {
    let mut h: u64 = 1469598103934665603; // FNV-1a offset
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    format!("{:x}", h)
}

trait CharExt {
    fn lower(self) -> char;
}

impl CharExt for char {
    fn lower(self) -> char {
        // Avoid pulling the `to_ascii_lowercase` method on char via unicode
        // case-folding so the sanitizer is byte-stable regardless of locale.
        if self.is_ascii_uppercase() {
            (self as u8 + 32) as char
        } else {
            self
        }
    }
}

/// Full path for a stored account.
pub fn path_for(provider: OAuthProvider, file_name: &str) -> PathBuf {
    oauth_dir().join(format!("{}-{}.json", provider.as_str(), file_name))
}

/// Encrypt and persist. Overwrites existing records (a re-login of the same
/// account updates the token + last_refresh).
///
/// Wire format (matches `model_manager`):
///   "enc:v1:" + hex(nonce || ciphertext)
/// stored inside a thin JSON envelope:
///
///   {
///     "v": 1,
///     "ct": "enc:v1:<hex>"
///   }
///
/// The JSON envelope lets us bump the format later (`v: 2`) without breaking
/// older files — readers fall back to legacy plaintext if `v` is missing.
pub fn save_account(account: &OAuthAccount) -> Result<(), String> {
    ensure_dir();
    let path = path_for(account.provider, &account.file_name);
    let json = serde_json::to_string(account).map_err(|e| {
        format!(
            "Failed to serialize account {}/{}: {}",
            account.provider.as_str(),
            account.file_name,
            e
        )
    })?;
    let ct = model_manager::encrypt_key_for_storage(&json);
    let envelope = serde_json::json!({ "v": 1, "ct": ct });
    let bytes = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| format!("Failed to serialize envelope: {}", e))?;
    fs::write(&path, &bytes).map_err(|e| format!("Failed to write {}: {}", path.display(), e))?;
    log::info!(
        "[OAuthStore] Saved account {}/{} ({} bytes)",
        account.provider.as_str(),
        account.file_name,
        bytes.len()
    );
    Ok(())
}

/// Read + decrypt a stored account. Returns Err with a useful string if the
/// file is missing, unreadable, or the encryption key has changed (decryption
/// produces garbage, then UTF-8 validation fails — we surface that as
/// "environment changed").
pub fn load_account(provider: OAuthProvider, file_name: &str) -> Result<OAuthAccount, String> {
    let path = path_for(provider, file_name);
    let content =
        fs::read_to_string(&path).map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;

    // Try the envelope format first.
    if let Ok(env) = serde_json::from_str::<serde_json::Value>(&content) {
        if let Some(ct) = env.get("ct").and_then(|v| v.as_str()) {
            let plain = model_manager::decrypt_key_for_use(ct);
            if plain.is_empty() {
                return Err(format!(
                    "Account {}/{} is encrypted with a different machine fingerprint. Re-login required.",
                    provider.as_str(),
                    file_name
                ));
            }
            return serde_json::from_str(&plain).map_err(|e| {
                format!(
                    "Decrypted payload for {}/{} is not valid JSON: {}",
                    provider.as_str(),
                    file_name,
                    e
                )
            });
        }
    }

    // Legacy plaintext fallback (older versions, or someone decrypts by hand).
    serde_json::from_str(&content).map_err(|e| {
        format!(
            "Account file {}/{} is not a recognized format: {}",
            provider.as_str(),
            file_name,
            e
        )
    })
}

/// Returns summaries for every account of a given provider. Skips files that
/// fail to decrypt (treated as "environment changed, needs re-login") so a
/// single bad file doesn't hide healthy ones. The UI can show a "stale"
/// indicator for the file count delta.
pub fn list_accounts_by_provider(
    provider: OAuthProvider,
) -> Vec<super::account::OAuthAccountSummary> {
    ensure_dir();
    let dir = oauth_dir();
    let prefix = format!("{}-", provider.as_str());
    let mut out = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("[OAuthStore] read_dir {:?} failed: {}", dir, e);
            return out;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(&prefix) || !name.ends_with(".json") {
            continue;
        }
        let file_name = name.trim_start_matches(&prefix).trim_end_matches(".json");
        match load_account(provider, file_name) {
            Ok(acct) => out.push((&acct).into()),
            Err(e) => {
                log::warn!(
                    "[OAuthStore] Skipping unreadable account {}/{}: {}",
                    provider.as_str(),
                    file_name,
                    e
                );
            }
        }
    }
    // Newest first.
    out.sort_by(|a, b| b.last_refresh.cmp(&a.last_refresh));
    out
}

/// Delete the on-disk file for an account. Returns true if a file was
/// removed. `provider + file_name` must match exactly — partial matches are
/// not supported (this is destructive).
pub fn delete_account_file(provider: OAuthProvider, file_name: &str) -> bool {
    let path = path_for(provider, file_name);
    match fs::remove_file(&path) {
        Ok(()) => {
            log::info!(
                "[OAuthStore] Deleted account {}/{}",
                provider.as_str(),
                file_name
            );
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            log::error!("[OAuthStore] Failed to delete {}: {}", path.display(), e);
            false
        }
    }
}

/// List all account files across providers. Used by `oauth_list_accounts`
/// when the frontend requests the full set. Returns one summary per record.
pub fn list_all_accounts() -> Vec<super::account::OAuthAccountSummary> {
    let mut out = Vec::new();
    for p in [
        OAuthProvider::Codex,
        OAuthProvider::Claude,
        OAuthProvider::Gemini,
        OAuthProvider::Antigravity,
        OAuthProvider::Kimi,
        OAuthProvider::Xai,
    ] {
        out.extend(list_accounts_by_provider(p));
    }
    out
}

/// Test-only helper: ensure a directory exists for a custom path. Not used
/// in production code; kept so the test suite can point at a temp dir without
/// monkey-patching `echobird_dir`.
#[cfg(test)]
pub fn path_at(dir: &Path, provider: OAuthProvider, file_name: &str) -> PathBuf {
    dir.join(format!("{}-{}.json", provider.as_str(), file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_name_sanitizes_email() {
        assert_eq!(
            file_name_for(OAuthProvider::Claude, "user@example.com"),
            "claude-user-example-com"
        );
    }

    #[test]
    fn file_name_lowercases_and_collapses_dashes() {
        assert_eq!(
            file_name_for(OAuthProvider::Codex, "  Foo+Bar__BAZ  "),
            "codex-foo-bar-baz"
        );
    }

    #[test]
    fn file_name_falls_back_when_all_stripped() {
        // All characters become dashes → trimmed empty → hash fallback
        let n = file_name_for(OAuthProvider::Xai, "////");
        assert!(n.starts_with("xai-"));
        assert!(n.len() > "xai-".len());
    }

    #[test]
    fn file_name_caps_at_64_chars() {
        let long = "a".repeat(200);
        let n = file_name_for(OAuthProvider::Gemini, &long);
        assert!(n.len() <= 64);
    }

    #[test]
    fn file_name_distinguishes_providers() {
        let a = file_name_for(OAuthProvider::Claude, "user@example.com");
        let b = file_name_for(OAuthProvider::Codex, "user@example.com");
        assert_ne!(a, b);
    }
}
