//! Model configuration for claudescience.
//!
//! The official Claude Science Electron binary is OAuth-only — it refuses to
//! serve requests without an Anthropic OAuth session, so writing an API key
//! into its preferences.json (or anywhere else under ~/.claude-science) has
//! no effect. The MIT-licensed `@cometix/cscience` community patch (P1
//! `oauth-gate-bypass` + P12 `disable-require-token`) flips that gate so the
//! same Electron build accepts an API key from `~/.claude-science/byok.env`.
//!
//! The `byok.env` schema (`OPERON_MODELS` is `id:name[,id:name...]` or JSON):
//!   ANTHROPIC_API_KEY    — required, third-party / Anthropic BYOK key
//!   ANTHROPIC_BASE_URL   — required, custom gateway URL (no trailing /v1)
//!   OPERON_MODELS        — required, model list shown in the picker
//!   NO_AUTO_UPDATE       — optional, "1" silences self-update checks
//!
//! EchoBird writes all four so the user can launch the binary (whether the
//! official Electron build or the patched `@cometix/cscience`) and have a
//! third-party model ready without OAuth. When the official binary is used
//! the OAuth gate still trips on first launch — see `docs/api/tools/install/
//! claudescience.json` for the install hint that points users at `cscience`.

use super::{ensure_parent, ApplyResult, ModelInfo};
use std::fs;

/// Upsert a `KEY=value` line into a dotenv body. Replaces the first
/// uncommented line whose key matches; otherwise appends. Commented lines
/// and every other key (the user's telemetry / feature toggles / future
/// `byok.env` entries we don't own) are left untouched.
fn env_upsert(content: &str, key: &str, value: &str) -> String {
    let mut replaced = false;
    let mut lines: Vec<String> = content
        .lines()
        .map(|line| {
            if !replaced {
                let trimmed = line.trim_start();
                let is_match = !trimmed.starts_with('#')
                    && trimmed
                        .split_once('=')
                        .map(|(k, _)| k.trim() == key)
                        .unwrap_or(false);
                if is_match {
                    replaced = true;
                    return format!("{key}={value}");
                }
            }
            line.to_string()
        })
        .collect();
    if !replaced {
        lines.push(format!("{key}={value}"));
    }
    let mut out = lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Read the value of an uncommented `KEY=value` line from a dotenv body.
/// Returns an empty string when the key is absent. Strips surrounding
/// whitespace and a single layer of matching quotes.
fn env_read(content: &str, key: &str) -> String {
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == key {
                let v = v.trim();
                let unquoted = v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                    .unwrap_or(v);
                return unquoted.to_string();
            }
        }
    }
    String::new()
}

/// Trim a trailing `/v1` and `/` so the BYOK launcher can't produce a
/// doubled `/v1/v1/messages`. Mirrors the convention in `apply_claudecode`
/// (claudecode.rs:106) and `apply_claudesktop` (claudedesktop.rs:~140).
fn normalize_base_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    trimmed
        .strip_suffix("/v1")
        .unwrap_or(trimmed)
        .trim_end_matches('/')
        .to_string()
}

/// Format `OPERON_MODELS` as the patched Claude Science schema accepts:
/// `id:name[,id:name...]`. The display name falls back to the id so the
/// picker never surfaces an empty label.
fn format_operon_models(real_id: &str, display_name: &str) -> String {
    let label = if display_name.is_empty() {
        real_id
    } else {
        display_name
    };
    format!("{real_id}:{label}")
}

pub(super) fn apply_claudescience(model_info: &ModelInfo) -> ApplyResult {
    let config_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".claude-science")
        .join("byok.env");
    let mut content = fs::read_to_string(&config_path).unwrap_or_default();

    let real_model_id = model_info
        .model
        .as_deref()
        .or(model_info.name.as_deref())
        .unwrap_or("");
    if real_model_id.is_empty() {
        return ApplyResult {
            success: false,
            message: "Model ID is empty, cannot apply Claude Science config.".to_string(),
        };
    }
    let display_name = model_info.name.as_deref().unwrap_or(real_model_id);

    // Frontend collapses the chosen protocol's URL into base_url (same
    // convention as apply_claudecode / apply_claudedesktop). Accept either
    // field so the anthropic_url branch works too.
    let anthropic_url = model_info
        .anthropic_url
        .as_deref()
        .or(model_info.base_url.as_deref())
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(normalize_base_url);
    let anthropic_url = match anthropic_url {
        Some(u) if !u.is_empty() => u,
        _ => {
            return ApplyResult {
                success: false,
                message: "Base URL is empty. Pick a model first.".to_string(),
            };
        }
    };

    // Local llama-server / vllm proxies need no real key; substitute the
    // same sentinel used by apply_codex / apply_claudecode /
    // apply_openscience so an empty key on a loopback endpoint is
    // legitimate instead of a hard failure.
    let raw_api_key = model_info.api_key.as_deref().unwrap_or("");
    let is_local_provider =
        anthropic_url.contains("127.0.0.1") || anthropic_url.contains("localhost");
    let api_key = if !raw_api_key.is_empty() {
        raw_api_key.to_string()
    } else if is_local_provider {
        "local-no-auth".to_string()
    } else {
        return ApplyResult {
            success: false,
            message: "API Key is empty, cannot apply Claude Science config.".to_string(),
        };
    };

    content = env_upsert(&content, "ANTHROPIC_API_KEY", &api_key);
    content = env_upsert(&content, "ANTHROPIC_BASE_URL", &anthropic_url);
    content = env_upsert(
        &content,
        "OPERON_MODELS",
        &format_operon_models(real_model_id, display_name),
    );
    content = env_upsert(&content, "NO_AUTO_UPDATE", "1");

    ensure_parent(&config_path);
    match fs::write(&config_path, &content) {
        Ok(_) => {
            log::info!(
                "[ToolConfigManager] Claude Science config written to {:?}",
                config_path
            );
            ApplyResult {
                success: true,
                message: format!(
                    "Model \"{}\" applied to Claude Science (byok.env) — restart Claude Science for the change to take effect.",
                    display_name,
                ),
            }
        }
        Err(e) => ApplyResult {
            success: false,
            message: format!("Claude Science error: {}", e),
        },
    }
}

pub(super) fn read_claudescience() -> Option<ModelInfo> {
    let path = dirs::home_dir()?.join(".claude-science").join("byok.env");
    let content = fs::read_to_string(&path).ok()?;

    let operon = env_read(&content, "OPERON_MODELS");
    if operon.is_empty() {
        return None;
    }
    // Parse the first `id:name` pair from OPERON_MODELS (the picker shows
    // every entry as its own row; we round-trip only the head back to the
    // UI to keep ModelInfo single-valued).
    let (real_model_id, display_name) = operon
        .split(',')
        .next()
        .and_then(|first| first.split_once(':'))
        .map(|(id, name)| (id.trim().to_string(), name.trim().to_string()))
        .unwrap_or_else(|| (operon.clone(), operon.clone()));

    let base_url_raw = env_read(&content, "ANTHROPIC_BASE_URL");
    let api_key = env_read(&content, "ANTHROPIC_API_KEY");

    Some(ModelInfo {
        name: if display_name.is_empty() {
            Some(real_model_id.clone())
        } else {
            Some(display_name)
        },
        model: Some(real_model_id),
        base_url: if base_url_raw.is_empty() {
            None
        } else {
            Some(base_url_raw.clone())
        },
        // byok.env is plaintext, so the key we just read is the plaintext
        // key EchoBird wrote — propagate it as base_url's anthropic-shaped
        // twin so the UI's protocol toggle stays in sync on reload.
        api_key: if api_key.is_empty() {
            None
        } else {
            Some(api_key)
        },
        anthropic_url: if base_url_raw.is_empty() {
            None
        } else {
            Some(base_url_raw)
        },
        protocol: Some("anthropic".to_string()),
        display_model: None,
        relay_mode: None,
        one_m_context: None,
    })
}

/// Drop the `byok.env` so Claude Science regenerates its defaults on next
/// launch. Matches the policy of `restore_claudecode_to_official` /
/// `restore_claudedesktop_to_official`: delete the config side-channel and
/// let the tool's own first-run flow take over.
pub(super) fn restore_claudescience_to_official() -> ApplyResult {
    let path = dirs::home_dir()
        .unwrap_or_default()
        .join(".claude-science")
        .join("byok.env");
    if !path.exists() {
        return ApplyResult {
            success: true,
            message: "Claude Science already at defaults — no byok.env to remove.".to_string(),
        };
    }
    match fs::remove_file(&path) {
        Ok(_) => ApplyResult {
            success: true,
            message: "Claude Science restored — byok.env removed, defaults will regenerate on next launch.".to_string(),
        },
        Err(e) => ApplyResult {
            success: false,
            message: format!("Failed to delete Claude Science byok.env: {}", e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_upsert_replaces_existing_key() {
        let body = "FOO=1\nBAR=keep\nBAZ=old\n";
        let out = env_upsert(body, "BAZ", "new");
        assert!(out.contains("BAZ=new"));
        assert!(out.contains("BAR=keep"));
        assert!(!out.contains("BAZ=old"));
    }

    #[test]
    fn env_upsert_appends_when_absent() {
        let body = "FOO=1\n";
        let out = env_upsert(body, "NEW", "value");
        assert!(out.contains("FOO=1"));
        assert!(out.contains("NEW=value"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn env_upsert_ignores_commented_lines() {
        let body = "# BAZ=old\nBAZ=current\n";
        let out = env_upsert(body, "BAZ", "new");
        assert!(out.contains("# BAZ=old"));
        assert!(out.contains("BAZ=new"));
        assert!(!out.contains("BAZ=current"));
    }

    #[test]
    fn env_read_strips_matching_quotes() {
        assert_eq!(env_read("KEY=\"x\"\n", "KEY"), "x");
        assert_eq!(env_read("KEY='x'\n", "KEY"), "x");
        assert_eq!(env_read("KEY=bare\n", "KEY"), "bare");
    }

    #[test]
    fn env_read_skips_commented_match() {
        // A commented-out KEY=stale must NOT shadow the live KEY=value
        // beneath it — read should return the live value.
        let body = "# KEY=stale\nKEY=live\n";
        assert_eq!(env_read(body, "KEY"), "live");
    }

    #[test]
    fn normalize_base_url_strips_trailing_v1_and_slashes() {
        assert_eq!(
            normalize_base_url("https://api.example.com/v1/"),
            "https://api.example.com"
        );
        assert_eq!(
            normalize_base_url("https://api.example.com/v1"),
            "https://api.example.com"
        );
        assert_eq!(
            normalize_base_url("https://api.example.com/"),
            "https://api.example.com"
        );
        assert_eq!(
            normalize_base_url("https://api.example.com"),
            "https://api.example.com"
        );
    }

    #[test]
    fn format_operon_models_falls_back_to_id_when_label_empty() {
        assert_eq!(
            format_operon_models("mimo-v2.5-pro", ""),
            "mimo-v2.5-pro:mimo-v2.5-pro"
        );
        assert_eq!(
            format_operon_models("mimo-v2.5-pro", "MiMo Pro"),
            "mimo-v2.5-pro:MiMo Pro"
        );
    }
}
