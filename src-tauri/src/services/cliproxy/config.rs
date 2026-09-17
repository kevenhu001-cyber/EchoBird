//! Managed `config.yaml` generation for the embedded CLIProxyAPI.
//!
//! The file is rewritten on every start from EchoBird-owned inputs, so
//! hand edits never survive (and never need to). Secrets live in
//! separate 0600 files; the server hashes its `secret-key` copy on boot.

use std::fs;

use rand::RngCore;

use super::{
    api_key_path, auth_dir, config_path, root_dir, secret_path, CLIPROXY_HOST, CLIPROXY_PORT,
};

/// Read the persisted management key, generating + storing one first run.
pub fn ensure_secret() -> Result<String, String> {
    ensure_private_file(&secret_path(), 32)
}

/// Read the persisted tool API key (`eb-<hex>`), generating first run.
pub fn ensure_api_key() -> Result<String, String> {
    let hex = ensure_private_file(&api_key_path(), 24)?;
    Ok(format!("eb-{hex}"))
}

/// Read the installed release tag, if any.
pub fn installed_version() -> Option<String> {
    fs::read_to_string(super::version_path())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Rewrite the managed config from current inputs.
pub fn write_config() -> Result<(), String> {
    let secret = ensure_secret()?;
    let api_key = ensure_api_key()?;
    let dir = root_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    fs::create_dir_all(auth_dir()).map_err(|e| format!("Cannot create auth dir: {e}"))?;
    // The management panel auto-downloads from GitHub on first access;
    // EchoBird ships its own UI, so keep the embedded instance quiet.
    let auth_dir = auth_dir().display().to_string();
    // Built line by line: `\`-continuations would swallow the leading
    // whitespace YAML nesting depends on.
    let lines = [
        "# Managed by EchoBird — do not hand-edit (rewritten on every start).".to_string(),
        format!("host: \"{CLIPROXY_HOST}\""),
        format!("port: {CLIPROXY_PORT}"),
        format!("auth-dir: \"{auth_dir}\""),
        "api-keys:".to_string(),
        format!("  - \"{api_key}\""),
        "debug: false".to_string(),
        "remote-management:".to_string(),
        "  allow-remote: false".to_string(),
        format!("  secret-key: \"{secret}\""),
        "  disable-control-panel: true".to_string(),
    ];
    let body = lines.join("\n") + "\n";
    fs::write(config_path(), body)
        .map_err(|e| format!("Cannot write {}: {e}", config_path().display()))?;
    Ok(())
}

/// Read-or-create a hex secret file with owner-only permissions.
fn ensure_private_file(path: &std::path::Path, bytes: usize) -> Result<String, String> {
    if let Ok(existing) = fs::read_to_string(path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    let hex = hex::encode(&buf);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create {}: {e}", parent.display()))?;
    }
    fs::write(path, &hex).map_err(|e| format!("Cannot write {}: {e}", path.display()))?;
    restrict_to_owner(path);
    Ok(hex)
}

fn restrict_to_owner(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
}
