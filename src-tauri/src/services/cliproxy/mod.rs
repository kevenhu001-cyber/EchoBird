//! Managed CLIProxyAPI engine.
//!
//! EchoBird embeds CLIProxyAPI (https://github.com/router-for-me/CLIProxyAPI)
//! as its subscription-account engine instead of re-implementing OAuth per
//! provider. This module owns the managed instance end to end:
//!
//! * `config` — `~/.echobird/cliproxy/config.yaml` generation (loopback
//!   bind, dedicated port/auth-dir, generated secrets).
//! * `process` — binary resolution, GitHub-release download + checksum
//!   verify, spawn/supervise/health, stop.
//! * `management` — typed client for `/v0/management/*` (headless OAuth
//!   login, account list/delete, quota).
//!
//! The managed instance is deliberately isolated from any standalone
//! CLIProxyAPI the user may run: own port (53684, next to EchoBird's
//! 53682/53683), own auth dir, own binary. Tokens live in CLIProxyAPI's
//! filestore; EchoBird never sees them — only summaries via the
//! management API.

pub mod config;
pub mod management;
pub mod process;

pub use process::{CliproxyState, CliproxyStatus};

use std::path::PathBuf;

/// Managed instance port. 8317 is CLIProxyAPI's default for standalone
/// use; 53684 keeps the managed copy from colliding with one.
pub const CLIPROXY_PORT: u16 = 53684;
/// Loopback only — the engine holds subscription tokens.
pub const CLIPROXY_HOST: &str = "127.0.0.1";
/// Upstream repo hosting release binaries + checksums.
pub const GITHUB_REPO: &str = "router-for-me/CLIProxyAPI";

/// `http://127.0.0.1:53684` — what third-party tools are pointed at.
pub fn base_url() -> String {
    format!("http://{CLIPROXY_HOST}:{CLIPROXY_PORT}")
}

/// `http://127.0.0.1:53684/v0/management`.
pub fn management_base() -> String {
    format!("{}/v0/management", base_url())
}

fn echobird_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_default().join(".echobird")
}

/// `~/.echobird/cliproxy` — root of everything this module manages.
pub fn root_dir() -> PathBuf {
    echobird_dir().join("cliproxy")
}

/// `~/.echobird/cliproxy/bin`.
pub fn bin_dir() -> PathBuf {
    root_dir().join("bin")
}

/// Full path of the managed server binary.
pub fn binary_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        bin_dir().join("cli-proxy-api.exe")
    } else {
        bin_dir().join("cli-proxy-api")
    }
}

/// `~/.echobird/cliproxy/config.yaml` — generated, owned by EchoBird.
pub fn config_path() -> PathBuf {
    root_dir().join("config.yaml")
}

/// `~/.echobird/cliproxy/auths` — CLIProxyAPI auth-dir for this instance.
pub fn auth_dir() -> PathBuf {
    root_dir().join("auths")
}

/// Plaintext management key (0600). The server hashes its own copy on boot.
pub fn secret_path() -> PathBuf {
    root_dir().join(".mgmt-key")
}

/// Static API key handed to third-party tools (0600).
pub fn api_key_path() -> PathBuf {
    root_dir().join(".api-key")
}

/// Installed release tag (e.g. `v7.3.1`).
pub fn version_path() -> PathBuf {
    root_dir().join("VERSION")
}

/// Resolve the release archive + binary name for this platform.
///
/// Returns `(archive_file, binary_in_archive)`, e.g.
/// `("CLIProxyAPI_7.3.1_linux_amd64.tar.gz", "cli-proxy-api")`.
/// Asset layout mirrors `.github/workflows/release.yaml` upstream:
/// `CLIProxyAPI_<tag-without-v>_<goos>_<arch>.{tar.gz|zip}` with
/// `amd64` for x86_64 and `aarch64` for arm64 on every OS.
pub fn release_asset(version_tag: &str) -> Result<(String, String), String> {
    let ver = version_tag.trim_start_matches('v');
    let (goos, ext, binary) = if cfg!(target_os = "macos") {
        ("darwin", "tar.gz", "cli-proxy-api")
    } else if cfg!(target_os = "windows") {
        ("windows", "zip", "cli-proxy-api.exe")
    } else if cfg!(target_os = "linux") {
        ("linux", "tar.gz", "cli-proxy-api")
    } else {
        return Err(format!(
            "Unsupported OS for managed CLIProxyAPI: {}",
            std::env::consts::OS
        ));
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" | "arm64" => "aarch64",
        other => return Err(format!("Unsupported arch for managed CLIProxyAPI: {other}")),
    };
    Ok((
        format!("CLIProxyAPI_{ver}_{goos}_{arch}.{ext}"),
        binary.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_port_does_not_collide_with_standalone_default() {
        assert_ne!(CLIPROXY_PORT, 8317);
        assert_eq!(CLIPROXY_HOST, "127.0.0.1");
    }

    #[test]
    fn release_asset_names_follow_upstream_layout() {
        // Shape check only — arch segment depends on the build host.
        let (archive, binary) = release_asset("v7.3.1").unwrap();
        assert!(archive.starts_with("CLIProxyAPI_7.3.1_"));
        assert!(archive.ends_with(".tar.gz") || archive.ends_with(".zip"));
        assert!(binary.starts_with("cli-proxy-api"));
    }

    #[test]
    fn release_asset_rejects_leading_v_only_once() {
        let (a, _) = release_asset("7.3.1").unwrap();
        let (b, _) = release_asset("v7.3.1").unwrap();
        assert_eq!(a, b);
    }
}
