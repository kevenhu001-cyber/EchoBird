//! Lifecycle of the managed CLIProxyAPI child process.
//!
//! * Binary resolution: `~/.echobird/cliproxy/bin/cli-proxy-api[.exe]`.
//!   Missing → the frontend drives `cliproxy_download` (GitHub release
//!   asset + `checksums.txt` verify, no new crates: system `tar` /
//!   PowerShell `Expand-Archive`, `sha2` is already a dependency).
//! * Supervision is deliberately thin: spawn on demand / app start,
//!   liveness via `GET /healthz`, reap via `Child::try_wait` in
//!   `status()`, kill on stop / app exit. No auto-restart daemon — the
//!   Account Hub surfaces stopped state with a one-click restart.

use std::fs;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::io::AsyncWriteExt;

use super::config::{self, installed_version};
use super::{base_url, bin_dir, binary_path, config_path, release_asset, root_dir, version_path, GITHUB_REPO};

/// Tauri-managed shared state (registered via `.manage()`).
#[derive(Clone, Default)]
pub struct CliproxyState {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    child: Option<tokio::process::Child>,
    starting: bool,
}

/// Point-in-time status for the Account Hub.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CliproxyStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub running: bool,
    pub port: u16,
}

impl CliproxyState {
    /// Installed? Which release? Still alive? Reaps an exited child.
    pub fn status(&self) -> CliproxyStatus {
        let mut inner = self.inner.lock().expect("cliproxy state poisoned");
        let mut running = false;
        if let Some(child) = inner.child.as_mut() {
            match child.try_wait() {
                Ok(None) => running = true,
                Ok(Some(_)) | Err(_) => {
                    inner.child = None;
                }
            }
        }
        CliproxyStatus {
            installed: binary_path().exists(),
            version: installed_version(),
            running,
            port: super::CLIPROXY_PORT,
        }
    }

    /// Start the managed server (idempotent). Writes fresh config first,
    /// then waits for `/healthz` (15s budget).
    pub async fn start(&self) -> Result<(), String> {
        {
            let mut inner = self.inner.lock().expect("cliproxy state poisoned");
            if inner.child.is_some() || inner.starting {
                return Ok(());
            }
            inner.starting = true;
        }
        let result = self.start_inner().await;
        self.inner.lock().expect("cliproxy state poisoned").starting = false;
        result
    }

    async fn start_inner(&self) -> Result<(), String> {
        if !binary_path().exists() {
            return Err("CLIProxyAPI engine is not installed yet".to_string());
        }
        config::write_config()?;
        let mut child = tokio::process::Command::new(binary_path())
            .arg("--config")
            .arg(config_path())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("Cannot launch managed CLIProxyAPI: {e}"))?;
        // Health-gate before handing the child over: a port clash or a bad
        // config fails fast here instead of surfacing as mysterious 503s.
        match health_wait().await {
            Ok(()) => {
                self.inner
                    .lock()
                    .expect("cliproxy state poisoned")
                    .child = Some(child);
                log::info!("[Cliproxy] managed engine up at {}", base_url());
                Ok(())
            }
            Err(e) => {
                let _ = child.kill().await;
                Err(e)
            }
        }
    }

    /// Stop the managed server. Sync so the app-exit hook can call it.
    pub fn stop(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().expect("cliproxy state poisoned");
        if let Some(mut child) = inner.child.take() {
            child
                .start_kill()
                .map_err(|e| format!("Cannot stop managed CLIProxyAPI: {e}"))?;
            log::info!("[Cliproxy] managed engine stopped");
        }
        Ok(())
    }

    /// Ensure a binary exists, downloading the latest release when needed.
    /// Returns the release tag (e.g. `v7.3.1`).
    pub async fn ensure_binary(&self) -> Result<String, String> {
        if binary_path().exists() {
            if let Some(v) = installed_version() {
                return Ok(v);
            }
        }
        download_binary().await
    }
}

async fn health_wait() -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| format!("HTTP client failed: {e}"))?;
    let url = format!("{}/healthz", base_url());
    for _ in 0..30 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "Managed CLIProxyAPI did not answer {url} within 15s (port {} busy?)",
        super::CLIPROXY_PORT
    ))
}

/// Download the latest release binary for this platform, verify SHA-256
/// against upstream `checksums.txt`, extract, install, record VERSION.
async fn download_binary() -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent("EchoBird/cliproxy-manager")
        .connect_timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client failed: {e}"))?;

    let tag: String = client
        .get(format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest"))
        .send()
        .await
        .map_err(|e| format!("Cannot reach GitHub releases: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GitHub releases lookup failed: {e}"))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Cannot parse release metadata: {e}"))?
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Release metadata has no tag_name".to_string())?
        .to_string();
    let (archive, binary_name) = release_asset(&tag)?;

    let dir = root_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("Cannot create {}: {e}", dir.display()))?;
    let archive_path = dir.join(&archive);

    download_file(
        &client,
        &format!("https://github.com/{GITHUB_REPO}/releases/download/{tag}/{archive}"),
        &archive_path,
    )
    .await?;
    verify_checksum(&client, &tag, &archive, &archive_path).await?;
    extract_binary(&archive_path, &dir, &binary_name)?;

    let staged = dir.join(&binary_name);
    let target = binary_path();
    fs::create_dir_all(bin_dir()).map_err(|e| format!("Cannot create bin dir: {e}"))?;
    // Same filesystem (both under root_dir) — rename suffices; copy as
    // a cross-device fallback.
    if fs::rename(&staged, &target).is_err() {
        fs::copy(&staged, &target).map_err(|e| format!("Cannot install engine binary: {e}"))?;
        let _ = fs::remove_file(&staged);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("Cannot chmod {}: {e}", target.display()))?;
    }
    let _ = fs::remove_file(&archive_path);
    fs::write(version_path(), &tag).map_err(|e| format!("Cannot record version: {e}"))?;
    log::info!("[Cliproxy] installed engine {tag}");
    Ok(tag)
}

async fn download_file(
    client: &reqwest::Client,
    url: &str,
    dest: &std::path::Path,
) -> Result<(), String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Download failed ({url}): {e}"))?
        .error_for_status()
        .map_err(|e| format!("Download failed ({url}): {e}"))?;
    let mut stream = resp.bytes_stream();
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Download interrupted: {e}"))?;
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("Cannot write {}: {e}", dest.display()))?;
    }
    Ok(())
}

async fn verify_checksum(
    client: &reqwest::Client,
    tag: &str,
    archive: &str,
    archive_path: &std::path::Path,
) -> Result<(), String> {
    let body = client
        .get(format!(
            "https://github.com/{GITHUB_REPO}/releases/download/{tag}/checksums.txt"
        ))
        .send()
        .await
        .map_err(|e| format!("Cannot fetch checksums.txt: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Cannot fetch checksums.txt: {e}"))?
        .text()
        .await
        .map_err(|e| format!("Cannot read checksums.txt: {e}"))?;
    let want = body
        .lines()
        .map(str::trim)
        .filter(|l| l.ends_with(archive))
        .filter_map(|l| l.split_whitespace().next())
        .next()
        .ok_or_else(|| format!("No checksum entry for {archive}"))?;
    let bytes = fs::read(archive_path).map_err(|e| format!("Cannot hash {archive}: {e}"))?;
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&bytes);
    let got = hex::encode(hasher.finalize());
    if got.eq_ignore_ascii_case(want.trim()) {
        Ok(())
    } else {
        Err(format!("Checksum mismatch for {archive} — refusing to install"))
    }
}

fn extract_binary(
    archive_path: &std::path::Path,
    dest_dir: &std::path::Path,
    binary_name: &str,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        let status = std::process::Command::new("tar")
            .arg("-xzf")
            .arg(archive_path)
            .arg("-C")
            .arg(dest_dir)
            .arg(binary_name)
            .status()
            .map_err(|e| format!("tar not available: {e}"))?;
        if status.success() {
            return Ok(());
        }
        return Err(format!("tar failed to extract {binary_name}"));
    }
    #[cfg(windows)]
    {
        let script = format!(
            "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
            archive_path.display(),
            dest_dir.display()
        );
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .map_err(|e| format!("PowerShell not available: {e}"))?;
        if status.success() {
            return Ok(());
        }
        return Err(format!("Expand-Archive failed for {binary_name}"));
    }
}
