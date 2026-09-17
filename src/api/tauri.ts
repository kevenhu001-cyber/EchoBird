// Tauri IPC API layer — replaces window.electron.* calls
// All frontend↔backend communication goes through this module.
//
// Domain modules have been split out for better organisation.
// This file keeps common/misc functions and re-exports all domain modules
// so consumers can continue to use  `import * as api from '../api/tauri'`.

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { DetectedTool, ApplyModelInput, AppSettings } from './types';

// ─── Re-export domain modules ───

export * from './models';
export * from './localServer';
export * from './agent';
export * from './parasite';
export * from './ssh';
export * from './secret';
export * from './bundled';
export * from './aiCareer';
export * from './freeModels';
export * from './smartRouter';
export * from './cliproxy';

// ─── Tool APIs ───

export async function scanTools(): Promise<DetectedTool[]> {
  return invoke('scan_tools');
}

export async function applyModelToTool(
  toolId: string,
  modelInfo: ApplyModelInput
): Promise<{ success: boolean; message: string }> {
  return invoke('apply_model_to_tool', { toolId, modelInfo });
}

export async function restoreToolToOfficial(
  toolId: string
): Promise<{ success: boolean; message: string }> {
  return invoke('restore_tool_to_official', { toolId });
}

// ─── Process APIs ───

export async function startTool(
  toolId: string,
  startCommand?: string,
  cwd?: string
): Promise<void> {
  return invoke('start_tool', {
    toolId,
    startCommand: startCommand || null,
    cwd: cwd ?? null,
  });
}

// ─── In-app self-update (Windows): download installer, launch it, exit ───

export interface SelfUpdateProgress {
  status: 'speed_test' | 'downloading' | 'launching' | 'error';
  percent: number;
}

/// Windows-only. Downloads the installer from GitHub releases, launches its
/// wizard, then exits so the installer can replace our files.
/// Rejects on non-Windows or download failure — the caller falls back to
/// opening the download page in the browser.
export async function downloadAndInstallUpdate(version: string): Promise<void> {
  return invoke('download_and_install_update', { version });
}

/// Subscribe to self-update progress while downloadAndInstallUpdate runs.
export function onSelfUpdateProgress(
  callback: (data: SelfUpdateProgress) => void
): Promise<UnlistenFn> {
  return listen<SelfUpdateProgress>('self-update-progress', (event) => {
    callback(event.payload);
  });
}

// ─── Shell APIs (uses Tauri shell plugin) ───

export async function openExternal(url: string): Promise<void> {
  const { open } = await import('@tauri-apps/plugin-shell');
  await open(url);
}

export async function openFolder(path: string): Promise<void> {
  await invoke('open_folder', { path });
}

/// Open (creating from a template on first use) the user's tool-path overrides
/// file `~/.echobird/tool-paths.json`, where users add install paths for tools
/// detected at non-default locations. Survives app updates; the scanner merges
/// it on top of bundled defaults. Returns the file's absolute path.
export async function openToolPathsConfig(): Promise<string> {
  return invoke('open_tool_paths_config');
}

// ─── App Settings APIs ───

export async function getSettings(): Promise<AppSettings> {
  return invoke('get_settings');
}

export async function saveSettings(settings: AppSettings): Promise<void> {
  return invoke('save_settings', { settings });
}

// ─── My Projects registry (persisted to ~/.echobird/projects.json via Rust) ───

/// Read the user-authored AI-project registry. The front-end (myProjectsStore)
/// owns the MyProject shape; Rust persists the array verbatim. Returns [] when
/// the file is missing.
export async function getMyProjects(): Promise<unknown[]> {
  const arr = await invoke<unknown>('get_my_projects');
  return Array.isArray(arr) ? arr : [];
}

/// Persist the full project registry (sent on every CRUD op).
export async function saveMyProjects(projects: unknown[]): Promise<void> {
  return invoke('save_my_projects', { projects });
}

// ─── App Lifecycle APIs ───

export async function appReady(): Promise<void> {
  return invoke('app_ready');
}

/// Read the last `lines` lines from EchoBird's backend log file — used
/// by the "问题反馈 / Feedback" page's copy-to-clipboard button so users
/// can paste recent logs into a GitHub issue.
export async function readLogTail(lines: number): Promise<string> {
  return invoke<string>('read_log_tail', { lines });
}

// ─── Misc APIs ───

export async function launchGame(
  toolId: string,
  launchFile: string,
  modelConfig?: {
    baseUrl?: string;
    anthropicUrl?: string;
    apiKey?: string;
    model?: string;
    name?: string;
    protocol?: string;
  }
): Promise<{ success: boolean; message?: string }> {
  return invoke('launch_game', { toolId, launchFile, modelConfig: modelConfig || null });
}

/// Copy a built-in tool's reference files (paths.json, models.json,
/// game.html, <id>.svg, README.txt) to ~/.echobird/<id>/ for the "我的AI
/// 项目" page. Idempotent — files the user already has are left alone.
/// Returns the absolute destination directory path.
export async function seedBuiltinToUserDir(toolId: string): Promise<string> {
  return invoke<string>('seed_builtin_to_user_dir', { toolId });
}

/// Apply a model config to a user-authored project's models.json mapping.
/// Reads the project's models.json, gets its write map + configFile, and
/// writes the ModelInfo fields into the target config file. Silent on
/// every failure — these are user projects, not our problem to babysit.
/// Caller is expected to NOT show error UI; await + ignore the Promise.
export interface UserProjectModelInfo {
  name?: string;
  model?: string;
  baseUrl?: string;
  apiKey?: string;
  anthropicUrl?: string;
}
export async function applyUserProjectModel(
  modelsJsonPath: string,
  modelInfo: UserProjectModelInfo
): Promise<void> {
  return invoke('apply_user_project_model', { modelsJsonPath, modelInfo });
}

/// Launch a user-authored project via the OS default handler. HTML →
/// system browser; .exe / .bat / .cli → whatever extension association the
/// user has. Silent on failure.
export async function launchUserProject(launcherPath: string): Promise<void> {
  return invoke('launch_user_project', { launcherPath });
}

// ─── Window APIs (Tauri built-in) ───

export { getCurrentWindow } from '@tauri-apps/api/window';
