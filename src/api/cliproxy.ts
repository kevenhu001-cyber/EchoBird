// Managed CLIProxyAPI engine APIs — Account Hub ↔ Rust cliproxy_commands.
// Subscription tokens live in the engine's filestore; only summaries cross IPC.

import { invoke } from '@tauri-apps/api/core';

export interface CliproxyStatus {
  installed: boolean;
  version: string | null;
  running: boolean;
  port: number;
}

export interface CliproxyAuthUrl {
  status: string;
  url: string;
  state: string;
  flow?: string | null;
  user_code?: string | null;
  expires_in?: number | null;
}

export interface CliproxyAuthStatus {
  status: string;
  error?: string | null;
}

export interface CliproxyAccount {
  id: string;
  name: string;
  type: string;
  provider?: string | null;
  email?: string | null;
  project_id?: string | null;
  status?: string | null;
  disabled?: boolean | null;
}

export async function cliproxyStatus(): Promise<CliproxyStatus> {
  return invoke('cliproxy_status');
}

/** Download the engine release (minutes on slow links). Returns the tag. */
export async function cliproxyDownload(): Promise<string> {
  return invoke('cliproxy_download');
}

export async function cliproxyStart(): Promise<void> {
  return invoke('cliproxy_start');
}

export async function cliproxyStop(): Promise<void> {
  return invoke('cliproxy_stop');
}

/** Begin a login. Returns the browser URL + session state to poll. */
export async function cliproxyAuthUrl(provider: string): Promise<CliproxyAuthUrl> {
  return invoke('cliproxy_auth_url', { provider });
}

/** Poll one login session: ok (saved) / wait / error. */
export async function cliproxyAuthStatus(state: string): Promise<CliproxyAuthStatus> {
  return invoke('cliproxy_auth_status', { state });
}

export async function cliproxyAuthCancel(state: string): Promise<void> {
  return invoke('cliproxy_auth_cancel', { state });
}

export async function cliproxyAccounts(): Promise<CliproxyAccount[]> {
  return invoke('cliproxy_accounts');
}

export async function cliproxyDeleteAccount(name: string): Promise<void> {
  return invoke('cliproxy_delete_account', { name });
}

/** Point a Claude-family tool at the engine. `toolId`: claudecode | claudedesktop. */
export async function cliproxyApplyToTool(toolId: string, model: string): Promise<string> {
  return invoke('cliproxy_apply_to_tool', { toolId, model });
}
