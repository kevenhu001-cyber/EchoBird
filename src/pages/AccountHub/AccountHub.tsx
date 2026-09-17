// Account Hub — subscription accounts via the managed CLIProxyAPI engine.
//
// The engine (Rust services::cliproxy) holds the accounts; this page only
// drives it: install/start, headless OAuth login (open URL → poll session),
// list/delete, and point Claude-family tools at the engine endpoint.

import { useCallback, useEffect, useRef, useState } from 'react';
import { Check, ClipboardCopy, ExternalLink, RefreshCw, Trash2 } from 'lucide-react';
import { open as shellOpen } from '@tauri-apps/plugin-shell';
import { useI18n } from '../../hooks/useI18n';
import { useToast } from '../../components/Toast';
import { copyText } from '../../utils/copyText';
import type { TKey } from '../../i18n';
import {
  cliproxyAccounts,
  cliproxyApplyToTool,
  cliproxyAuthCancel,
  cliproxyAuthStatus,
  cliproxyAuthUrl,
  cliproxyDeleteAccount,
  cliproxyDownload,
  cliproxyStart,
  cliproxyStatus,
  cliproxyStop,
  type CliproxyAccount,
  type CliproxyAuthUrl,
  type CliproxyStatus,
} from '../../api/tauri';

const openExternal = (url: string) => shellOpen(url).catch(() => window.open(url, '_blank'));

// EchoBird provider id → display. The Rust side maps these onto the
// engine's `-auth-url` names (gemini goes through its plugin path).
const PROVIDERS: { id: string; name: string; tag: TKey }[] = [
  { id: 'codex', name: 'Codex', tag: 'account.tag.codex' },
  { id: 'claude', name: 'Claude', tag: 'account.tag.claude' },
  { id: 'gemini', name: 'Gemini', tag: 'account.tag.gemini' },
  { id: 'antigravity', name: 'Antigravity', tag: 'account.tag.antigravity' },
  { id: 'kimi', name: 'Kimi', tag: 'account.tag.kimi' },
  { id: 'xai', name: 'xAI', tag: 'account.tag.xai' },
];

// The engine waits on a login session for 5 minutes; stop a little earlier.
const POLL_INTERVAL_MS = 2000;
const POLL_ROUNDS = 140;

export function AccountHubMain() {
  const { t } = useI18n();
  const { showToast } = useToast();
  const [engine, setEngine] = useState<CliproxyStatus | null>(null);
  const [engineBusy, setEngineBusy] = useState(false);
  const [accounts, setAccounts] = useState<CliproxyAccount[]>([]);
  const [busyProvider, setBusyProvider] = useState<string | null>(null);
  const [pending, setPending] = useState<CliproxyAuthUrl | null>(null);
  const [urlCopied, setUrlCopied] = useState(false);
  const [model, setModel] = useState('');
  const pollTimer = useRef<number | null>(null);

  const refreshEngine = useCallback(async () => {
    try {
      setEngine(await cliproxyStatus());
    } catch (e) {
      console.error('[AccountHub] engine status failed', e);
    }
  }, []);

  const reloadAccounts = useCallback(async () => {
    try {
      setAccounts(await cliproxyAccounts());
    } catch {
      // Engine down or fresh install — list stays empty, status card explains.
      setAccounts([]);
    }
  }, []);

  const stopPolling = useCallback(() => {
    if (pollTimer.current !== null) {
      window.clearInterval(pollTimer.current);
      pollTimer.current = null;
    }
  }, []);

  useEffect(() => {
    (async () => {
      await refreshEngine();
      try {
        const st = await cliproxyStatus();
        if (st.installed && !st.running) await cliproxyStart();
      } catch {
        // Best-effort autostart; the status card covers manual control.
      }
      await refreshEngine();
      await reloadAccounts();
    })();
    return () => stopPolling();
  }, [refreshEngine, reloadAccounts, stopPolling]);

  const onEngine = async (action: 'download' | 'start' | 'stop') => {
    setEngineBusy(true);
    try {
      if (action === 'download') {
        const tag = await cliproxyDownload();
        showToast('success', `${t('cliproxy.downloaded')} ${tag}`);
        await cliproxyStart();
      } else if (action === 'start') {
        await cliproxyStart();
      } else {
        await cliproxyStop();
      }
    } catch (e) {
      console.error(`[AccountHub] engine ${action} failed`, e);
      showToast('error', `${e instanceof Error ? e.message : e}`);
    } finally {
      setEngineBusy(false);
      await refreshEngine();
      await reloadAccounts();
    }
  };

  const login = async (provider: string) => {
    stopPolling();
    setBusyProvider(provider);
    setPending(null);
    try {
      const auth = await cliproxyAuthUrl(provider);
      if (!auth.url) throw new Error(t('account.loginFailed'));
      setPending(auth);
      openExternal(auth.url);
      let rounds = 0;
      pollTimer.current = window.setInterval(async () => {
        rounds += 1;
        try {
          const st = await cliproxyAuthStatus(auth.state);
          if (st.status === 'ok') {
            stopPolling();
            setBusyProvider(null);
            setPending(null);
            showToast('success', t('account.loginSuccess'));
            await reloadAccounts();
          } else if (st.status === 'error' || rounds >= POLL_ROUNDS) {
            stopPolling();
            setBusyProvider(null);
            if (rounds >= POLL_ROUNDS) cliproxyAuthCancel(auth.state).catch(() => {});
            showToast('error', st.error || t('account.loginFailed'));
          }
        } catch (e) {
          console.error('[AccountHub] auth poll failed', e);
        }
      }, POLL_INTERVAL_MS);
    } catch (e) {
      console.error('[AccountHub] login failed', e);
      setBusyProvider(null);
      showToast('error', `${t('account.loginFailed')}: ${e instanceof Error ? e.message : e}`);
    }
  };

  const remove = async (a: CliproxyAccount) => {
    if (!window.confirm(t('account.confirmDelete'))) return;
    try {
      await cliproxyDeleteAccount(a.name || a.id);
      setAccounts((prev) => prev.filter((x) => x.name !== a.name || x.id !== a.id));
      showToast('success', t('account.deleted'));
    } catch (e) {
      console.error('[AccountHub] delete failed', e);
      showToast('error', `${e instanceof Error ? e.message : e}`);
    }
  };

  const applyToTool = async (toolId: 'claudecode' | 'claudedesktop') => {
    if (!model.trim()) {
      showToast('error', t('account.applyModelPlaceholder'));
      return;
    }
    try {
      const msg = await cliproxyApplyToTool(toolId, model.trim());
      showToast('success', msg || t('account.applied'));
    } catch (e) {
      console.error('[AccountHub] apply failed', e);
      showToast('error', `${t('account.applyFailed')}: ${e instanceof Error ? e.message : e}`);
    }
  };

  const copyUrl = async () => {
    if (!pending?.url) return;
    if (await copyText(pending.url)) {
      setUrlCopied(true);
      window.setTimeout(() => setUrlCopied(false), 2000);
    }
  };

  const copyUserCode = async () => {
    if (!pending?.user_code) return;
    if (await copyText(pending.user_code)) {
      setUrlCopied(true);
      window.setTimeout(() => setUrlCopied(false), 2000);
    }
  };

  const engineReady = engine?.installed && engine?.running;

  return (
    <div className="max-w-2xl mx-auto py-8 px-2 space-y-8">
      <header className="space-y-3">
        <h1 className="cjk-title text-2xl">{t('account.title')}</h1>
        <p className="text-cyber-text-secondary leading-relaxed">{t('account.intro')}</p>
      </header>

      <section className="rounded-lg border border-cyber-border bg-cyber-bg-secondary/40 p-4 flex items-center gap-4">
        <div className="flex-1 min-w-0">
          <div className="font-semibold">{t('cliproxy.engine')}</div>
          <div className="text-sm text-cyber-text-secondary">
            {!engine || !engine.installed
              ? t('cliproxy.notInstalled')
              : engine.running
                ? `${t('cliproxy.running')} · :${engine.port}${engine.version ? ` · ${engine.version}` : ''}`
                : t('cliproxy.stopped')}
          </div>
        </div>
        {!engine?.installed ? (
          <button
            onClick={() => onEngine('download')}
            disabled={engineBusy}
            className="flex-shrink-0 inline-flex items-center gap-2 px-4 py-2 rounded-md bg-cyber-accent/15 hover:bg-cyber-accent/25 border border-cyber-accent/40 text-cyber-accent transition-colors text-sm font-medium disabled:opacity-50"
          >
            {engineBusy && <RefreshCw size={14} className="animate-spin" />}
            {engineBusy ? t('cliproxy.downloading') : t('cliproxy.download')}
          </button>
        ) : engine.running ? (
          <button
            onClick={() => onEngine('stop')}
            disabled={engineBusy}
            className="flex-shrink-0 px-4 py-2 rounded-md border border-cyber-border text-cyber-text-secondary hover:text-cyber-text transition-colors text-sm font-medium disabled:opacity-50"
          >
            {t('cliproxy.stop')}
          </button>
        ) : (
          <button
            onClick={() => onEngine('start')}
            disabled={engineBusy}
            className="flex-shrink-0 inline-flex items-center gap-2 px-4 py-2 rounded-md bg-cyber-accent/15 hover:bg-cyber-accent/25 border border-cyber-accent/40 text-cyber-accent transition-colors text-sm font-medium disabled:opacity-50"
          >
            {t('cliproxy.start')}
          </button>
        )}
      </section>

      {pending && (
        <section className="rounded-lg border border-cyber-accent/40 bg-cyber-accent/10 p-5 space-y-3">
          <p className="text-sm leading-relaxed">{t('account.waiting')}</p>
          {pending.user_code && (
            <button
              onClick={copyUserCode}
              className="text-lg font-mono tracking-widest px-4 py-2 rounded-md border border-cyber-accent/40 hover:bg-cyber-accent/15 transition-colors"
              title={t('account.copyUrl')}
            >
              {pending.user_code}
            </button>
          )}
          <p className="text-xs font-mono break-all text-cyber-text-secondary">{pending.url}</p>
          <div className="flex gap-2">
            <button
              onClick={() => openExternal(pending.url)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-cyber-accent/15 hover:bg-cyber-accent/25 border border-cyber-accent/40 text-cyber-accent transition-colors text-sm font-medium"
            >
              <ExternalLink size={14} />
              {t('account.openBrowser')}
            </button>
            <button
              onClick={copyUrl}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-cyber-border text-cyber-text-secondary hover:text-cyber-text transition-colors text-sm font-medium"
            >
              {urlCopied ? <Check size={14} /> : <ClipboardCopy size={14} />}
              {urlCopied ? t('account.copied') : t('account.copyUrl')}
            </button>
          </div>
        </section>
      )}

      <section className="grid gap-3">
        {PROVIDERS.map((p) => (
          <div
            key={p.id}
            className="rounded-lg border border-cyber-border bg-cyber-bg-secondary/40 p-4 flex items-center gap-4"
          >
            <div className="flex-1 min-w-0">
              <div className="font-semibold">{p.name}</div>
              <div className="text-sm text-cyber-text-secondary">{t(p.tag)}</div>
            </div>
            <button
              onClick={() => login(p.id)}
              disabled={busyProvider !== null || !engineReady}
              title={!engineReady ? t('cliproxy.stopped') : undefined}
              className="flex-shrink-0 inline-flex items-center gap-2 px-4 py-2 rounded-md bg-cyber-accent/15 hover:bg-cyber-accent/25 border border-cyber-accent/40 text-cyber-accent transition-colors text-sm font-medium disabled:opacity-50"
            >
              {busyProvider === p.id && <RefreshCw size={14} className="animate-spin" />}
              {busyProvider === p.id ? t('account.loggingIn') : t('account.login')}
            </button>
          </div>
        ))}
      </section>

      <section className="space-y-3">
        <h2 className="font-semibold">{t('account.savedTitle')}</h2>
        {accounts.length === 0 ? (
          <p className="text-sm text-cyber-text-secondary">{t('account.empty')}</p>
        ) : (
          <>
            <div className="flex items-center gap-2">
              <input
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder={t('account.applyModelPlaceholder')}
                className="flex-1 px-3 py-2 rounded-md bg-cyber-bg border border-cyber-border text-sm text-cyber-text placeholder:text-cyber-text-secondary/60 focus:outline-none focus:border-cyber-accent/60"
              />
              <button
                onClick={() => applyToTool('claudecode')}
                className="flex-shrink-0 px-3 py-2 rounded-md border border-cyber-accent/40 text-cyber-accent text-sm hover:bg-cyber-accent/15 transition-colors"
              >
                {t('account.applyCode')}
              </button>
              <button
                onClick={() => applyToTool('claudedesktop')}
                className="flex-shrink-0 px-3 py-2 rounded-md border border-cyber-accent/40 text-cyber-accent text-sm hover:bg-cyber-accent/15 transition-colors"
              >
                {t('account.applyDesktop')}
              </button>
            </div>
            {accounts.map((a) => (
              <div
                key={a.id || a.name}
                className="rounded-lg border border-cyber-border bg-cyber-bg-secondary/40 p-4 flex items-center gap-3"
              >
                <div className="flex-1 min-w-0">
                  <div className="font-medium truncate">{a.email || a.name}</div>
                  <div className="text-xs text-cyber-text-secondary">
                    {a.provider || a.type}
                    {a.project_id ? ` · ${a.project_id}` : ''}
                    {a.status ? ` · ${a.status}` : ''}
                    {a.disabled ? ' · disabled' : ''}
                  </div>
                </div>
                <button
                  onClick={() => remove(a)}
                  title={t('account.delete')}
                  className="flex-shrink-0 p-2 rounded-md border border-cyber-border text-cyber-text-secondary hover:text-red-400 transition-colors"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </>
        )}
      </section>
    </div>
  );
}
