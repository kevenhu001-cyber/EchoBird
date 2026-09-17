// Sidebar navigation component
import { useState, useEffect } from 'react';
import {
  Box,
  Server,
  FolderHeart,
  Trophy,
  Monitor,
  Download,
  RefreshCw,
  KeyRound,
} from 'lucide-react';
import { NavItem } from './NavItem';
import { useI18n } from '../hooks/useI18n';
import * as api from '../api/tauri';
import { useDocumentVisible } from '../hooks/useDocumentVisible';

declare const __APP_EDITION__: string;
const isFullEdition = __APP_EDITION__ === 'full';

export type PageType =
  | 'models'
  | 'freeModels'
  | 'apps'
  | 'aiCareer'
  | 'myProjects'
  | 'account'
  | 'localLlm'
  | 'mother'
  | 'feedback';

interface SidebarProps {
  activePage: PageType;
  onPageChange: (page: PageType) => void;
  agentRunning?: boolean;
  smartRouterOnline?: boolean;
  updateAvailable?: string | null;
  onSettingsClick?: () => void;
}

export const Sidebar = ({
  activePage,
  onPageChange,
  agentRunning = false,
  smartRouterOnline = false,
  updateAvailable = null,
  onSettingsClick,
}: SidebarProps) => {
  const { t } = useI18n();
  // Poll local model server status
  const [serverRunning, setServerRunning] = useState(false);
  const docVisible = useDocumentVisible();

  // Poll local model server status — pause when the window is hidden so a
  // backgrounded app doesn't poll IPC every 2s for hours. Resumes on focus.
  useEffect(() => {
    if (!isFullEdition || !docVisible) return;
    const check = async () => {
      try {
        const info = await api.getLlmServerInfo();
        const running = info?.running ?? false;
        setServerRunning((prev) => (prev === running ? prev : running));
      } catch {
        setServerRunning((prev) => (prev === false ? prev : false));
      }
    };
    check();
    const interval = setInterval(check, 2000);
    return () => clearInterval(interval);
  }, [docVisible]);

  return (
    <nav className="w-64 flex flex-col px-6 pb-6">
      <div className="mb-7 flex items-center gap-2 overflow-hidden">
        <img
          src="/brand/bird.png"
          alt=""
          aria-hidden="true"
          draggable={false}
          className="flex-shrink-0 h-7 w-7 select-none"
        />
        <span className="brand-mark flex-shrink-0 text-cyber-text">{t('app.name')}</span>
        {updateAvailable && (
          <button
            onClick={onSettingsClick}
            className="flex-shrink-0 text-[11px] font-mono text-red-400 hover:opacity-70 transition-opacity animate-pulse leading-none"
          >
            {t('settings.updates')}
          </button>
        )}
      </div>
      <div className="flex-1 space-y-5 text-[15px]">
        <NavItem
          icon={<Monitor size={20} />}
          label={t('nav.appManager')}
          active={activePage === 'apps'}
          onClick={() => onPageChange('apps')}
        />
        <NavItem
          icon={<Box size={20} />}
          label={t('nav.modelNexus')}
          active={activePage === 'models'}
          onClick={() => onPageChange('models')}
        />
        <NavItem
          icon={
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M11.013 18.582 6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.12 2.12 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.12 2.12 0 0 0 1.597-1.16l2.309-4.679a.53.53 0 0 1 .95 0l2.31 4.679a2.12 2.12 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904L20 11.5" />
              <path d="M15 18h6" />
              <path d="M18 15v6" />
            </svg>
          }
          label={t('nav.freeModels')}
          active={activePage === 'freeModels'}
          onClick={() => onPageChange('freeModels')}
        />
        <NavItem
          icon={<Download size={20} />}
          label={t('nav.motherAgent')}
          active={activePage === 'mother'}
          onClick={() => onPageChange('mother')}
          trailing={
            agentRunning && (
              <RefreshCw size={14} aria-hidden="true" className="animate-spin text-cyber-accent" />
            )
          }
        />
        {/* Divider — primary actions above; career and project tools below */}
        <div className="border-t border-cyber-border/50" />
        <NavItem
          icon={<Trophy size={20} />}
          label={t('nav.aiCareer')}
          active={activePage === 'aiCareer'}
          onClick={() => onPageChange('aiCareer')}
        />
        <NavItem
          icon={<FolderHeart size={20} />}
          label={t('nav.myProjects')}
          active={activePage === 'myProjects'}
          onClick={() => onPageChange('myProjects')}
        />
        <NavItem
          icon={<KeyRound size={20} />}
          label={t('nav.account')}
          active={activePage === 'account'}
          onClick={() => onPageChange('account')}
        />
        {isFullEdition && (
          <NavItem
            icon={<Server size={20} />}
            label={t('nav.localServer')}
            active={activePage === 'localLlm'}
            onClick={() => onPageChange('localLlm')}
          />
        )}
      </div>

      {(smartRouterOnline || (isFullEdition && serverRunning)) && (
        <div className="pt-4 text-[14px] text-cyber-text-secondary">
          {smartRouterOnline && (
            <div>
              {t('nav.smartRouter')}:{' '}
              <span className="text-cyber-accent font-semibold">{t('status.online')}</span>
            </div>
          )}
          {isFullEdition && serverRunning && (
            <div className={smartRouterOnline ? 'mt-1' : ''}>
              {t('nav.localServer')}:{' '}
              <span className="text-cyber-accent font-semibold">{t('status.running')}</span>
            </div>
          )}
        </div>
      )}
    </nav>
  );
};
