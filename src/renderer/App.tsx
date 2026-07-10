import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Shield, Ghost, Lock, Settings, Sun, Moon, Monitor, Terminal as TerminalIcon, ChevronUp, ChevronDown, ChevronRight, X, RefreshCw, Download, Zap, Bot, Crosshair, ArrowDown } from 'lucide-react';
import { useVault } from './hooks/useVault';
import { useStats } from './hooks/useStats';
import { useTheme } from './hooks/useTheme';

import { SettingsView } from './components/SettingsView';
import { HomeView } from './components/HomeView';
import { VaultView } from './components/VaultView';
import { AuthView } from './components/AuthView';
import { AddressDisplay } from './components/common/AddressDisplay';
import { AgentTab } from './components/vault/AgentTab';
import { ExchangeView } from './components/ExchangeView';
import { VigilView } from './components/VigilView';
import { XMR402Modal } from './components/common/XMR402Modal';
import { VaultProvider } from './contexts/VaultContext';
import { VigilProvider, useVigil } from './contexts/VigilContext';

const SkinOverlay = ({ config }: { config: any }) => {
  if (!config?.skin_background) return null;
  return (
    <div
      className="absolute inset-0 pointer-events-none z-0"
      style={{
        backgroundImage: `url(${config.skin_background})`,
        opacity: config.skin_opacity !== undefined ? config.skin_opacity : 0.2,
        backgroundSize: config.skin_style === 'cover' || config.skin_style === 'contain' ? config.skin_style : config.skin_style === 'tile' ? 'auto' : 'cover',
        backgroundPosition: config.skin_style === 'top-left' ? 'top left' : 'center',
        backgroundRepeat: config.skin_style === 'tile' ? 'repeat' : 'no-repeat'
      }}
    />
  );
};

function MainApp() {
  const [view, setView] = useState<'home' | 'vault' | 'settings' | 'agent' | 'exchange' | 'vigil'>('home');
  const [showConsole, setShowConsole] = useState(false);
  const [showFeedbackModal, setShowFeedbackModal] = useState(false);
  const [feedbackText, setFeedbackText] = useState('');
  const [appVersion, setAppVersion] = useState('1.0');
  const [isPackaged, setIsPackaged] = useState(true);
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({ exchange: true, tools: true });

  useEffect(() => {
    window.api.getAppInfo().then(info => { setAppVersion(info.version); setIsPackaged(info.isPackaged); });
  }, []);

  const [appConfig, setAppConfig] = useState<any>(null);

  const vault = useVault();
  const {
    address, logs, status, isAppLoading, isInitializing, syncPercent, currentHeight, totalHeight, isLocked, unlock, lock, purgeIdentity,
    hasVaultFile, identities, activeId, switchIdentity
  } = vault;

  const { stats, loading: statsLoading } = useStats();
  const { mode, cycleTheme, resolvedTheme, skin, skinLabel, cycleSkin, contrast, toggleContrast } = useTheme();

  const activeIdentity = identities.find(i => i.id === activeId);

  const [showScanlines, setShowScanlines] = useState(resolvedTheme === 'dark');
  const [autoLockMinutes, setAutoLockMinutes] = useState(0);
  const vigil = useVigil();
  // Auto-lock is never inhibited anymore: an armed EJECT keeps the wallet
  // hot behind the locked UI (see vigilHotWallet), which is strictly safer
  // than keeping the whole app unlocked.
  const vigilArmed = vigil.state !== 'IDLE' && vigil.state !== 'COMPLETED' && vigil.state !== 'ERROR';

  const [uplink, setUplink] = useState<string>('SCANNING...');
  const [uplinkUrl, setUplinkUrl] = useState<string>('');
  const [sessionStartTime] = useState(Date.now());
  const [uptime, setUptime] = useState('00:00:00');

  const [updateBanner, setUpdateBanner] = useState<{ show: boolean; version: string; url: string } | null>(null);

  const lastActivityRef = useRef(Date.now());
  const resetActivity = useCallback(() => { lastActivityRef.current = Date.now(); }, []);

  useEffect(() => {
    const loadConfig = async () => {
      const config = await window.api.getConfig();
      setAppConfig(config);

      // Maintain compatibility with legacy single-setting logic
      if (config.show_scanlines !== undefined) setShowScanlines(config.show_scanlines && resolvedTheme === 'dark');
      if (config.auto_lock_minutes !== undefined) setAutoLockMinutes(config.auto_lock_minutes);
    };
    loadConfig();
  }, [view, resolvedTheme]); // Refresh configuration on view change

  // --- Auto Update Check on Boot ---
  useEffect(() => {
    if (isAppLoading || isInitializing || !appConfig) return;

    const checkOnBoot = async () => {
      try {
        const res = await window.api.checkForUpdates(appConfig.include_prereleases);
        if (res.success && res.hasUpdate && res.latestVersion && res.releaseUrl) {
          setUpdateBanner({ show: true, version: res.latestVersion, url: res.releaseUrl });
        }
      } catch (e) { console.warn('[App] Update check failed:', e); }
    };

    // Delay check slightly so it doesn't interrupt the user's initial orientation
    const timer = setTimeout(checkOnBoot, 5000);
    return () => clearTimeout(timer);
  }, [isAppLoading, isInitializing, appConfig]);
  // ---------------------------------

  const toggleTor = async () => {
    if (!appConfig) return;
    const newConfig = {
      ...appConfig,
      routingMode: appConfig.routingMode === 'tor' ? 'clearnet' : 'tor'
    };
    await window.api.saveConfigAndReload(newConfig);
    setAppConfig(newConfig); // Sync local state
  };

  useEffect(() => {
    if (isLocked) return;
    const checkLock = setInterval(() => {
      if (autoLockMinutes <= 0) return;
      const now = Date.now();
      const elapsedMs = now - lastActivityRef.current;
      if (elapsedMs > autoLockMinutes * 60 * 1000) {
        lock();
      }
    }, 10000);
    window.addEventListener('mousemove', resetActivity);
    window.addEventListener('keydown', resetActivity);
    window.addEventListener('mousedown', resetActivity);
    return () => {
      clearInterval(checkLock);
      window.removeEventListener('mousemove', resetActivity);
      window.removeEventListener('keydown', resetActivity);
      window.removeEventListener('mousedown', resetActivity);
    };
  }, [isLocked, autoLockMinutes, lock, resetActivity]);

  useEffect(() => {
    const timer = setInterval(() => {
      const seconds = Math.floor((Date.now() - sessionStartTime) / 1000);
      const h = Math.floor(seconds / 3600).toString().padStart(2, '0');
      const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
      const s = (seconds % 60).toString().padStart(2, '0');
      setUptime(`${h}:${m}:${s}`);
    }, 1000);
    return () => clearInterval(timer);
  }, [sessionStartTime]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showConsole) {
        setShowConsole(false);
        return;
      }

      if (!appConfig?.shortcuts || isLocked) return;

      const isMod = e.metaKey || e.ctrlKey;
      const isAlt = e.altKey;
      const key = e.key.toUpperCase();

      // Helper to match key sequence strings like "Mod+S" or "Mod+Alt+C"
      const matchShortcut = (id: string) => {
        const seq = appConfig.shortcuts[id];
        if (!seq) return false;
        const parts = seq.split('+');
        const wantsMod = parts.includes('Mod');
        const wantsAlt = parts.includes('Alt');
        const targetKey = parts[parts.length - 1].toUpperCase();

        return isMod === wantsMod && isAlt === wantsAlt && key === targetKey;
      };

      if (matchShortcut('LOCK')) {
        e.preventDefault();
        lock();
      } else if (matchShortcut('SEND')) {
        e.preventDefault();
        setView('vault');
        vault.setRequestedAction('OPEN_SEND');
      } else if (matchShortcut('RECEIVE')) {
        e.preventDefault();
        setView('vault');
        vault.setRequestedAction('OPEN_RECEIVE');
      } else if (matchShortcut('CHURN')) {
        e.preventDefault();
        setView('vault');
        vault.setRequestedAction('OPEN_CHURN');
      } else if (matchShortcut('SPLIT')) {
        e.preventDefault();
        setView('vault');
        vault.setRequestedAction('OPEN_SPLINTER');
      } else if (matchShortcut('SYNC')) {
        e.preventDefault();
        vault.refresh();
      } else if (matchShortcut('SETTINGS')) {
        e.preventDefault();
        setView('settings');
      } else if (matchShortcut('TERMINAL')) {
        e.preventDefault();
        setShowConsole(prev => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showConsole, appConfig, isLocked, lock, setView, vault]);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const s = await window.api.getUplinkStatus();
        if (s) {
          if (s.nodeLabel) {
            setUplink(s.nodeLabel);
            setUplinkUrl(s.node);
          } else if (s.node) {
            let cleanUrl = s.node.replace('http://', '').replace('https://', '');
            if (cleanUrl.includes('.onion')) {
              const parts = cleanUrl.split('.');
              if (parts[0].length > 12) {
                cleanUrl = `${parts[0].substring(0, 12)}...onion${parts[1] ? ':' + parts[1].split(':')[1] : ''}`;
              }
            }
            setUplink(cleanUrl);
            setUplinkUrl(s.node);
          }
        }
      } catch (e) {
        setUplink('LINK_OFFLINE');
        setUplinkUrl('');
      }
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // --- 🔗 DEEP LINK LISTENER ---
  useEffect(() => {
    const cleanup = window.api.onDeepLink((url: string) => {
      console.log('[App] Received deep link:', url);
      try {
        const protocolRegex = /^(monero|ghost|ripley):([^?]+)(\?.*)?$/i;
        const match = url.match(protocolRegex);
        if (!match) return;

        const address = match[2];
        const searchParams = new URLSearchParams(match[3] || '');

        const data = {
          address,
          amount: searchParams.get('tx_amount') || searchParams.get('amount') || '',
          description: searchParams.get('tx_description') || searchParams.get('tx_note') || searchParams.get('note') || '',
          name: searchParams.get('recipient_name') || ''
        };

        vault.setDeepLinkData(data);
        setView('vault');
        vault.setRequestedAction('OPEN_SEND');

        // If app is locked, we'll wait for unlock. If not, DirectSendTab will pick it up.
      } catch (err) {
        console.error('[App] Failed to parse deep link:', err);
      }
    });
    return cleanup;
  }, [vault]);

  // --- 🔒 LOCK / AUTH RENDERING LOGIC ---

  // 1. Splash Screen: Only during initial app data load
  if (isAppLoading || !appConfig) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-xmr-base text-xmr-green font-mono p-10 relative overflow-hidden">
        <Shield size={48} className="animate-pulse mb-6 text-xmr-green" />
        <div className="text-xs text-xmr-dim uppercase tracking-[0.4em] animate-pulse">Establishing_Uplink...</div>
      </div>
    );
  }

  // 2. Auth View: Visible whenever locked
  if (isLocked) {
    return (
      <div className="relative min-h-screen bg-xmr-base text-xmr-green font-mono overflow-hidden">
        <SkinOverlay config={appConfig} />
        {vigilArmed && (
          <div className="fixed top-4 left-1/2 -translate-x-1/2 z-50 px-3 py-1.5 rounded-sm border border-xmr-ghost/50 bg-xmr-ghost/10 text-xmr-ghost text-[10px] font-black uppercase tracking-widest flex items-center gap-2 animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-xmr-ghost" />
            VIGIL ARMED — {vigil.activeSession?.mode || vigil.state}
            {vigil.state === 'PAUSED_LOCKED' && ' · UNLOCK TO DISPATCH'}
          </div>
        )}
        <div className="relative z-10 w-full h-full">
          <AuthView
            onUnlock={unlock}
            isInitialSetup={!hasVaultFile}
            identities={identities}
            activeId={activeId}
            onSwitchIdentity={switchIdentity}
            onCreateIdentity={(name) => unlock('', name, '', 0)}
            onPurgeIdentity={purgeIdentity}
            logs={logs}
          />
        </div>
      </div>
    );
  }

  const isSyncing = currentHeight < totalHeight - 1 && totalHeight > 0;

  const toggleGroup = (g: string) => setExpandedGroups(prev => ({ ...prev, [g]: !prev[g] }));

  const NavButton = ({ id, label, icon: Icon, badge, compact }: any) => (
    <button
      onClick={() => setView(id)}
      className={`w-full flex items-center justify-between px-5 py-3 border-l-2 transition-all cursor-pointer group ${view === id ? 'bg-xmr-green/5 border-xmr-green text-xmr-green' : 'border-transparent text-xmr-dim hover:text-xmr-green hover:bg-xmr-green/5'}`}
    >
      <div className="flex items-center gap-3">
        <Icon size={16} className={view === id ? 'drop-shadow-[0_0_8px_rgba(0,255,65,0.5)]' : 'opacity-50 group-hover:opacity-100'} />
        <span className="text-[11px] font-black uppercase tracking-[0.15em]">{label}</span>
      </div>
      {badge && (
        <span className="text-[9px] font-black bg-xmr-green/10 px-1.5 py-0.5 rounded-sm border border-xmr-green/20 animate-pulse">
          {badge}
        </span>
      )}
    </button>
  );

  const NavGroup = ({ label, groupKey, children }: { label: string; groupKey: string; children: React.ReactNode }) => {
    const childArray = React.Children.toArray(children).filter(Boolean);
    if (childArray.length === 1) return <>{childArray[0]}</>;
    return (
      <div>
        <button
          onClick={() => toggleGroup(groupKey)}
          className="w-full flex items-center gap-2 px-5 py-1.5 text-[9px] font-black uppercase tracking-[0.25em] text-xmr-dim/60 hover:text-xmr-dim transition-colors cursor-pointer"
        >
          <ChevronRight size={10} className={`transition-transform duration-200 ${expandedGroups[groupKey] ? 'rotate-90' : ''}`} />
          {label}
        </button>
        {expandedGroups[groupKey] && children}
      </div>
    );
  };

  return (
    <div className="flex h-screen bg-xmr-base text-xmr-green font-mono relative overflow-hidden select-none transition-colors duration-300">
      <SkinOverlay config={appConfig} />
      <style>{` .scanline-overlay { background: linear-gradient(to bottom, transparent 50%, rgba(0, 77, 19, var(--scanline-opacity, 0)) 50%); background-size: 100% 4px; pointer-events: none; z-index: 100; display: block; } `}</style>
      <div className="fixed inset-0 scanline-overlay pointer-events-none z-[100]"></div>

      <aside className="w-56 shrink-0 flex flex-col border-r border-xmr-border/40 bg-xmr-surface backdrop-blur-xl z-50" style={{ WebkitAppRegion: 'drag' } as any}>
        {/* ─── Header ─── */}
        <div className="px-5 pt-6 pb-5 mt-3 flex flex-col items-center gap-2.5" style={{ WebkitAppRegion: 'no-drag' } as any}>
          <div className="relative group cursor-pointer" onClick={() => setView('home')}>
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" className="w-12 h-12 drop-shadow-[0_0_12px_rgba(0,255,65,0.4)] overflow-visible transition-transform duration-500 ease-in-out group-hover:scale-[1.15]">
              <defs>
                <mask id="cutMask">
                  <rect width="100" height="100" fill="white" />
                  <line x1="85" y1="15" x2="15" y2="85" stroke="black" strokeWidth="16" strokeLinecap="round" className="origin-center transition-all duration-300 ease-out group-hover:scale-x-125 group-hover:stroke-[24]" />
                </mask>
              </defs>
              <g mask="url(#cutMask)" className="origin-center transition-all duration-500 ease-out group-hover:opacity-75">
                <circle cx="50" cy="50" r="45" fill="none" stroke={resolvedTheme === 'light' ? '#0bc43a' : '#ffffff'} strokeWidth="6" />
                <path d="M30,50 a20,20 0 0,1 40,0" fill="none" stroke={resolvedTheme === 'light' ? '#000000' : '#ffffff'} strokeWidth="6" strokeLinecap="round" className="transition-transform duration-[600ms] ease-[cubic-bezier(0.34,1.56,0.64,1)] origin-bottom group-hover:-translate-y-3 group-hover:opacity-0" />
                <path d="M30,50 a20,20 0 0,0 40,0" fill="none" stroke={resolvedTheme === 'light' ? '#000000' : '#ffffff'} strokeWidth="4" strokeLinecap="round" strokeDasharray="2 6" className="transition-all duration-[600ms] ease-out opacity-0 group-hover:opacity-100 group-hover:translate-y-3" />
              </g>
              <line x1="85" y1="15" x2="15" y2="85" stroke="#ff3333" strokeWidth="8" strokeLinecap="round" className="origin-center transition-transform duration-[400ms] ease-[cubic-bezier(0.34,1.56,0.64,1)] group-hover:scale-[1.4]" />
            </svg>
          </div>
          <div className="text-center">
            <div className="text-[11px] font-black tracking-[0.3em] text-xmr-green">RIPLEY_TERMINAL</div>
            <div className="text-[9px] text-xmr-dim font-bold tracking-[0.2em] uppercase truncate max-w-[180px]" title={activeIdentity?.name || 'TACTICAL_UPLINK'}>
              {activeIdentity?.name || 'TACTICAL_UPLINK'}
            </div>
          </div>
        </div>

        {/* ─── Portfolio Card ─── */}
        {vault.accounts.length > 0 && (
          <div
            className="mx-3 mt-1 p-3 bg-gradient-to-br from-xmr-green/10 to-transparent border border-xmr-border/30 rounded-sm cursor-pointer hover:border-xmr-green/30 transition-all"
            style={{ WebkitAppRegion: 'no-drag' } as any}
            onClick={() => setView('vault')}
          >
            <div className="text-[8px] font-bold uppercase tracking-[0.25em] text-xmr-dim mb-1">Total Portfolio</div>
            <div className="font-[var(--font-display)] text-base font-black text-xmr-green leading-tight">
              {vault.accounts.reduce((sum, a) => sum + parseFloat(a.balance || '0'), 0).toFixed(4)}
              <span className="text-[9px] text-xmr-dim font-normal ml-1">XMR</span>
            </div>
            <div className="text-[8px] text-xmr-dim/50 mt-0.5 uppercase tracking-wider">
              {vault.accounts.length} accounts
            </div>
          </div>
        )}

        {/* ─── Grouped Navigation ─── */}
        <nav className="flex-grow overflow-y-auto custom-scrollbar space-y-1 pb-2" style={{ WebkitAppRegion: 'no-drag' } as any}>
          <NavButton id="home" label="Dashboard" icon={Ghost} />
          <NavButton id="vault" label="Vault" icon={Shield} badge={isSyncing ? `${syncPercent.toFixed(1)}%` : null} />

          <NavGroup label="Exchange" groupKey="exchange">
            <NavButton id="exchange" label="Exchange" icon={ArrowDown} />
            <NavButton id="vigil" label="Vigil / Limit" icon={Crosshair} />
          </NavGroup>

          <NavGroup label="Tools" groupKey="tools">
            <NavButton id="agent" label="Agent" icon={Bot} />
            <NavButton id="settings" label="Settings" icon={Settings} />
          </NavGroup>
          <button
            onClick={() => { setShowFeedbackModal(true); setFeedbackText(''); }}
            className="w-full flex items-center gap-2.5 px-5 py-2.5 border-l-2 border-transparent text-xmr-dim hover:text-xmr-accent hover:bg-xmr-accent/5 transition-all cursor-pointer group"
          >
            <RefreshCw size={15} className="opacity-50 group-hover:opacity-100 group-hover:animate-spin-slow" />
            <span className="text-[10px] font-black uppercase tracking-[0.15em]">Feedback</span>
          </button>
        </nav>

        {/* ─── Compact Bottom Panel ─── */}
        <div className="px-4 py-3 border-t border-xmr-border/20 bg-xmr-green/[0.02] space-y-2" style={{ WebkitAppRegion: 'no-drag' } as any}>
          {/* Lock + Console row */}
          <div className="flex gap-1.5">
            <button onClick={lock} className="flex-grow flex items-center justify-center gap-1.5 py-2 bg-red-950/20 border border-red-900/50 text-red-500 hover:bg-red-500 hover:text-white transition-all cursor-pointer group uppercase text-[10px] font-black rounded-sm">
              <Lock size={12} className="group-hover:scale-110 transition-transform" /> LOCK
            </button>
            <button onClick={() => setShowConsole(!showConsole)} className={`px-2.5 py-2 border transition-all cursor-pointer rounded-sm ${showConsole ? 'border-xmr-green text-xmr-green bg-xmr-green/10' : 'border-xmr-border text-xmr-dim hover:border-xmr-green'}`}>
              <TerminalIcon size={12} />
            </button>
          </div>

          {/* Theme + Skin + Network in one compact grid */}
          <div className="grid grid-cols-3 gap-1.5">
            <button onClick={cycleTheme} className="flex flex-col items-center gap-0.5 py-1.5 rounded-sm border border-xmr-border/50 hover:bg-xmr-green/10 transition-all cursor-pointer text-xmr-green" title={`Theme: ${mode}`}>
              {mode === 'dark' ? <Moon size={12} /> : mode === 'light' ? <Sun size={12} /> : <Monitor size={12} />}
              <span className="text-[8px] font-black uppercase tracking-wide">{mode === 'system' ? 'SYS' : mode.substring(0, 4).toUpperCase()}</span>
            </button>
            <button onClick={cycleSkin} className="flex flex-col items-center gap-0.5 py-1.5 rounded-sm border border-xmr-border/50 hover:bg-xmr-green/10 transition-all cursor-pointer text-xmr-green" title={`Skin: ${skinLabel}`}>
              <span className="text-[10px]">◈</span>
              <span className="text-[8px] font-black uppercase tracking-wide">{skinLabel.substring(0, 4).toUpperCase()}</span>
            </button>
            <button onClick={toggleTor} className={`flex flex-col items-center gap-0.5 py-1.5 rounded-sm border cursor-pointer ${appConfig.routingMode === 'tor' ? 'border-xmr-green/50 text-xmr-green' : 'border-xmr-accent/50 text-xmr-accent'}`} title={appConfig.routingMode === 'tor' ? 'Tor Only' : 'Clearnet'}>
              <Shield size={12} />
              <span className="text-[8px] font-black uppercase tracking-wide">{appConfig.routingMode === 'tor' ? 'TOR' : 'CLR'}</span>
            </button>
          </div>

          {/* Status row */}
          <div className="flex items-center justify-between text-[9px] font-bold uppercase tracking-wider text-xmr-dim">
            <span className="flex items-center gap-1">
              <div className={`w-1 h-1 rounded-full ${status === 'SYNCING' || status === 'READY' ? 'bg-xmr-accent animate-pulse' : 'bg-xmr-green'}`} />
              {status === 'SYNCING' || status === 'READY' ? `SYNC ${syncPercent ? syncPercent.toFixed(0) + '%' : ''}` : status}
            </span>
            <span className="text-xmr-dim/60">{uptime}</span>
          </div>
        </div>
      </aside>

      <div className="flex-grow flex flex-col min-w-0 bg-transparent relative z-10">
        <header className="h-14 flex items-center justify-end px-8 border-b border-xmr-border/20 bg-xmr-surface/80 backdrop-blur-md shrink-0" style={{ WebkitAppRegion: 'drag' } as any}>
          <div className="flex gap-6 text-[10px] font-black uppercase tracking-[0.2em]" style={{ WebkitAppRegion: 'no-drag' } as any}>
            <span className="flex items-center gap-2 text-xmr-dim">SESSION: <span className="text-xmr-green opacity-80 font-black">{uptime}</span></span>
            <span className="flex items-center gap-2 text-xmr-dim">XMR: <span className="text-xmr-accent font-black">${stats?.price.street || '---.--'}</span></span>
            <span className="flex items-center gap-2 text-xmr-dim">POOL: <span className={(stats?.network.mempool || 0) > 50 ? "text-orange-500" : "text-xmr-green"}>{stats?.network.mempool ?? '--'} TXs</span></span>
          </div>
        </header>

        <main className="flex-grow overflow-y-auto p-10 custom-scrollbar relative transition-colors duration-300">
          <div className={`absolute top-0 left-0 w-full h-32 bg-gradient-to-b from-xmr-green/5 to-transparent pointer-events-none`}></div>

          {isInitializing ? (
            <div className="h-full flex flex-col items-center justify-center space-y-6 animate-in fade-in duration-500">
              <div className="relative">
                <Shield size={48} className="text-xmr-green animate-pulse" />
                <RefreshCw size={24} className="absolute -bottom-2 -right-2 text-xmr-accent animate-spin" />
              </div>
              <div className="text-center space-y-2">
                <h3 className="text-sm font-black uppercase tracking-[0.3em] text-xmr-green">Waking_Stealth_Engine</h3>
                <p className="text-[11px] text-xmr-dim uppercase tracking-widest leading-relaxed">
                  Decrypting vault keys and preparing Wasm runtime...<br />
                  <span className="opacity-50 italic">This may take a moment for large wallets.</span>
                </p>
              </div>
              <div className="w-48 h-1 bg-xmr-border/20 rounded-full overflow-hidden">
                <div className="h-full bg-xmr-green animate-progress-indeterminate"></div>
              </div>
            </div>
          ) : (
            <>
                {/* Update Banner */}
                {updateBanner?.show && (
                  <div className="mb-6 p-4 border border-xmr-accent/30 bg-xmr-accent/5 rounded-sm flex items-center justify-between animate-in slide-in-from-top-4 duration-500">
                    <div className="flex items-center gap-3">
                      <Zap size={16} className="text-xmr-accent animate-pulse" />
                      <div>
                        <div className="text-[10px] font-black uppercase text-xmr-accent tracking-widest">Update_Detected</div>
                        <div className="text-[10px] text-xmr-dim uppercase font-mono mt-0.5">Version {updateBanner.version} is available for deployment.</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => window.api.openExternal(updateBanner.url)}
                        className="px-4 py-2 bg-xmr-accent text-xmr-base font-black text-[11px] uppercase hover:bg-white transition-all cursor-pointer flex items-center gap-2"
                      >
                        <Download size={12} /> Init_Download
                      </button>
                      <button
                        onClick={() => setUpdateBanner(prev => prev ? { ...prev, show: false } : null)}
                        className="p-2 text-xmr-dim hover:text-xmr-accent transition-colors cursor-pointer"
                      >
                        <X size={14} />
                      </button>
                    </div>
                  </div>
                )}

              <div className={view === 'home' ? 'block' : 'hidden'}><HomeView setView={setView} stats={stats} loading={statsLoading} /></div>
                <div className={view === 'vault' ? 'block' : 'hidden'}><VaultView setView={setView} vault={vault} handleBurn={() => purgeIdentity(activeId)} appConfig={appConfig} /></div>
                <div className={view === 'exchange' ? 'block' : 'hidden'}><ExchangeView localXmrAddress={address} /></div>
                <div className={view === 'vigil' ? 'block' : 'hidden'}><VigilView localXmrAddress={address} /></div>

              <div className={view === 'settings' ? 'block' : 'hidden'}><SettingsView /></div>
                <div className={view === 'agent' ? 'block' : 'hidden'}><AgentTab /></div>
            </>
          )}
        </main>

        {showConsole && (
          <>
            <div className="fixed inset-0 z-50 bg-black/5" onClick={() => setShowConsole(false)} />
            <div className="absolute inset-x-0 bottom-8 h-64 bg-xmr-base/95 backdrop-blur-xl border-t border-xmr-green/30 z-[60] flex flex-col animate-in slide-in-from-bottom-4 duration-300 shadow-[0_-20px_50px_rgba(0,0,0,0.5)] select-text">
              <div className="px-4 py-2 border-b border-xmr-green/10 flex justify-between items-center bg-xmr-green/5">
                <div className="flex items-center gap-2 text-[11px] font-black text-xmr-green uppercase tracking-widest"><TerminalIcon size={12} /> System_Log_Output</div>
                <div className="flex items-center gap-4">
                  <span className="text-[11px] text-xmr-dim uppercase font-black opacity-50">[ PRESS ESC TO CLOSE ]</span>
                  <button onClick={() => setShowConsole(false)} className="text-xmr-dim hover:text-xmr-green transition-all cursor-pointer"><X size={14} /></button>
                </div>
              </div>
              <div className="flex-grow overflow-y-auto p-4 font-mono text-[11px] space-y-1.5 custom-scrollbar">
                {logs.map((log, i) => (
                  <div key={i} className="flex gap-3 group">
                    <span className="text-xmr-dim opacity-85 shrink-0 hidden">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                    <span className={`break-all ${log.type === 'error' ? 'text-red-500 font-bold' :
                      log.type === 'success' ? 'text-xmr-green font-bold' :
                        log.type === 'process' ? 'text-xmr-accent' :
                          log.type === 'warning' ? 'text-orange-500' :
                            log.msg.includes('❌') || log.msg.includes('ERROR') ? 'text-red-500' :
                              log.msg.includes('✅') || log.msg.includes('SUCCESS') ? 'text-xmr-green' :
                                'text-xmr-green/70'
                      }`}>{'>'} {log.msg}</span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}

        <footer className="h-8 border-t border-xmr-border/10 px-8 flex justify-between items-center text-[10px] font-black text-xmr-dim uppercase tracking-widest shrink-0 bg-xmr-surface/80 backdrop-blur-md">
          <div className="flex items-center gap-4">
            <button onClick={() => setShowConsole(!showConsole)} className={`flex items-center gap-1.5 transition-all cursor-pointer ${showConsole ? 'text-xmr-green' : 'text-xmr-dim hover:text-xmr-green'}`}><TerminalIcon size={10} /><span className="font-mono font-black tracking-tighter">CONSOLE</span>{showConsole ? <ChevronDown size={10} /> : <ChevronUp size={10} />}</button>
            <span className="opacity-20">|</span>
            <div className="flex items-center gap-1">
              <span>ID:</span>
              <AddressDisplay address={address} truncate length={12} className="text-xmr-dim" />
            </div>
          </div>
          <div className="flex gap-4">
            <span className="animate-pulse flex items-center gap-1">
              <div className={`w-1 h-1 rounded-full ${isSyncing ? 'bg-xmr-accent' : 'bg-xmr-green'}`}></div>
              {isSyncing ? 'Sync_In_Progress' : 'System_Operational'}
            </span>
            <span className="opacity-75">© 2026 kyc.rip // ripley_terminal_v{appVersion}</span>
          </div>
        </footer>
        {showFeedbackModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/80 backdrop-blur-sm animate-in fade-in duration-300">
            <div className="w-[500px] bg-xmr-base border border-xmr-accent/30 p-8 shadow-2xl relative animate-in zoom-in-95 duration-300">
              <button onClick={() => setShowFeedbackModal(false)} className="absolute top-4 right-4 text-xmr-dim hover:text-xmr-accent transition-colors">
                <X size={20} />
              </button>

              <div className="flex items-center gap-3 mb-6">
                <RefreshCw size={24} className="text-xmr-accent" />
                <div>
                  <h2 className="text-xl font-black uppercase tracking-tighter text-xmr-accent italic leading-none">Transmission_Input</h2>
                  <p className="text-[10px] text-xmr-dim uppercase font-black tracking-widest mt-1">Found a bug? Want a feature? Report it.</p>
                </div>
              </div>

              <textarea
                autoFocus
                value={feedbackText}
                onChange={(e) => setFeedbackText(e.target.value)}
                placeholder="TYPE_YOUR_TACTICAL_FEEDBACK_HERE..."
                className="w-full h-40 bg-xmr-surface border border-xmr-border p-4 text-xs text-xmr-green font-black outline-none focus:border-xmr-accent transition-all resize-none custom-scrollbar"
              />

              <div className="mt-6 flex gap-4">
                <button
                  onClick={() => {
                    const template = encodeURIComponent(`Hi @XBToshi, I have a feedback for Ripley Terminal:\n\n"${feedbackText}"\n\n#kycrip #privacy #RipleyTerminal`);
                    window.api.openExternal(`https://x.com/intent/tweet?text=${template}`);
                    setShowFeedbackModal(false);
                  }}
                  disabled={!feedbackText.trim()}
                  className="flex-grow py-4 bg-xmr-accent text-xmr-base font-black uppercase text-xs tracking-[0.2em] hover:bg-white transition-all disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
                >
                  <RefreshCw size={16} /> Submit_To_Uplink
                </button>
                <button
                  onClick={() => setShowFeedbackModal(false)}
                  className="px-6 py-4 border border-xmr-border text-xmr-dim font-black uppercase text-xs tracking-widest hover:border-xmr-green hover:text-xmr-green transition-all cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
        <XMR402Modal />
      </div>
    </div>
  );
}

export default function App() {
  return (
    <VaultProvider>
      {/* VigilProvider sits ABOVE the lock gate inside MainApp: an armed
          vigil survives lock/unlock and dies only with the process. */}
      <VigilProvider>
        <MainApp />
      </VigilProvider>
    </VaultProvider>
  );
}
