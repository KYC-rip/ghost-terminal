import { useState, useEffect } from 'react';
import { Settings, Server, Zap, EyeOff, Check, RefreshCw, History, ShieldAlert, Edit2, Download, FolderOpen, ExternalLink, Loader2, Image as ImageIcon, Trash2, X } from 'lucide-react';
import { Card } from './Card';
import { useVault } from '../hooks/useVault';

export function SettingsView() {
  const { rescan, currentHeight, purgeIdentity, activeId, renameIdentity, identities } = useVault();

  // 🟢 Unified configuration state
  const [config, setConfig] = useState<any>(null);

  // Local UI state (for interaction before saving)
  const [localSettings, setLocalSettings] = useState({
    routingMode: 'tor',
    network: 'mainnet',
    customNodeAddress: '',
    show_scanlines: true,
    auto_lock_minutes: 10,
    identityName: '',
    useSystemProxy: false,
    systemProxyAddress: '',
    skin_background: '',
    skin_opacity: 0.2,
    skin_style: 'cover',
    shortcuts: {} as Record<string, string>,
    hide_zero_balances: false,
    include_prereleases: false
  });

  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved'>('idle');
  const [targetHeight, setTargetHeight] = useState<string>('');
  const [isRescanning, setIsRescanning] = useState(false);

  // 📦 App Info & Updates state
  const [appInfo, setAppInfo] = useState<{ version: string; appDataPath: string; walletsPath: string; platform: string; capabilities?: { stressnet: boolean } } | null>(null);
  const [isCheckingUpdate, setIsCheckingUpdate] = useState(false);
  const [updateResult, setUpdateResult] = useState<{
    checked: boolean;
    hasUpdate?: boolean;
    latestVersion?: string;
    releaseUrl?: string;
    body?: string;
    error?: string;
  }>({ checked: false });
  const [showChangelog, setShowChangelog] = useState(false);

  const currentIdentity = identities.find(i => i.id === activeId);

  // 1. Initialization: Load full configuration
  useEffect(() => {
    const loadInitialConfig = async () => {
      const fullConfig = await window.api.getConfig();
      setConfig(fullConfig);
      setLocalSettings({
        routingMode: fullConfig.routingMode || 'tor',
        network: fullConfig.network || 'mainnet',
        customNodeAddress: fullConfig.customNodeAddress || '',
        show_scanlines: fullConfig.show_scanlines !== false,
        auto_lock_minutes: fullConfig.auto_lock_minutes || 10,
        identityName: currentIdentity?.name || '',
        useSystemProxy: fullConfig.useSystemProxy || false,
        systemProxyAddress: fullConfig.systemProxyAddress || '',
        skin_background: fullConfig.skin_background || '',
        skin_opacity: fullConfig.skin_opacity !== undefined ? fullConfig.skin_opacity : 0.2,
        skin_style: fullConfig.skin_style || 'cover',
        shortcuts: fullConfig.shortcuts || {},
        hide_zero_balances: fullConfig.hide_zero_balances || false,
        include_prereleases: fullConfig.include_prereleases || false
      });

      const info = await window.api.getAppInfo();
      setAppInfo(info as any);
    };
    loadInitialConfig();
  }, [currentIdentity]);

  // --- Update Checker ---
  const handleCheckUpdate = async () => {
    setIsCheckingUpdate(true);
    setUpdateResult({ checked: false });
    setShowChangelog(false);
    try {
      const res = await window.api.checkForUpdates(localSettings?.include_prereleases);
      if (res.success) {
        setUpdateResult({
          checked: true,
          hasUpdate: res.hasUpdate,
          latestVersion: res.latestVersion,
          releaseUrl: res.releaseUrl,
          body: res.body
        });
      } else {
        setUpdateResult({ checked: true, error: res.error });
      }
    } catch (e: any) {
      setUpdateResult({ checked: true, error: e.message });
    } finally {
      setIsCheckingUpdate(false);
    }
  };

  const handleReveal = async (path: string) => {
    const res = await window.api.openPath(path);
    if (!res.success) alert(`Failed to open path: ${res.error}`);
  };

  // 2. Save: One-time submission to backend
  const handleSave = async () => {
    setSaveStatus('saving');

    try {
      // 1. Handle identity renaming (logical change, no effect on engine)
      if (localSettings.identityName && localSettings.identityName !== currentIdentity?.name) {
        await renameIdentity(activeId, localSettings.identityName);
      }

      // 2. Check if a "physical change" was triggered
      const needsPhysicalReload =
        localSettings.routingMode !== config.routingMode ||
        localSettings.network !== config.network ||
        localSettings.customNodeAddress !== config.customNodeAddress ||
        localSettings.useSystemProxy !== config.useSystemProxy ||
        localSettings.systemProxyAddress !== config.systemProxyAddress;

      const newConfig = {
        ...config,
        routingMode: localSettings.routingMode,
        network: localSettings.network,
        customNodeAddress: localSettings.customNodeAddress,
        useSystemProxy: localSettings.useSystemProxy,
        systemProxyAddress: localSettings.systemProxyAddress,
        show_scanlines: localSettings.show_scanlines,
        auto_lock_minutes: localSettings.auto_lock_minutes,
        skin_background: localSettings.skin_background,
        skin_opacity: localSettings.skin_opacity,
        skin_style: localSettings.skin_style,
        shortcuts: localSettings.shortcuts,
        hide_zero_balances: localSettings.hide_zero_balances,
        include_prereleases: localSettings.include_prereleases
      };

      if (needsPhysicalReload) {
        // 🚀 Trigger physical reload: Reboot Tor / RPC processes
        console.log("⚙️ Physical parameters changed. Re-igniting Uplink...", "warning");
        const res = await window.api.saveConfigAndReload(newConfig);
        if (!res.success) throw new Error(res.error);
      } else {
        // 💾 Save config only: no interruption to current connection
        console.log("💾 UI preferences synchronized.", "success");
        // note: if backend lacks saveConfigOnly, reloadEngine can skip reboot based on logic checks
        await window.api.saveConfigOnly?.(newConfig) || await window.api.saveConfigAndReload(newConfig);
      }

      setSaveStatus('saved');
      setTimeout(() => setSaveStatus('idle'), 2000);

      // Update local benchmark to prevent miscalculation next time
      setConfig(newConfig);

    } catch (e: any) {
      alert(`SAVE_FAILED: ${e.message}`);
      setSaveStatus('idle');
    }
  };

  const handleRescan = async () => {
    const h = parseInt(targetHeight);
    if (isNaN(h)) return alert("INVALID_HEIGHT");

    if (confirm(`INITIATE_RESCAN from height ${h}? This will clear local wallet cache.`)) {
      setIsRescanning(true);
      try {
        await rescan(h);
        alert("RESCAN_SIGNAL_BROADCASTED.");
      } catch (e: any) {
        alert(`RESCAN_FAILED: ${e.message}`);
      } finally {
        setIsRescanning(false);
      }
    }
  };

  if (!config) return null; // Loading

  return (
    <div className="max-w-3xl mx-auto py-8 space-y-8 animate-in fade-in slide-in-from-right-4 duration-500 font-mono font-black">
      <div className="flex items-center gap-4 border-b border-xmr-border/30 pb-6">
        <Settings size={32} className="text-xmr-green" />
        <div>
          <h2 className="text-3xl font-black italic uppercase tracking-tighter text-xmr-green">Ripley_Config</h2>
          <p className="text-xs text-xmr-dim uppercase tracking-widest">Adjust tactical parameters and cryptographic routing.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 font-black">
        {/* 🆔 Identity Section */}
        <section className="space-y-4">
          <h3 className="text-xs font-black text-xmr-green flex items-center gap-2 uppercase"><Edit2 size={14} /> Identity_Management</h3>
          <Card className="p-6 bg-xmr-surface border-xmr-border/40">
            <div className="space-y-2">
              <label className="text-[11px] font-black text-xmr-dim uppercase">Active_Identity_Label</label>
              <input
                type="text"
                value={localSettings.identityName}
                onChange={(e) => setLocalSettings({ ...localSettings, identityName: e.target.value })}
                className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none font-black"
              />
            </div>
          </Card>
        </section>

        {/* 📦 Version & Updates Section */}
        <section className="space-y-4">
          <h3 className="text-xs font-black text-xmr-green flex items-center gap-2 uppercase"><Download size={14} /> System_Updates</h3>
          <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-1">
                <div className="text-xs font-black text-xmr-dim uppercase">Current_Version</div>
                <div className="text-xl text-xmr-green font-mono">v{appInfo?.version || '...'}</div>
                <p className="mt-1 text-xmr-dim/50 italic lowercase">Latest tactical builds from the frontline.</p>
              </div>
              <div className="flex flex-col items-end gap-3">
                <label className="flex items-center gap-3 text-[10px] font-black uppercase tracking-widest cursor-pointer group hover:text-xmr-accent transition-all">
                  <span>Include_Pre-releases</span>
                  <input
                    type="checkbox"
                    className="accent-xmr-accent hidden"
                    checked={localSettings.include_prereleases}
                    onChange={(e) => setLocalSettings({ ...localSettings, include_prereleases: e.target.checked })}
                  />
                  <div className={`w-10 h-5 border flex items-center px-1 transition-all ${localSettings.include_prereleases ? 'border-xmr-accent bg-xmr-accent/10' : 'border-xmr-border bg-xmr-base'}`}>
                    <div className={`w-3 h-3 transition-all ${localSettings.include_prereleases ? 'bg-xmr-accent translate-x-5' : 'bg-xmr-dim translate-x-0'}`} />
                  </div>
                </label>
                <button
                  onClick={handleCheckUpdate}
                  disabled={isCheckingUpdate}
                  className="px-6 py-2 border border-xmr-green text-xmr-green text-xs font-black uppercase tracking-widest hover:bg-xmr-green hover:text-xmr-base transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {isCheckingUpdate ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
                  Check_For_Tactical_Updates
                </button>
              </div>
            </div>

            {updateResult.checked && (
              <div className={`mt-4 p-4 border rounded-sm text-xs ${updateResult.error ? 'border-xmr-error/50 bg-xmr-error/10 text-xmr-error' : updateResult.hasUpdate ? 'border-xmr-accent/50 bg-xmr-accent/10 text-xmr-accent' : 'border-xmr-border bg-xmr-base text-xmr-dim'}`}>
                {updateResult.error ? (
                  <div className="flex items-center gap-2"><ShieldAlert size={14} /> Update check failed: {updateResult.error}</div>
                ) : updateResult.hasUpdate ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 font-black uppercase text-xs">
                        <Zap size={14} className="animate-pulse" /> Update Available: v{updateResult.latestVersion}
                      </div>
                      <button onClick={() => updateResult.releaseUrl && window.open(updateResult.releaseUrl)} className="flex items-center gap-1.5 px-3 py-1.5 bg-xmr-accent text-xmr-base hover:bg-white transition-colors cursor-pointer font-black uppercase">
                        <Download size={10} /> Download Release
                      </button>
                    </div>
                    {updateResult.body && (
                      <div className="mt-2 text-xmr-green border border-xmr-border/50 bg-xmr-base">
                        <button onClick={() => setShowChangelog(!showChangelog)} className="w-full flex items-center justify-between p-2 hover:bg-xmr-surface transition-colors cursor-pointer text-[11px] uppercase tracking-widest text-xmr-dim">
                          <span>View Changelog</span>
                          <span className="opacity-50 text-[16px] leading-none">{showChangelog ? '−' : '+'}</span>
                        </button>
                        {showChangelog && (
                          <div className="p-3 border-t border-xmr-border/50 font-mono whitespace-pre-wrap max-h-48 overflow-y-auto custom-scrollbar text-[11px]">
                            {updateResult.body}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 uppercase font-black"><Check size={14} className="text-xmr-green" /> System is up to date</div>
                )}
              </div>
            )}
          </Card>
        </section>

        {/* 🌐 Network Section */}
        <section className="space-y-4 font-black">
          <h3 className="text-xs font-black text-xmr-green flex items-center gap-2 uppercase"><Server size={14} /> Uplink_Protocols</h3>
          <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-6">

            {/* Routing Mode Toggle (Tor vs Clearnet) */}
            <div className="flex items-center justify-between p-4 bg-xmr-green/5 border border-xmr-green/20 rounded-sm">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Zap size={14} className={localSettings.routingMode === 'tor' ? "text-xmr-green animate-pulse" : "text-xmr-dim"} />
                  <span className="text-xs text-xmr-green font-black uppercase">Tor_Darknet_Routing</span>
                </div>
                <p className="text-xs text-xmr-dim uppercase font-black">Onion_Tunnel_Privacy_Active</p>
              </div>
              <button
                onClick={() => setLocalSettings({ ...localSettings, routingMode: localSettings.routingMode === 'tor' ? 'clearnet' : 'tor' })}
                className={`w-10 h-5 rounded-full relative transition-all cursor-pointer ${localSettings.routingMode === 'tor' ? 'bg-xmr-green' : 'bg-xmr-base border border-xmr-border'}`}
              >
                <div className={`absolute top-0.5 w-3 h-3 rounded-full transition-all ${localSettings.routingMode === 'tor' ? 'right-1 bg-xmr-base' : 'left-1 bg-xmr-border'}`}></div>
              </button>
            </div>

            {/* Network Selector (Mainnet / Stagenet / FCMP++ Stressnet) */}
            <div className={`p-4 border rounded-sm transition-all space-y-3 ${localSettings.network !== 'mainnet' ? 'bg-xmr-accent/10 border-xmr-accent/40' : 'bg-xmr-green/5 border-xmr-border'}`}>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <RefreshCw size={14} className={localSettings.network !== 'mainnet' ? "text-xmr-accent animate-spin" : "text-xmr-dim"} />
                  <span className={`text-xs font-black uppercase ${localSettings.network !== 'mainnet' ? 'text-xmr-accent' : ''}`}>Network_Protocol</span>
                </div>
                <p className="text-xs text-xmr-dim uppercase font-black">Wallets are stored per-network and never mix</p>
              </div>
              <div className="grid grid-cols-3 gap-2">
                {([
                  { id: 'mainnet', label: 'MAINNET' },
                  { id: 'stagenet', label: 'STAGENET' },
                  ...(appInfo?.capabilities?.stressnet ? [{ id: 'stressnet', label: 'STRESSNET FCMP++' }] : []),
                ] as { id: string; label: string }[]).map((net) => (
                  <button
                    key={net.id}
                    onClick={() => setLocalSettings({ ...localSettings, network: net.id })}
                    className={`px-2 py-2 border rounded-sm text-[10px] font-black uppercase tracking-wider transition-all cursor-pointer
                      ${localSettings.network === net.id
                        ? net.id === 'stressnet' ? 'bg-xmr-warning/10 border-xmr-warning text-xmr-warning' : 'bg-xmr-accent/10 border-xmr-accent text-xmr-accent'
                        : 'bg-xmr-base border-xmr-border text-xmr-dim hover:border-xmr-dim/50'}`}
                  >
                    {net.label}
                  </button>
                ))}
              </div>
              {localSettings.network === 'stressnet' && (
                <p className="text-[10px] text-xmr-warning uppercase font-black">
                  FCMP++/CARROT beta stressnet — test coins only, chain may reset
                </p>
              )}
            </div>

            {/* System Proxy */}
            <div className="flex items-center justify-between p-4 bg-xmr-green/5 border border-xmr-green/20 rounded-sm">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-xmr-green font-black uppercase">Follow_OS_Proxy</span>
                </div>
                <p className="text-xs text-xmr-dim uppercase font-black">Inherit_System_Network_Settings</p>
              </div>
              <button
                onClick={() => setLocalSettings({ ...localSettings, useSystemProxy: !localSettings.useSystemProxy })}
                className={`w-10 h-5 rounded-full relative transition-all cursor-pointer ${localSettings.useSystemProxy ? 'bg-xmr-green' : 'bg-xmr-base border border-xmr-border'}`}
              >
                <div className={`absolute top-0.5 w-3 h-3 rounded-full transition-all ${localSettings.useSystemProxy ? 'right-1 bg-xmr-base' : 'left-1 bg-xmr-border'}`}></div>
              </button>
            </div>

            {!localSettings.useSystemProxy && (
              <div className="space-y-2 mt-2">
                <label className="text-[11px] font-black text-xmr-dim uppercase border-l-2 border-xmr-border pl-2">Manual_Proxy_Override (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g., socks5://127.0.0.1:7890"
                  value={localSettings.systemProxyAddress}
                  onChange={(e) => setLocalSettings({ ...localSettings, systemProxyAddress: e.target.value })}
                  className="w-full bg-xmr-base border border-xmr-border focus:border-xmr-green/50 hover:border-xmr-green/30 p-3 text-xs text-xmr-green outline-none font-black transition-colors"
                />
              </div>
            )}

            {/* Custom Node Address */}
            <div className="space-y-2">
              <label className="text-[11px] font-black text-xmr-dim uppercase">Manual_Uplink_Address (Optional)</label>
              <input
                type="text"
                placeholder="Leave empty for automatic node selection"
                value={localSettings.customNodeAddress}
                onChange={(e) => setLocalSettings({ ...localSettings, customNodeAddress: e.target.value })}
                className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none font-black"
              />
            </div>
          </Card>
        </section>

        {/* 📊 Rescan Section */}
        <section className="space-y-4">
          <h3 className="text-xs font-black text-xmr-green flex items-center gap-2 uppercase"><History size={14} /> Synchronized_Ledger</h3>
          <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-4">
            <div className="flex justify-between items-center text-xs font-black uppercase">
              <span className="text-xmr-dim">Current_Head</span>
              <span className="text-xmr-green">{currentHeight || 'FETCHING...'}</span>
            </div>
            <div className="space-y-2">
              <label className="text-[11px] font-black text-xmr-dim uppercase">Target_Restore_Height</label>
              <div className="flex gap-2">
                <input
                  type="number"
                  placeholder="3100000"
                  value={targetHeight}
                  onChange={(e) => setTargetHeight(e.target.value)}
                  className="flex-grow bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none font-black"
                />
                <button
                  disabled={isRescanning || !targetHeight}
                  onClick={handleRescan}
                  className="px-4 bg-xmr-green text-xmr-base text-xs font-black uppercase hover:bg-white transition-all disabled:opacity-50 cursor-pointer"
                >
                  {isRescanning ? 'Scanning...' : 'Trigger_Rescan'}
                </button>
              </div>
            </div>
          </Card>
        </section>

        {/* 📁 Storage Paths Section */}
        <section className="space-y-4">
          <h3 className="text-xs font-black text-xmr-green flex items-center gap-2 uppercase"><FolderOpen size={14} /> Data_Storage</h3>
          <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-4">
            <div className="space-y-4">
              {/* App Data Path */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs font-black text-xmr-dim uppercase">
                  <span>Application_Data</span>
                  <button onClick={() => appInfo?.appDataPath && handleReveal(appInfo.appDataPath)} className="flex items-center gap-1 hover:text-xmr-accent transition-colors cursor-pointer"><ExternalLink size={10} /> Reveal</button>
                </div>
                <div className="w-full bg-xmr-base border border-xmr-border p-2 text-[11px] text-xmr-green opacity-70 font-mono select-all overflow-x-auto whitespace-nowrap custom-scrollbar">
                  {appInfo?.appDataPath || 'Loading...'}
                </div>
                <p className="text-xs text-xmr-dim uppercase opacity-60">Contains configuration, node lists, and Tor runtime data.</p>
              </div>

              {/* Wallets Path */}
              <div className="space-y-1.5 pt-2 border-t border-xmr-border/20">
                <div className="flex items-center justify-between text-xs font-black text-xmr-dim uppercase">
                  <span>Encrypted_Vault_Storage</span>
                  <button onClick={() => appInfo?.walletsPath && handleReveal(appInfo.walletsPath)} className="flex items-center gap-1 hover:text-xmr-accent transition-colors cursor-pointer"><ExternalLink size={10} /> Reveal</button>
                </div>
                <div className="w-full bg-xmr-base border border-xmr-error/30 p-2 text-[11px] text-xmr-green opacity-70 font-mono select-all overflow-x-auto whitespace-nowrap custom-scrollbar">
                  {appInfo?.walletsPath || 'Loading...'}
                </div>
                <p className="text-xs text-xmr-error/60 uppercase font-black flex items-center gap-1"><ShieldAlert size={8} /> Never share or modify these files manually. Backup regularly.</p>
              </div>
            </div>
          </Card>
        </section>

        {/* 👁️ Visuals & UI Section */}
        <section className="space-y-4">
          <h3 className="text-xs font-black text-xmr-green flex items-center gap-2 uppercase"><EyeOff size={14} /> Countermeasures & UI</h3>
          <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-6">
            <div className="flex items-center justify-between">
              <div className="space-y-1"><span className="text-xs text-xmr-green font-black uppercase">CRT_Visual_Scanlines</span><p className="text-xs text-xmr-dim uppercase font-black">Overlay_Effect</p></div>
              <button
                onClick={() => setLocalSettings({ ...localSettings, show_scanlines: !localSettings.show_scanlines })}
                className={`w-10 h-5 rounded-full relative transition-all cursor-pointer ${localSettings.show_scanlines ? 'bg-xmr-green' : 'bg-xmr-base border border-xmr-border'}`}
              >
                <div className={`absolute top-0.5 w-3 h-3 rounded-full transition-all ${localSettings.show_scanlines ? 'right-1 bg-xmr-base' : 'left-1 bg-xmr-border'}`}></div>
              </button>
            </div>

            <div className="flex items-center justify-between border-t border-xmr-border/10 pt-6">
              <div className="space-y-1">
                <span className="text-xs text-xmr-green font-black uppercase">Auto_Lock_Timeout</span>
                <p className="text-xs text-xmr-dim uppercase font-black">Lock session after inactivity (min)</p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  value={localSettings.auto_lock_minutes}
                  onChange={(e) => setLocalSettings({ ...localSettings, auto_lock_minutes: parseInt(e.target.value) || 0 })}
                  className="w-20 bg-xmr-base border border-xmr-border p-2 text-right text-xs text-xmr-green outline-none font-black"
                />
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-xmr-border/10 pt-6">
              <div className="space-y-1">
                <span className="text-xs text-xmr-green font-black uppercase">Reset_Context_Tooltips</span>
                <p className="text-xs text-xmr-dim uppercase font-black">Restore all dismissed 'How It Works' banners</p>
              </div>
              <button
                onClick={() => {
                  localStorage.removeItem('hide_explainer_vault_churn');
                  localStorage.removeItem('hide_explainer_vault_splinter');
                  alert("CONTEXT_RESET: Educational banners will reappear.");
                }}
                className="px-3 py-1.5 border border-xmr-border text-[10px] uppercase font-black hover:border-xmr-green hover:text-xmr-green transition-all cursor-pointer"
              >
                Restore_Banners
              </button>
            </div>

            {/* Custom Interface Skin */}
            <div className="flex flex-col border-t border-xmr-border/10 pt-6 space-y-4">
              <div className="space-y-1">
                <span className="text-xs text-xmr-green font-black uppercase flex items-center gap-2">
                  <ImageIcon size={12} /> Custom_Skin
                </span>
                <p className="text-xs text-xmr-dim uppercase font-black">Upload a local image (JPG/PNG/GIF) to use as background.</p>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={async () => {
                    const res = await window.api.selectBackgroundImage?.();
                    if (res?.success) {
                      setLocalSettings({ ...localSettings, skin_background: res.data || '' });
                    } else if (res?.error && res.error !== 'Cancelled') {
                      alert(`Failed to load image: ${res.error}`);
                    }
                  }}
                  className="px-4 py-2 bg-xmr-base border border-xmr-border hover:border-xmr-accent text-xmr-green text-xs font-black uppercase transition-colors cursor-pointer flex items-center gap-2"
                >
                  <FolderOpen size={12} /> Select_Image
                </button>

                {localSettings.skin_background && (
                  <button
                    onClick={() => setLocalSettings({ ...localSettings, skin_background: '' })}
                    className="px-4 py-2 bg-xmr-error/10 border border-xmr-error/30 hover:bg-xmr-error/30 text-xmr-error text-xs font-black uppercase transition-colors cursor-pointer flex items-center gap-2"
                  >
                    <Trash2 size={12} /> Clear
                  </button>
                )}

                <button
                  onClick={() => window.api.openExternal('https://x.com/search?q=%23RipleyTerminalSkin')}
                  className="px-4 py-2 bg-xmr-base border border-xmr-border hover:border-xmr-accent text-xmr-green text-xs font-black uppercase transition-colors cursor-pointer flex items-center gap-2">
                  <ExternalLink size={12} /> Find more on <X size={14} />
                </button>
              </div>

              {localSettings.skin_background && (
                <div className="grid grid-cols-2 gap-4 mt-2 p-4 bg-xmr-base border border-xmr-border/50">
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <label className="text-[10px] text-xmr-dim uppercase font-black block">Skin_Opacity ({Math.round(localSettings.skin_opacity * 100)}%)</label>
                      <input
                        type="range"
                        min="0.05" max="1" step="0.05"
                        value={localSettings.skin_opacity}
                        onChange={(e) => setLocalSettings({ ...localSettings, skin_opacity: parseFloat(e.target.value) })}
                        className="w-full accent-xmr-green cursor-ew-resize"
                      />
                    </div>

                    <div className="space-y-2">
                      <label className="text-[10px] text-xmr-dim uppercase font-black block">Skin_Position</label>
                      <select
                        value={localSettings.skin_style}
                        onChange={(e) => setLocalSettings({ ...localSettings, skin_style: e.target.value as any })}
                        className="w-full bg-xmr-surface border border-xmr-border/50 p-2 text-xs text-xmr-green uppercase outline-none focus:border-xmr-accent"
                      >
                        <option value="cover">Cover (Center)</option>
                        <option value="contain">Contain (Fit)</option>
                        <option value="tile">Tile (Repeat)</option>
                        <option value="top-left">Top Left</option>
                      </select>
                    </div>
                  </div>

                  <div className="border border-xmr-border/30 rounded-sm overflow-hidden relative bg-black/50 h-24 flex items-center justify-center">
                    <div
                      className="absolute inset-0 z-0 pointer-events-none"
                      style={{
                        backgroundImage: `url(${localSettings.skin_background})`,
                        opacity: localSettings.skin_opacity,
                        backgroundSize: localSettings.skin_style === 'cover' || localSettings.skin_style === 'contain' ? localSettings.skin_style : localSettings.skin_style === 'tile' ? 'auto' : 'cover',
                        backgroundPosition: localSettings.skin_style === 'top-left' ? 'top left' : 'center',
                        backgroundRepeat: localSettings.skin_style === 'tile' ? 'repeat' : 'no-repeat'
                      }}
                    />
                    <span className="text-[10px] text-white/50 z-10 font-bold mix-blend-difference drop-shadow-md">Preview</span>
                  </div>
                </div>
              )}
            </div>
          </Card>
        </section>

        {/* ⌨️ Keyboard Command Center */}
        <section className="space-y-4">
          <h3 className="text-xs font-black text-xmr-green flex items-center gap-2 uppercase">
            <Zap size={14} /> Tactical_Shortcuts
          </h3>
          <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-4">
            <p className="text-[10px] text-xmr-dim uppercase font-black leading-relaxed">
              Map major terminal functions to key sequences.<br />
              Format: <span className="text-xmr-green">Mod+Key</span> (e.g., Mod+S) or <span className="text-xmr-green">Mod+Alt+Key</span>.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(localSettings.shortcuts || {}).map(([action, sequence]) => (
                <div key={action} className="flex flex-col gap-1.5">
                  <label className="text-[10px] font-black text-xmr-dim uppercase">{action.replace('_', ' ')}</label>
                  <input
                    type="text"
                    value={sequence}
                    onChange={(e) => {
                      const newShortcuts = { ...localSettings.shortcuts, [action]: e.target.value };
                      setLocalSettings({ ...localSettings, shortcuts: newShortcuts });
                    }}
                    className="bg-xmr-base border border-xmr-border p-2 text-xs text-xmr-green focus:border-xmr-green outline-none font-black"
                    placeholder="e.g. Mod+S"
                  />
                </div>
              ))}
            </div>
          </Card>
        </section>

        {/* ☢️ Danger Zone */}
        <section className="space-y-4 pt-4">
          <h3 className="text-xs font-black text-xmr-error flex items-center gap-2 uppercase"><ShieldAlert size={14} /> Dangerous_Sector</h3>
          <Card noPadding={false} topGradientAccentColor='xmr-error' className="p-6 bg-xmr-error/5 border-xmr-error/30 flex items-center justify-between">
            <div className="space-y-1"><span className="text-xs font-black text-xmr-error uppercase">Nuclear_Burn_ID</span><p className="text-xs text-xmr-error/60 uppercase font-black">Erase local seed and vault keys forever.</p></div>
            <button onClick={() => purgeIdentity(activeId)} className="px-4 py-2 border border-xmr-error text-xmr-error text-xs font-black hover:bg-xmr-error hover:text-white transition-all uppercase cursor-pointer">Burn_Everything</button>
          </Card>
        </section>
      </div>

      <div className="pt-6 flex justify-end">
        <button
          onClick={handleSave}
          disabled={saveStatus !== 'idle'}
          className="px-10 py-4 font-black uppercase tracking-[0.3em] flex items-center gap-3 transition-all cursor-pointer bg-xmr-green text-xmr-base hover:opacity-90"
        >
          {saveStatus === 'saving' ? <RefreshCw size={16} className="animate-spin" /> : saveStatus === 'saved' ? <Check size={16} /> : null}
          {saveStatus === 'saving' ? 'Applying_Uplink...' : saveStatus === 'saved' ? 'Config_Synchronized' : 'Commit_Changes'}
        </button>
      </div>
    </div>
  );
}