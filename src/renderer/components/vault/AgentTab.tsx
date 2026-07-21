import { useState, useEffect } from 'react';
import { Bot, Shield, Zap, Key, RefreshCw, BarChart3, Activity, Terminal as TerminalIcon, ChevronDown, ChevronUp } from 'lucide-react';
import { Card } from '../Card';
import { useVault } from '../../hooks/useVault';

export function AgentTab() {
  const { identities, activeId, accounts } = useVault();
  const [isEnabled, setIsEnabled] = useState(false);
  const [dailyLimit, setDailyLimit] = useState('0.1');
  const [totalLimit, setTotalLimit] = useState('1.0');
  const [apiKey, setApiKey] = useState('RG-************************');
  const [showApiKey, setShowApiKey] = useState(false);
  const [selectedAccountIndex, setSelectedAccountIndex] = useState(0);
  const [activities, setActivities] = useState<{ id: string; type: string; msg: string; timestamp: number; status: 'ok' | 'fail' }[]>([]);
  const [activeInstallTab, setActiveInstallTab] = useState<'gemini' | 'claw' | 'claude'>('gemini');
  const [networkType, setNetworkType] = useState('mainnet');
  const [isUplinkExpanded, setIsUplinkExpanded] = useState(false);

  const blockedCount = activities.filter(a => a.status === 'fail').length;
  const managedBalance = accounts.find(a => a.index === selectedAccountIndex)?.balance || '0.0000';

  // 1. Initial Load
  useEffect(() => {
    const loadCfg = async () => {
      const fullConfig = await window.api.getConfig();
      const agent = fullConfig.agent_config;
      if (agent) {
        setIsEnabled(agent.enabled);
        setDailyLimit(agent.dailyLimit);
        setTotalLimit(agent.totalLimit);
        setApiKey(agent.apiKey);
        setSelectedAccountIndex(agent.selectedAccountIndex || 0);
        setNetworkType(fullConfig.network || 'mainnet');
      }
    };
    loadCfg();
  }, [activeId]);

  // 2. Real-time Activity Listener
  useEffect(() => {
    const cleanup = window.api.onAgentActivity((activity: any) => {
      setActivities(prev => [activity, ...prev].slice(0, 50));
    });
    return cleanup;
  }, []);

  // 3. Save Config helper
  const syncConfig = async (overrides: any = {}) => {
    const fullConfig = await window.api.getConfig();
    const updated = {
      ...fullConfig.agent_config,
      enabled: isEnabled,
      dailyLimit,
      totalLimit,
      apiKey,
      selectedAccountIndex,
      ...overrides
    };
    await window.api.updateAgentConfig(updated);
  };

  const handleToggle = async () => {
    const next = !isEnabled;
    setIsEnabled(next);
    await syncConfig({ enabled: next });
  };

  const handleRegenKey = async () => {
    if (confirm("Regenerate Agent API Key? Existing agent connections will be severed.")) {
      const newKey = "RG-" + Math.random().toString(36).substring(2, 15).toUpperCase();
      setApiKey(newKey);
      await syncConfig({ apiKey: newKey });
      alert("NEW_KEY_GENERATED: Update your agent configuration.");
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 font-mono font-black select-none">

      {/* 1. HERO / MASCOT SECTION */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
        <div className="relative group">
          <div className="absolute inset-0 bg-xmr-green/10 blur-3xl rounded-full animate-pulse group-hover:bg-xmr-green/20 transition-all duration-1000"></div>
          {/* Mascot Animation Container */}
          <div className="relative z-10 p-8 flex justify-center h-64">
            <div className="mascot-wrapper relative w-64 h-64 group-hover:scale-105 transition-transform duration-700">
              {/* Front View */}
              <img
                src="/ripley_cybercat-front.png"
                alt="Ripley Front"
                className="absolute inset-0 w-full h-full object-contain filter brightness-110 drop-shadow-[0_0_30px_var(--color-xmr-green)] animate-mascot-front"
              />
              {/* Side View (Animated Flip) */}
              <img
                src="/ripley_cybercat.png"
                alt="Ripley Side"
                className="absolute inset-0 w-full h-full object-contain filter brightness-110 drop-shadow-[0_0_30px_var(--color-xmr-green)] animate-mascot-side"
              />
            </div>
          </div>
          <div className="absolute top-4 left-4 border-l-2 border-t-2 border-xmr-green/30 w-8 h-8"></div>
          <div className="absolute bottom-4 right-4 border-r-2 border-b-2 border-xmr-green/30 w-8 h-8"></div>
        </div>

        <div className="space-y-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <Bot size={32} className="text-xmr-green" />
              <h2 className="text-3xl font-black italic uppercase tracking-tighter text-xmr-green">Agent_Gateway</h2>
            </div>
            <p className="text-xs text-xmr-dim uppercase tracking-widest leading-relaxed">
              Connect autonomous AI entities to your local Monero liquidity.
              Configure granular spend permissions and monitoring protocols.
            </p>
          </div>

          <div className="flex items-center justify-between p-6 bg-xmr-green/5 border border-xmr-green/20 rounded-sm">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Activity size={14} className={isEnabled ? "text-xmr-green animate-pulse" : "text-xmr-dim"} />
                <span className="text-xs text-xmr-green font-black uppercase">Gateway_Interface</span>
              </div>
              <p className="text-[10px] text-xmr-dim uppercase font-black tracking-widest">
                {isEnabled ? "UPLINK_ESTABLISHED : LISTENING_ON_PORT_38084" : "INTERFACE_STANDBY : NO_LISTENER"}
              </p>
            </div>
            <button
              onClick={() => setIsEnabled(!isEnabled)}
              className={`w-12 h-6 rounded-full relative transition-all cursor-pointer ${isEnabled ? 'bg-xmr-green shadow-[0_0_15px_var(--color-xmr-green)]' : 'bg-xmr-base border border-xmr-border'}`}
            >
              <div className={`absolute top-1 w-4 h-4 rounded-full transition-all ${isEnabled ? 'right-1 bg-xmr-base' : 'left-1 bg-xmr-dim'}`}></div>
            </button>
          </div>
        </div>
      </div>

      {/* 2. CONFIG & FEED GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

        {/* CONFIG COLUMN */}
        <div className="lg:col-span-1 space-y-6">
          <section className="space-y-4">
            <h3 className="text-[11px] font-black text-xmr-green flex items-center gap-2 uppercase tracking-[0.2em]">
              <Shield size={14} /> Spend_Countermeasures
            </h3>
            <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-6">
              <div className="space-y-2">
                <label className="text-[10px] font-black text-xmr-dim uppercase tracking-widest">Daily_Agent_Limit (XMR)</label>
                <input
                  type="text"
                  value={dailyLimit}
                  onChange={(e) => setDailyLimit(e.target.value)}
                  className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none font-black"
                />
              </div>
              <div className="space-y-2">
                <label className="text-[10px] font-black text-xmr-dim uppercase tracking-widest">Global_Session_Limit (XMR)</label>
                <input
                  type="text"
                  value={totalLimit}
                  onChange={(e) => setTotalLimit(e.target.value)}
                  className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none font-black"
                />
              </div>
              <div className="space-y-2">
                <label className="text-[10px] font-black text-xmr-dim uppercase tracking-widest">Access_Liquidity_Account</label>
                <select
                  value={selectedAccountIndex}
                  onChange={(e) => setSelectedAccountIndex(parseInt(e.target.value))}
                  className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-green outline-none font-black uppercase"
                >
                  {accounts.map((acc: any) => (
                    <option key={acc.index} value={acc.index}>
                      {acc.index}: {acc.label || 'UNTITLED'} ({parseFloat(acc.balance).toFixed(4)} XMR)
                    </option>
                  ))}
                  {accounts.length === 0 && (
                    <option value={0}>Primary Account (0.0000 XMR)</option>
                  )}
                </select>
              </div>
            </Card>
          </section>

          <section className="space-y-4">
            <h3 className="text-[11px] font-black text-xmr-green flex items-center gap-2 uppercase tracking-[0.2em]">
              <Key size={14} /> Authentication_Keys
            </h3>
            <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-4">
              <div className="relative group">
                <input
                  type={showApiKey ? "text" : "password"}
                  readOnly
                  value={apiKey}
                  className="w-full bg-xmr-base border border-xmr-border p-3 pr-12 text-[10px] text-xmr-green font-black select-all"
                />
                <button
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-3 top-3 text-xmr-dim hover:text-xmr-green transition-colors cursor-pointer"
                >
                  <Zap size={14} className={showApiKey ? "text-xmr-accent" : ""} />
                </button>
              </div>
              <button
                onClick={handleRegenKey}
                className="w-full py-3 border border-xmr-border text-[10px] text-xmr-dim hover:border-xmr-green hover:text-xmr-green transition-all uppercase font-black flex items-center justify-center gap-2 cursor-pointer"
              >
                <RefreshCw size={12} /> Rotate_Access_Key
              </button>
            </Card>
          </section>
        </div>

        {/* FEED & INSTRUCTIONS COLUMN */}
        <div className="lg:col-span-2 space-y-8">
          {/* KNOWLEDGE_UPLINK Section */}
          <section className="space-y-4">
            <h3
              onClick={() => setIsUplinkExpanded(!isUplinkExpanded)}
              className="text-[11px] font-black text-xmr-green flex items-center justify-between uppercase tracking-[0.2em] cursor-pointer hover:opacity-80 transition-opacity"
            >
              <div className="flex items-center gap-2">
                <Zap size={14} className={isEnabled ? "animate-pulse" : ""} /> Knowledge_Uplink
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[9px] opacity-50 underline decoration-xmr-green/20">AGENT_SKILL_SETUP</span>
                {isUplinkExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </div>
            </h3>

            <Card className={`p-6 bg-xmr-surface border-xmr-border/40 transition-all duration-300 overflow-hidden ${isUplinkExpanded ? 'max-h-[500px] opacity-100' : 'max-h-0 opacity-0 overflow-hidden !py-0 !border-none'}`}>
              <div className="space-y-4">
                <p className="text-[10px] text-xmr-dim uppercase font-black leading-relaxed">
                  Teach your AI agent how to use this gateway. This desktop wallet is a drop-in provider for the <span className="text-xmr-green">ripley-xmr-gateway</span> skill.
                </p>

                <div className="flex border-b border-xmr-border/20">
                  <button
                    onClick={() => setActiveInstallTab('gemini')}
                    className={`px-4 py-2 text-[10px] uppercase font-black tracking-tighter transition-all ${activeInstallTab === 'gemini' ? 'text-xmr-green border-b-2 border-xmr-green' : 'text-xmr-dim hover:text-xmr-green'}`}
                  >Gemini</button>
                  <button
                    onClick={() => setActiveInstallTab('claw')}
                    className={`px-4 py-2 text-[10px] uppercase font-black tracking-tighter transition-all ${activeInstallTab === 'claw' ? 'text-xmr-green border-b-2 border-xmr-green' : 'text-xmr-dim hover:text-xmr-green'}`}
                  >OpenClaw</button>
                  <button
                    onClick={() => setActiveInstallTab('claude')}
                    className={`px-4 py-2 text-[10px] uppercase font-black tracking-tighter transition-all ${activeInstallTab === 'claude' ? 'text-xmr-green border-b-2 border-xmr-green' : 'text-xmr-dim hover:text-xmr-green'}`}
                  >Claude/Manual</button>
                </div>

                <div className="space-y-4">
                  {activeInstallTab === 'gemini' && (
                    <div className="space-y-2 animate-in fade-in slide-in-from-top-1 duration-300">
                      <label className="text-[9px] text-xmr-green/60 uppercase font-black tracking-widest">Git_Install_Command</label>
                      <div className="bg-xmr-base/60 p-3 border border-xmr-border/30 rounded-sm font-mono text-[10px] text-xmr-green select-all break-all leading-relaxed">
                        gemini skills install https://github.com/KYC-rip/ripley-xmr-gateway.git --path skills/monero-wallet
                      </div>
                    </div>
                  )}

                  {activeInstallTab === 'claw' && (
                    <div className="space-y-2 animate-in fade-in slide-in-from-top-1 duration-300">
                      <label className="text-[9px] text-xmr-green/60 uppercase font-black tracking-widest">NPM_Install_Command</label>
                      <div className="bg-xmr-base/60 p-3 border border-xmr-border/30 rounded-sm font-mono text-[10px] text-xmr-green select-all break-all leading-relaxed">
                        npx clawhub@latest install monero-wallet
                      </div>
                    </div>
                  )}

                  {activeInstallTab === 'claude' && (
                    <div className="space-y-2 animate-in fade-in slide-in-from-top-1 duration-300">
                      <label className="text-[9px] text-xmr-green/60 uppercase font-black tracking-widest">System_Prompt_Uplink</label>
                      <div className="bg-xmr-base/60 p-3 border border-xmr-border/30 rounded-sm font-mono text-[10px] text-xmr-green select-all whitespace-pre-wrap break-all opacity-80 hover:opacity-100 transition-opacity">
                        {`# Monero Ripley Gateway Skill\nURL: http://localhost:38084\nAPI_KEY: ${apiKey}\nACCOUNT_INDEX: ${selectedAccountIndex}\nNETWORK: ${networkType}\nCOMMANDS: /sync, /balance, /subaddress, /transfer`}
                      </div>
                      <p className="text-[8px] text-xmr-dim/60 uppercase font-black">
                        For local Claude Desktop, you can also download the ZIP from GitHub and import via Settings.
                      </p>
                    </div>
                  )}
                </div>

                <div className="pt-2 border-t border-xmr-border/10">
                  <p className="text-[9px] text-xmr-dim uppercase font-black italic">
                    * Ensure the Ripley Terminal is running and the gateway is enabled.
                  </p>
                </div>
              </div>
            </Card>
          </section>

          <section className="space-y-4">
            <h3 className="text-[11px] font-black text-xmr-green flex items-center justify-between uppercase tracking-[0.2em]">
              <div className="flex items-center gap-2">
                <TerminalIcon size={14} /> Real-time_Agent_Activity
              </div>
              <span className="text-[9px] opacity-50">PROCESSED_VIA_LOCAL_UPLINK</span>
            </h3>
            <Card withGlow={false} noPadding className="h-[300px] flex flex-col bg-black/40 border-xmr-border/30 overflow-hidden relative">
              <div className="flex-grow overflow-y-auto p-4 space-y-3 custom-scrollbar">
                {activities.map(act => (
                  <div key={act.id} className="group border-l-2 border-xmr-border/20 pl-4 py-1 hover:border-xmr-green/40 transition-all">
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest">
                        <span className={act.status === 'ok' ? 'text-xmr-green' : 'text-xmr-error'}>[{act.type}]</span>
                        <span className="text-xmr-dim opacity-50">{new Date(act.timestamp).toLocaleTimeString()}</span>
                      </div>
                      {act.status === 'fail' && <Shield size={10} className="text-xmr-error animate-pulse" />}
                    </div>
                    <p className={`text-[11px] font-black tracking-tight leading-none ${act.status === 'ok' ? 'text-xmr-dim group-hover:text-xmr-green' : 'text-xmr-error/80'} transition-colors`}>
                      {act.msg}
                    </p>
                  </div>
                ))}
              </div>
              <div className="p-3 border-t border-xmr-border/20 bg-xmr-green/[0.02] flex justify-between items-center">
                <div className="flex items-center gap-1.5 text-[9px] font-black uppercase text-xmr-dim tracking-tighter">
                  <div className="w-1.5 h-1.5 rounded-full bg-xmr-green animate-pulse"></div>
                  Agent_Gateway_Heartbeat_OK
                </div>
                <div className="text-[9px] font-black text-xmr-green/40">PORT: 38084</div>
              </div>
            </Card>

            <div className="grid grid-cols-2 gap-4">
              <Card withGlow={false} className="p-4 bg-xmr-surface/30 border-xmr-border/30 text-center space-y-1">
                <div className="text-[9px] font-black uppercase text-xmr-dim tracking-widest opacity-60">Session_Blocked</div>
                <div className="text-xl font-black text-xmr-error italic">{blockedCount}</div>
              </Card>
              <Card withGlow={false} className="p-4 bg-xmr-surface/30 border-xmr-border/30 text-center space-y-1">
                <div className="text-[9px] font-black uppercase text-xmr-dim tracking-widest opacity-60">Uplink_Managed_XMR</div>
                <div className="text-xl font-black text-xmr-green/80 italic">{parseFloat(managedBalance).toFixed(4)}</div>
              </Card>
            </div>
            <div className="pt-4 flex justify-end">
              <button
                onClick={() => syncConfig()}
                className="px-8 py-3 bg-xmr-green text-xmr-base font-black uppercase text-[10px] tracking-[0.2em] hover:bg-white transition-all cursor-pointer flex items-center gap-2"
              >
                <Shield size={12} /> Commit_Gateway_Settings
              </button>
            </div>
          </section>
        </div>
      </div>

      {/* 3. MASCOT PROMPT (For Reference) */}
      <Card className="p-6 bg-xmr-surface border-xmr-border/40 space-y-4 opacity-50 hover:opacity-100 transition-opacity">
        <h4 className="text-[11px] font-black text-xmr-dim uppercase tracking-[0.2em] flex items-center gap-2">
          <BarChart3 size={14} /> Mascot_Generation_DNA
        </h4>
        <p className="text-[10px] text-xmr-dim font-black leading-relaxed italic">
          "A cute yet edgy cyber-security mascot for the 'Ripley' XMR Gateway. The mascot is a small, robotic, high-tech cat with sleek metallic black fur and glowing XMR-green eyes. It wears a miniature tactical vest with a Monero 'M' patch. The tail is a thick bundle of numerous glowing fiber-optic cables that separate at the tip. Tech-noir hacker aesthetic."
        </p>
      </Card>

    </div>
  );
}
