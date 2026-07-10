/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect } from 'react';
import { Shield, Radio, Loader2, CheckCircle2, Copy, Check, AlertTriangle, History, WifiOff, RotateCcw } from 'lucide-react';
import { VigilConfig, type VigilConfigData } from './vigil/VigilConfig';
import { VigilDashboard } from './vigil/VigilDashboard';
import { StrikeWalletPanel } from './vigil/StrikeWalletPanel';
import { Card } from './Card';
import { CurrencySelector } from './CurrencySelector';
import { useVigil } from '../contexts/VigilContext';
import { useVault } from '../hooks/useVault';
import { getOrCreateSubaddress } from '../services/subaddressService';
// Lightweight notification (avoids react-hot-toast dependency)
const notify = (msg: string) => console.log(`[Vigil] ${msg}`);

// ─── Types ───

type VigilState = 'IDLE' | 'WATCHING' | 'TRIGGERED' | 'EXECUTING' | 'POLLING' | 'COMPLETED' | 'ERROR';

interface VigilViewProps {
  localXmrAddress: string;
}

// ─── Main Component ───

export function VigilView({ localXmrAddress }: VigilViewProps) {
  const {
    state,
    logs,
    executionStatus,
    progress,
    arm,
    abort,
    retry,
    price,
    reset,
    wsConnected,
    wsDegraded,
    priceHistory,
    reconnectFeed,
    activeSession,
    completedTrade,
    pendingSession,
    rearmPendingSession,
    discardPendingSession,
    strikeAddress,
    strikeBalances,
    strikeGas,
    strikeCreated,
    strikeUnlocked,
    unlockStrike,
    exportStrikeKey,
    refreshStrike,
    refundStrike,
    regenerateStrike,
  } = useVigil();
  const { createSubaddress, subaddresses } = useVault();

  const [mode, setMode] = useState<'SNIPE' | 'EJECT'>('EJECT'); // Default EJECT for wallet app
  const [localConfig, setLocalConfig] = useState<VigilConfigData>({
    inputCurrency: CurrencySelector.Monero,
    outputCurrency: null,
    triggerPrice: '',
    stopPrice: '',
    targetAddress: '',
    amount: '',
    memo: '',
    compliance: { kyc: 'ANY', log: 'ANY' },
  });
  const [copyFeedback, setCopyFeedback] = useState(false);
  const [rearmError, setRearmError] = useState('');

  const isDanger = state === 'TRIGGERED' || state === 'EXECUTING';
  const vigilState = (state as VigilState) || 'IDLE';

  // ─── Auto-fill based on mode ───
  useEffect(() => {
    if (mode === 'EJECT') {
      // EJECT: input is XMR from vault, output address is user-provided stablecoin addr
      setLocalConfig((prev) => ({
        ...prev,
        inputCurrency: CurrencySelector.Monero,
      }));
    } else {
      // SNIPE: output goes to a reusable vault subaddress
      (async () => {
        try {
          const addr = await getOrCreateSubaddress('Vigil', subaddresses, createSubaddress);
          setLocalConfig((prev) => ({
            ...prev,
            targetAddress: addr || localXmrAddress,
          }));
        } catch {
          setLocalConfig((prev) => ({
            ...prev,
            targetAddress: localXmrAddress,
          }));
        }
      })();
    }
  }, [mode, localXmrAddress, createSubaddress, subaddresses]);

  // Restore config from active session if resuming
  useEffect(() => {
    if (activeSession?.config) {
      setMode(activeSession.mode || 'EJECT');
      setLocalConfig((prev) => ({
        ...prev,
        triggerPrice: activeSession.config.triggerPrice || prev.triggerPrice,
        stopPrice: activeSession.config.stopPrice || '',
        amount: activeSession.config.amount || prev.amount,
        targetAddress: activeSession.config.targetAddress || prev.targetAddress,
        inputCurrency: activeSession.config.inputCurrency || prev.inputCurrency,
        outputCurrency: activeSession.config.outputCurrency || prev.outputCurrency,
      }));
    }
  }, [activeSession]);

  // ─── Handlers ───

  const handleArm = () => {
    arm(mode, localConfig);
  };

  const handleAbort = () => {
    if (confirm('ABORT VIGIL?\n\nThis will cancel the active monitoring session.')) {
      abort();
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopyFeedback(true);
    notify('Copied to clipboard');
    setTimeout(() => setCopyFeedback(false), 2000);
  };

  const handleReset = () => {
    reset();
    setLocalConfig((prev) => ({ ...prev, triggerPrice: '' }));
  };

  const handleRearm = async () => {
    setRearmError('');
    try {
      await rearmPendingSession();
    } catch (e: any) {
      setRearmError(e.message || 'Re-arm failed');
    }
  };

  // SNIPE arming requires a funded, unlocked strike wallet
  const inputTicker = localConfig.inputCurrency?.ticker?.toUpperCase() || 'USDT';
  const strikeTokenBalance = strikeBalances?.tokens?.[inputTicker];
  const strikeFunded = strikeTokenBalance !== undefined
    && parseFloat(localConfig.amount || '0') > 0
    && parseFloat(strikeTokenBalance) >= parseFloat(localConfig.amount || '0');
  const snipeBlocked = mode === 'SNIPE' && (!strikeUnlocked || !strikeFunded || !(strikeGas?.ok));

  // ─── Progress bar width ───
  const progressWidth = (() => {
    switch (vigilState) {
      case 'IDLE': return 'w-1/5';
      case 'WATCHING': return 'w-2/5';
      case 'TRIGGERED': return 'w-3/5';
      case 'EXECUTING': return 'w-4/5';
      case 'POLLING': return 'w-[90%]';
      case 'COMPLETED': return 'w-full';
      case 'ERROR': return 'w-full';
      default: return 'w-0';
    }
  })();

  return (
    <div className={`
      border rounded-sm overflow-hidden backdrop-blur-md flex flex-col relative shadow-xl transition-all duration-500
      ${isDanger
        ? 'bg-xmr-error/20 border-xmr-error/50 shadow-[0_0_50px_rgba(239,68,68,0.3)]'
        : 'bg-xmr-surface border-xmr-border'
      }
    `}>

      {/* ─── Progress Bar ─── */}
      <div className="h-0.5 w-full bg-xmr-ghost/10">
        <div className={`h-full transition-all duration-1000 ease-in-out
          ${isDanger ? 'bg-xmr-error animate-pulse' : 'bg-xmr-ghost shadow-[0_0_10px_var(--color-xmr-ghost)]'}
          ${progressWidth}
        `} />
      </div>

      {/* ─── Header ─── */}
      <div className={`px-4 py-2.5 border-b flex justify-between items-center transition-colors
        ${isDanger ? 'bg-xmr-error/10 border-xmr-error/30' : 'bg-xmr-base/30 border-xmr-border'}
      `}>
        <div className="flex items-center gap-2">
          <div className={`p-1.5 rounded-sm border transition-colors
            ${isDanger
              ? 'bg-xmr-error/20 border-xmr-error text-xmr-error'
              : 'bg-xmr-ghost/10 border-xmr-ghost/20 text-xmr-ghost'
            }
          `}>
            <Shield size={16} />
          </div>
          <div>
            <h2 className="text-sm font-bold text-current tracking-widest font-mono">VIGIL_</h2>
            <div className="text-[9px] text-xmr-dim uppercase tracking-[0.2em]">
              {isDanger ? 'EXECUTION IN PROGRESS' : 'Limit Order Protocol'}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {vigilState !== 'IDLE' && (
            <Radio size={12} className={`${isDanger ? 'text-xmr-error animate-ping' : 'text-xmr-green animate-pulse'}`} />
          )}
          <span className="text-[10px] font-mono text-xmr-dim">
            STATUS: <span className={`font-bold ${isDanger ? 'text-xmr-error' : 'text-current'}`}>{vigilState}</span>
          </span>
          {wsConnected !== undefined && (
            <div className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-xmr-green' : 'bg-xmr-error'}`}
              title={wsConnected ? 'WebSocket Connected' : 'WebSocket Disconnected'}
            />
          )}
        </div>
      </div>

      {/* ─── Degraded feed banner ─── */}
      {wsDegraded && vigilState === 'WATCHING' && (
        <div className="px-4 py-2 bg-xmr-warning/10 border-b border-xmr-warning/30 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[10px] font-mono uppercase text-xmr-warning">
            <WifiOff size={12} />
            STALE FEED — price stream lost, triggers will not fire
          </div>
          <button
            onClick={reconnectFeed}
            className="px-3 py-1 border border-xmr-warning/50 text-xmr-warning text-[9px] font-black uppercase tracking-widest hover:bg-xmr-warning/10 transition-all"
          >
            Reconnect
          </button>
        </div>
      )}

      {/* ─── Main Body ─── */}
      <div className="flex-1 w-full px-2 py-2 mx-auto transition-all duration-500 ease-in-out max-w-4xl">

        {/* IDLE: Configuration */}
        {vigilState === 'IDLE' && (
          <div className="flex-1 p-1 relative flex flex-col items-center w-full space-y-3">

            {/* Persisted session recovery */}
            {pendingSession && (
              <div className="w-full max-w-3xl bg-xmr-ghost/5 border border-xmr-ghost/30 rounded-sm p-3 space-y-2 animate-in fade-in">
                <div className="flex items-center gap-2 text-[10px] font-mono uppercase text-xmr-ghost">
                  <History size={12} />
                  {pendingSession.phase === 'POLLING'
                    ? `Unfinished swap found (${pendingSession.tradeId})`
                    : `Armed ${pendingSession.mode} session found from last run`}
                </div>
                <div className="text-[10px] text-xmr-dim font-mono">
                  {pendingSession.triggers.map(t => `${t.id} ${t.operator} $${t.price}`).join(' | ')}
                  {' — '}{pendingSession.config.amount} {pendingSession.config.inputCurrency?.ticker}
                </div>
                {pendingSession.mode === 'SNIPE' && pendingSession.phase !== 'POLLING' && !strikeUnlocked && (
                  <div className="text-[10px] text-xmr-warning font-mono uppercase">Unlock the strike wallet below first</div>
                )}
                {rearmError && <div className="text-[10px] text-xmr-error font-mono uppercase">{rearmError}</div>}
                <div className="flex gap-2">
                  <button onClick={handleRearm}
                    className="px-4 py-1.5 border border-xmr-ghost/50 text-xmr-ghost text-[9px] font-black uppercase tracking-widest hover:bg-xmr-ghost/10 transition-all">
                    {pendingSession.phase === 'POLLING' ? 'Resume tracking' : 'Re-arm'}
                  </button>
                  <button onClick={discardPendingSession}
                    className="px-4 py-1.5 border border-xmr-border text-xmr-dim text-[9px] font-black uppercase tracking-widest hover:text-xmr-error hover:border-xmr-error/50 transition-all">
                    Discard
                  </button>
                </div>
              </div>
            )}

            {/* SNIPE funding panel */}
            {mode === 'SNIPE' && (
              <div className="w-full max-w-3xl">
                <StrikeWalletPanel
                  unlocked={strikeUnlocked}
                  address={strikeAddress}
                  balances={strikeBalances}
                  gas={strikeGas}
                  created={strikeCreated}
                  requiredAmount={localConfig.amount}
                  requiredTicker={inputTicker}
                  onUnlock={(pwd) => unlockStrike(pwd, localConfig.inputCurrency?.network || 'ERC20')}
                  onExportKey={exportStrikeKey}
                  onRefresh={refreshStrike}
                  onRefund={refundStrike}
                  onRegenerate={(pwd) => regenerateStrike(pwd, localConfig.inputCurrency?.network || 'ERC20', localConfig.inputCurrency?.ticker)}
                />
              </div>
            )}

            <VigilConfig
              mode={mode}
              setMode={setMode}
              data={localConfig}
              setData={(data: any) => setLocalConfig((prev) => ({ ...prev, ...data }))}
              onArm={handleArm}
              currentPrice={price || 0}
              armDisabled={snipeBlocked}
              armDisabledReason={mode === 'SNIPE'
                ? (!strikeUnlocked ? 'UNLOCK STRIKE WALLET' : !strikeFunded ? 'FUND STRIKE WALLET' : !(strikeGas?.ok) ? 'STRIKE WALLET NEEDS ETH FOR GAS' : undefined)
                : undefined}
            />
          </div>
        )}

        {/* WATCHING / TRIGGERED: Dashboard */}
        {(vigilState === 'WATCHING' || vigilState === 'TRIGGERED') && (
          <div className="flex-1 px-2 py-1 relative flex flex-col items-center w-full">
            <VigilDashboard
              config={activeSession?.config || localConfig}
              mode={activeSession?.mode || mode}
              state={vigilState}
              onCancel={handleAbort}
              realPrice={price}
              priceConnected={!!price && wsConnected !== false}
              externalLogs={logs}
              priceHistory={priceHistory}
            />
          </div>
        )}

        {/* EXECUTING / POLLING: Spinner with logs */}
        {(vigilState === 'EXECUTING' || vigilState === 'POLLING') && (
          <div className="flex flex-col items-center justify-center min-h-[300px] space-y-6 animate-in fade-in">
            <Loader2 size={48} className={`animate-spin ${vigilState === 'POLLING' ? 'text-xmr-ghost' : 'text-xmr-error'}`} />
            <div className="text-xs font-mono text-current animate-pulse uppercase tracking-widest">
              {vigilState === 'POLLING' ? (executionStatus || 'TRACKING SWAP...') : 'EXECUTING TRADE...'}
            </div>
            {vigilState === 'POLLING' && (
              <div className="w-full max-w-xs h-1 bg-xmr-border/30 rounded-full overflow-hidden">
                <div className="h-full bg-xmr-ghost transition-all duration-700" style={{ width: `${progress}%` }} />
              </div>
            )}

            {/* Inline log stream */}
            <div className="w-full max-w-xl bg-xmr-base border border-xmr-border/20 rounded-sm p-3 max-h-[200px] overflow-y-auto font-mono text-[10px] space-y-0.5 custom-scrollbar">
              {logs.map((log) => (
                <div key={log.id} className={`flex gap-2 ${log.type === 'error' ? 'text-xmr-error' : log.type === 'success' ? 'text-xmr-green' : 'text-xmr-dim'}`}>
                  <span className="text-xmr-dim/40 shrink-0">{log.time}</span>
                  <span>{log.text}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* COMPLETED: Success */}
        {vigilState === 'COMPLETED' && (
          <div className="flex flex-col items-center justify-center min-h-[300px] space-y-6 animate-in fade-in zoom-in-95">

            <div className="p-4 bg-xmr-green/10 rounded-full">
              <CheckCircle2 size={48} className="text-xmr-green" />
            </div>

            <div className="text-center space-y-2">
              <h3 className="text-xl font-black uppercase tracking-widest text-xmr-green font-mono">
                VIGIL COMPLETE
              </h3>
              <p className="text-[10px] text-xmr-dim uppercase tracking-[0.2em]">
                Order executed successfully
              </p>
            </div>

            {/* Trade details */}
            {completedTrade && (
              <Card className="p-6 w-full max-w-md bg-xmr-surface border-xmr-green/20 space-y-4">
                <div className="flex justify-between text-[10px] font-mono uppercase">
                  <span className="text-xmr-dim">Trade ID</span>
                  <span className="text-xmr-green font-bold">{completedTrade.id || '---'}</span>
                </div>
                {completedTrade.amount && (
                  <div className="flex justify-between text-[10px] font-mono uppercase">
                    <span className="text-xmr-dim">Amount</span>
                    <span className="text-xmr-green">{completedTrade.amount}</span>
                  </div>
                )}
                {completedTrade.txHash && (
                  <div className="flex justify-between items-center text-[10px] font-mono uppercase">
                    <span className="text-xmr-dim">TX Hash</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xmr-green truncate max-w-[200px]">{completedTrade.txHash}</span>
                      <button
                        onClick={() => handleCopy(completedTrade.txHash!)}
                        className="text-xmr-dim hover:text-xmr-green transition-colors"
                      >
                        {copyFeedback ? <Check size={10} /> : <Copy size={10} />}
                      </button>
                    </div>
                  </div>
                )}
              </Card>
            )}

            <button
              onClick={handleReset}
              className="px-8 py-3 border border-xmr-green/50 text-xmr-green text-[10px] font-black uppercase tracking-[0.2em] hover:bg-xmr-green/10 transition-all"
            >
              NEW VIGIL
            </button>
          </div>
        )}

        {/* ERROR: Error state */}
        {vigilState === 'ERROR' && (
          <div className="flex flex-col items-center justify-center min-h-[300px] space-y-6 animate-in fade-in">
            <AlertTriangle size={48} className="text-xmr-error" />
            <div className="text-center space-y-2">
              <h3 className="text-lg font-black uppercase tracking-widest text-xmr-error font-mono">
                VIGIL ERROR
              </h3>
              <p className="text-[10px] text-xmr-dim uppercase tracking-[0.2em]">
                {executionStatus || 'An unexpected error occurred'}
              </p>
            </div>

            {/* Error logs */}
            <div className="w-full max-w-xl bg-xmr-base border border-xmr-error/20 rounded-sm p-3 max-h-[150px] overflow-y-auto font-mono text-[10px] space-y-0.5 custom-scrollbar">
              {logs.filter((l) => l.type === 'error').map((log) => (
                <div key={log.id} className="text-xmr-error">
                  <span className="text-xmr-dim/40 mr-2">{log.time}</span>
                  {log.text}
                </div>
              ))}
            </div>

            <div className="flex gap-3">
              <button
                onClick={retry}
                className="px-8 py-3 border border-xmr-warning/50 text-xmr-warning text-[10px] font-black uppercase tracking-[0.2em] hover:bg-xmr-warning/10 transition-all flex items-center gap-2"
              >
                <RotateCcw size={12} /> RETRY
              </button>
              <button
                onClick={handleReset}
                className="px-8 py-3 border border-xmr-error/50 text-xmr-error text-[10px] font-black uppercase tracking-[0.2em] hover:bg-xmr-error/10 transition-all"
              >
                RESET
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
