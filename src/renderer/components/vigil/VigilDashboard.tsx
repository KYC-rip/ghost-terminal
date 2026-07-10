/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect, useRef } from 'react';
import { Radio, XCircle, Shield, ArrowDown, Copy, Check } from 'lucide-react';
import { HeartbeatChart } from './HeartbeatChart';
// Lightweight toast-like notification (avoids react-hot-toast dependency)
const notify = (msg: string) => console.log(`[Vigil] ${msg}`);

// ─── Types ───

interface LogLine {
  id: number;
  time: string;
  text: string;
  type: string;
}

interface Props {
  config: any;
  mode: 'SNIPE' | 'EJECT';
  onCancel: () => void;
  state: string;
  realPrice?: number | null;
  priceConnected?: boolean;
  externalLogs?: LogLine[];
  priceHistory?: { time: number; value: number }[];
}

// ─── Main Component ───

export function VigilDashboard({
  config,
  mode,
  onCancel,
  state,
  realPrice,
  priceConnected = true,
  externalLogs = [],
  priceHistory = [],
}: Props) {
  const isTriggered = state === 'TRIGGERED' || state === 'EXECUTING';
  const displayPrice = realPrice ?? parseFloat(config.triggerPrice) ?? 0;
  const hasStop = !!config.stopPrice && parseFloat(config.stopPrice) > 0;
  const triggerVal = parseFloat(config.triggerPrice) || 0;
  const stopVal = parseFloat(config.stopPrice) || 0;

  const logEndRef = useRef<HTMLDivElement>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // ─── Price animation ───
  const [prevPrice, setPrevPrice] = useState(displayPrice);
  const [priceFlash, setPriceFlash] = useState<'up' | 'down' | null>(null);

  useEffect(() => {
    if (displayPrice !== prevPrice) {
      setPriceFlash(displayPrice > prevPrice ? 'up' : 'down');
      setPrevPrice(displayPrice);
      const t = setTimeout(() => setPriceFlash(null), 600);
      return () => clearTimeout(t);
    }
  }, [displayPrice, prevPrice]);

  // Auto-scroll logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [externalLogs.length]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    notify(`${label} copied`);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // ─── Price comparison helpers ───
  const getPriceComparison = () => {
    if (!triggerVal || !displayPrice) return null;
    const diff = ((displayPrice - triggerVal) / triggerVal) * 100;
    const isClose = Math.abs(diff) < 2;
    return { diff, isClose };
  };

  const comparison = getPriceComparison();

  const logTypeColor = (type: string) => {
    switch (type) {
      case 'error': return 'text-xmr-error';
      case 'success': return 'text-xmr-green';
      case 'warn': return 'text-xmr-warning';
      case 'trigger': return 'text-xmr-error font-bold';
      default: return 'text-xmr-dim';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-4 animate-in fade-in duration-300">

      {/* ─── Price Display ─── */}
      <div className="relative bg-xmr-base/50 border border-xmr-border/30 rounded-sm p-6 overflow-hidden">
        {/* Background glow when triggered */}
        {isTriggered && (
          <div className="absolute inset-0 bg-xmr-error/5 animate-pulse" />
        )}

        {/* Live heartbeat chart as the card's background layer (web parity) */}
        <div className="absolute inset-0 top-16 z-0">
          <HeartbeatChart
            triggerPrice={triggerVal}
            stopPrice={hasStop ? parseFloat(config.stopPrice) : undefined}
            mode={mode}
            isTriggered={isTriggered}
            realPrice={realPrice}
            priceHistory={priceHistory}
          />
        </div>

        <div className="relative z-10">
          {/* Top bar */}
          <div className="flex justify-between items-start mb-6">
            <div>
              <div className="text-[10px] text-xmr-dim font-mono uppercase tracking-wider mb-1">
                XMR / USD Market Price
              </div>
              <div className={`text-5xl font-black tracking-tighter tabular-nums transition-colors duration-300 drop-shadow-lg font-mono
                ${isTriggered ? 'text-xmr-error animate-pulse' : ''}
                ${priceFlash === 'up' ? 'text-xmr-green' : ''}
                ${priceFlash === 'down' ? 'text-xmr-error' : ''}
                ${!isTriggered && !priceFlash ? 'text-current' : ''}
              `}>
                ${displayPrice.toFixed(2)}
              </div>
              {comparison && (
                <div className={`text-[10px] font-mono mt-1 ${comparison.isClose ? 'text-xmr-warning animate-pulse' : 'text-xmr-dim'}`}>
                  {comparison.diff > 0 ? '+' : ''}{comparison.diff.toFixed(2)}% FROM TARGET
                  {comparison.isClose && ' -- APPROACHING'}
                </div>
              )}
            </div>

            <div className="flex flex-col items-end gap-2">
              <div className={`flex items-center gap-2 text-[10px] font-mono px-2 py-1 rounded-sm border backdrop-blur-sm
                ${priceConnected
                  ? 'text-xmr-green border-xmr-green/20 bg-xmr-green/5'
                  : 'text-xmr-error border-xmr-error/20 bg-xmr-error/5 animate-pulse'
                }
              `}>
                <Radio size={12} className={priceConnected ? 'animate-pulse' : ''} />
                {priceConnected ? 'LIVE FEED' : 'CONNECTING...'}
              </div>

              <div className={`text-[9px] font-mono uppercase tracking-widest px-2 py-1 rounded-sm border
                ${isTriggered
                  ? 'text-xmr-error border-xmr-error/30 bg-xmr-error/10 animate-pulse'
                  : 'text-xmr-ghost border-xmr-ghost/20 bg-xmr-ghost/5'
                }
              `}>
                {state}
              </div>
            </div>
          </div>

          {/* ─── Target Lines ─── */}
          <div className="grid grid-cols-2 gap-4 mt-24">
            {/* Main Target */}
            <div className="p-3 rounded-sm border border-xmr-green/20 bg-xmr-surface/35 backdrop-blur-[2px] space-y-1">
              <div className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-xmr-green" />
                {mode === 'SNIPE' ? 'BUY DIP TARGET' : 'TAKE PROFIT TARGET'}
              </div>
              <div className="text-xl font-black font-mono text-xmr-green flex items-center gap-1.5">
                <ArrowDown size={14} className={mode === 'SNIPE' ? '' : 'rotate-180'} />
                ${triggerVal.toFixed(2)}
              </div>
            </div>

            {/* Stop / Strategy */}
            <div className={`p-3 rounded-sm border space-y-1 bg-xmr-surface/35 backdrop-blur-[2px]
              ${hasStop ? 'border-xmr-error/20' : 'border-xmr-border/20'}
            `}>
              {hasStop ? (
                <>
                  <div className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest flex items-center gap-1.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-xmr-error" />
                    {mode === 'SNIPE' ? 'BREAKOUT STOP' : 'STOP LOSS'}
                  </div>
                  <div className="text-xl font-black font-mono text-xmr-error flex items-center gap-1.5">
                    <Shield size={14} />
                    ${stopVal.toFixed(2)}
                  </div>
                </>
              ) : (
                <>
                  <div className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest">STRATEGY</div>
                  <div className="text-sm font-black font-mono text-xmr-dim uppercase">
                    {mode === 'SNIPE' ? 'BUY DIP (SINGLE)' : 'TAKE PROFIT (SINGLE)'}
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* ─── Mission Parameters ─── */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-xmr-surface/50 border border-xmr-border/20 rounded-sm p-3 space-y-1">
          <div className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest">Amount</div>
          <div className="text-sm font-black font-mono text-xmr-green">
            {config.amount} {config.inputCurrency?.ticker?.toUpperCase() || 'XMR'}
          </div>
        </div>

        <div className="bg-xmr-surface/50 border border-xmr-border/20 rounded-sm p-3 space-y-1">
          <div className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest">Output</div>
          <div className="text-sm font-black font-mono text-xmr-green">
            {config.outputCurrency?.ticker?.toUpperCase() || 'USDT'}
          </div>
        </div>

        <div className="bg-xmr-surface/50 border border-xmr-border/20 rounded-sm p-3 space-y-1 overflow-hidden">
          <div className="flex justify-between items-center">
            <div className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest">Destination</div>
            {config.targetAddress && (
              <button
                onClick={() => copyToClipboard(config.targetAddress, 'Address')}
                className="text-xmr-dim hover:text-xmr-green transition-colors"
              >
                {copiedField === 'Address' ? <Check size={10} /> : <Copy size={10} />}
              </button>
            )}
          </div>
          <div className="text-[10px] font-mono text-xmr-dim/70 truncate" title={config.targetAddress}>
            {config.targetAddress
              ? `${config.targetAddress.slice(0, 8)}...${config.targetAddress.slice(-6)}`
              : 'Local Wallet'
            }
          </div>
        </div>
      </div>

      {/* ─── Log Output ─── */}
      <div className="bg-xmr-base border border-xmr-border/20 rounded-sm overflow-hidden">
        <div className="flex items-center justify-between px-3 py-2 border-b border-xmr-border/20 bg-xmr-surface/30">
          <div className="flex items-center gap-2">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-xmr-green opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-xmr-green" />
            </span>
            <span className="text-[9px] font-mono text-xmr-dim uppercase tracking-widest">VIGIL_LOG</span>
          </div>
          <span className="text-[9px] font-mono text-xmr-dim">{externalLogs.length} entries</span>
        </div>

        <div className="max-h-[180px] overflow-y-auto p-3 space-y-0.5 font-mono text-[10px] custom-scrollbar">
          {externalLogs.length === 0 ? (
            <div className="text-xmr-dim/30 text-center py-4 uppercase">Waiting for events...</div>
          ) : (
            externalLogs.map((log) => (
              <div key={log.id} className={`flex gap-2 ${logTypeColor(log.type)}`}>
                <span className="text-xmr-dim/40 shrink-0">{log.time}</span>
                <span className="break-all">{log.text}</span>
              </div>
            ))
          )}
          <div ref={logEndRef} />
        </div>
      </div>

      {/* ─── Abort Button ─── */}
      <button
        onClick={onCancel}
        className="w-full py-3 bg-xmr-error/5 hover:bg-xmr-error/10 border border-xmr-error/20 hover:border-xmr-error/40 text-xmr-error text-[10px] font-bold uppercase tracking-[0.2em] flex items-center justify-center gap-2 transition-all rounded-sm group hover:shadow-[0_0_15px_rgba(248,113,113,0.2)]"
      >
        <XCircle size={14} className="group-hover:rotate-90 transition-transform" />
        ABORT MISSION
      </button>
    </div>
  );
}
