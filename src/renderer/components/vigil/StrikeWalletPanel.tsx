import { useState, useEffect } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { Zap, Lock, Loader2, RefreshCw, Eye, EyeOff, Copy, Check, AlertTriangle, Send } from 'lucide-react';
import { AddressDisplay } from '../common/AddressDisplay';
import type { StrikeBalances, GasCheck } from '../../services/strikeWallet';

interface Props {
  unlocked: boolean;
  address: string;
  balances: StrikeBalances | null;
  gas: GasCheck | null;
  created: boolean;
  requiredAmount: string;
  requiredTicker: string;
  onUnlock: (vaultPassword: string) => Promise<unknown>;
  onExportKey: (vaultPassword: string) => Promise<string>;
  onRefresh: () => Promise<void>;
  onRefund: (toAddress: string, ticker?: string) => Promise<string>;
  onRegenerate: (vaultPassword: string) => Promise<unknown>;
}

/**
 * SNIPE funding panel: a dedicated EVM burner wallet the user pre-funds
 * before arming. The engine auto-sends from it when the trigger fires.
 */
export function StrikeWalletPanel({
  unlocked, address, balances, gas, created,
  requiredAmount, requiredTicker,
  onUnlock, onExportKey, onRefresh, onRefund, onRegenerate,
}: Props) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revealedKey, setRevealedKey] = useState<string | null>(null);
  const [showExport, setShowExport] = useState(false);
  const [showSweep, setShowSweep] = useState(false);
  const [sweepAddr, setSweepAddr] = useState('');
  const [sweepBusy, setSweepBusy] = useState(false);
  const [sweepResult, setSweepResult] = useState<string | null>(null);
  const [sweepError, setSweepError] = useState<string | null>(null);
  const [showRotate, setShowRotate] = useState(false);
  const [rotateBusy, setRotateBusy] = useState(false);
  const [rotateError, setRotateError] = useState('');
  const [copied, setCopied] = useState(false);

  // Surface the backup prompt automatically right after key generation
  useEffect(() => { if (created) setShowExport(true); }, [created]);

  // Auto-refresh balances while the panel is visible so incoming pre-funding
  // shows up without manual refreshes
  useEffect(() => {
    if (!unlocked) return;
    const interval = setInterval(() => { onRefresh().catch(() => { }); }, 30_000);
    return () => clearInterval(interval);
  }, [unlocked, onRefresh]);

  const handleUnlock = async () => {
    if (!password || busy) return;
    setBusy(true);
    setError('');
    try {
      await onUnlock(password);
      setPassword('');
    } catch (e: any) {
      setError(e.message || 'Unlock failed');
    } finally {
      setBusy(false);
    }
  };

  const handleExport = async () => {
    if (!password || busy) return;
    setBusy(true);
    setError('');
    try {
      setRevealedKey(await onExportKey(password));
      setPassword('');
    } catch (e: any) {
      setError(e.message || 'Export failed');
    } finally {
      setBusy(false);
    }
  };

  const handleSweep = async () => {
    if (sweepBusy || !/^0x[0-9a-fA-F]{40}$/.test(sweepAddr)) return;
    setSweepBusy(true);
    setSweepError(null);
    try {
      setSweepResult(await onRefund(sweepAddr, requiredTicker));
      setSweepAddr('');
    } catch (e: any) {
      setSweepError(e.message || 'Sweep failed');
    } finally {
      setSweepBusy(false);
    }
  };

  const handleRotate = async () => {
    if (!password || rotateBusy) return;
    setRotateBusy(true);
    setRotateError('');
    try {
      // Close the rotate panel immediately on success so the auto-opened
      // backup prompt (fresh key) is the only thing showing — the trailing
      // balance refresh inside onRegenerate must not keep this spinning.
      await onRegenerate(password);
      setPassword('');
      setShowRotate(false);
    } catch (e) {
      setRotateError((e as Error).message || 'Rotation failed');
    } finally {
      setRotateBusy(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const tokenBalance = balances?.tokens?.[requiredTicker];
  const funded = tokenBalance !== undefined && parseFloat(tokenBalance) >= parseFloat(requiredAmount || '0') && parseFloat(requiredAmount || '0') > 0;

  return (
    <div className="bg-xmr-base/30 border border-xmr-accent/30 rounded-sm p-3 space-y-3 animate-in fade-in">
      <div className="flex justify-between items-center border-b border-xmr-border/30 pb-1.5">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded-sm bg-xmr-accent/10 text-xmr-accent"><Zap size={12} /></div>
          <span className="text-[10px] text-xmr-dim font-mono uppercase tracking-widest">Strike_Wallet (EVM Burner)</span>
        </div>
        {unlocked && (
          <button onClick={() => onRefresh()} className="text-xmr-dim hover:text-xmr-accent transition-colors" title="Refresh balances">
            <RefreshCw size={12} />
          </button>
        )}
      </div>

      {!unlocked ? (
        <div className="space-y-2">
          <p className="text-[10px] text-xmr-dim leading-relaxed">
            SNIPE orders are funded from a dedicated burner wallet so the trigger can fire unattended.
            Enter your vault password to load (or generate) this identity's strike key.
          </p>
          <div className="flex gap-2">
            <input
              type="password"
              value={password}
              placeholder="Vault password"
              onChange={(e) => { setPassword(e.target.value); setError(''); }}
              onKeyDown={(e) => e.key === 'Enter' && handleUnlock()}
              className="flex-1 bg-xmr-base border border-xmr-border rounded-sm py-2 px-3 text-xs font-mono text-current focus:outline-none focus:border-xmr-accent transition-colors"
            />
            <button
              onClick={handleUnlock}
              disabled={!password || busy}
              className="px-4 py-2 border border-xmr-accent/50 text-xmr-accent rounded-sm text-[10px] font-black uppercase tracking-widest hover:bg-xmr-accent/10 disabled:opacity-30 disabled:cursor-not-allowed transition-all flex items-center gap-1.5"
            >
              {busy ? <Loader2 size={12} className="animate-spin" /> : <Lock size={12} />}
              Unlock
            </button>
          </div>
          {error && <div className="text-[10px] text-xmr-error font-mono uppercase">{error}</div>}
        </div>
      ) : (
        <div className="space-y-3">
          {/* Address + QR for pre-funding */}
          <div className="flex gap-3 items-start">
            <div className="bg-white p-1.5 rounded-sm shrink-0">
              <QRCodeSVG value={address} size={72} />
            </div>
            <div className="flex-1 min-w-0 space-y-2">
              <div>
                <div className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest mb-1">Fund this address before arming</div>
                <div className="flex items-center gap-2">
                  <AddressDisplay address={address} className="text-[10px] text-xmr-accent font-bold" />
                  <button onClick={() => handleCopy(address)} className="text-xmr-dim hover:text-xmr-accent shrink-0 transition-colors">
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                  </button>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                <div className="bg-black/30 rounded-sm px-2 py-1.5 border border-xmr-border/30">
                  <span className="text-xmr-dim block text-[9px] uppercase">{requiredTicker || 'Token'}</span>
                  <span className={funded ? 'text-xmr-green font-bold' : 'text-current'}>{tokenBalance ?? '—'}</span>
                </div>
                <div className="bg-black/30 rounded-sm px-2 py-1.5 border border-xmr-border/30">
                  <span className="text-xmr-dim block text-[9px] uppercase">ETH (gas)</span>
                  <span className={gas?.ok ? 'text-xmr-green font-bold' : 'text-current'}>{balances?.eth ?? '—'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Funding / gas warnings */}
          {requiredAmount && !funded && (
            <div className="flex items-center gap-2 text-[10px] text-xmr-warning font-mono uppercase">
              <AlertTriangle size={12} className="shrink-0" />
              Needs {requiredAmount} {requiredTicker} before arming
            </div>
          )}
          {gas && !gas.ok && (
            <div className="flex items-center gap-2 text-[10px] text-xmr-warning font-mono uppercase">
              <AlertTriangle size={12} className="shrink-0" />
              Short ~{gas.missingEth} ETH for gas
            </div>
          )}

          {/* Key backup / export */}
          {showExport && !revealedKey && (
            <div className="border border-xmr-warning/30 bg-xmr-warning/5 rounded-sm p-2 space-y-2">
              <p className="text-[10px] text-xmr-warning leading-relaxed font-mono uppercase">
                {created ? 'New key generated — back it up now.' : 'Reveal strike key'}
              </p>
              <p className="text-[9px] text-xmr-dim leading-relaxed">
                The key is recoverable only with your vault password. Export it if this wallet will hold meaningful funds.
              </p>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={password}
                  placeholder="Vault password"
                  onChange={(e) => { setPassword(e.target.value); setError(''); }}
                  onKeyDown={(e) => e.key === 'Enter' && handleExport()}
                  className="flex-1 bg-xmr-base border border-xmr-border rounded-sm py-1.5 px-2 text-[10px] font-mono focus:outline-none focus:border-xmr-warning"
                />
                <button onClick={handleExport} disabled={!password || busy}
                  className="px-3 py-1.5 border border-xmr-warning/50 text-xmr-warning rounded-sm text-[9px] font-black uppercase hover:bg-xmr-warning/10 disabled:opacity-30 transition-all">
                  {busy ? <Loader2 size={10} className="animate-spin" /> : 'Reveal'}
                </button>
                {!created && (
                  <button onClick={() => setShowExport(false)} className="px-2 text-xmr-dim text-[9px] uppercase hover:text-current">Close</button>
                )}
              </div>
              {error && <div className="text-[10px] text-xmr-error font-mono uppercase">{error}</div>}
            </div>
          )}
          {revealedKey && (
            <div className="border border-xmr-error/30 bg-xmr-error/5 rounded-sm p-2 space-y-1.5">
              <div className="text-[9px] text-xmr-error font-mono uppercase font-black">Private key — anyone with this controls the funds</div>
              <div className="flex items-center gap-2">
                <code className="text-[9px] text-current break-all flex-1">{revealedKey}</code>
                <button onClick={() => handleCopy(revealedKey)} className="text-xmr-dim hover:text-xmr-error shrink-0">
                  {copied ? <Check size={12} /> : <Copy size={12} />}
                </button>
              </div>
              <button onClick={() => { setRevealedKey(null); setShowExport(false); }}
                className="text-[9px] text-xmr-dim uppercase hover:text-current flex items-center gap-1">
                <EyeOff size={10} /> Hide
              </button>
            </div>
          )}
          {!showExport && !revealedKey && (
            <div className="flex items-center gap-4">
              <button onClick={() => setShowExport(true)}
                className="text-[9px] text-xmr-dim uppercase tracking-wider hover:text-xmr-accent transition-colors flex items-center gap-1">
                <Eye size={10} /> Export / back up key
              </button>
              <button onClick={() => { setShowSweep(!showSweep); setSweepResult(null); setSweepError(null); }}
                className="text-[9px] text-xmr-dim uppercase tracking-wider hover:text-xmr-accent transition-colors flex items-center gap-1">
                <Send size={10} /> Sweep leftovers
              </button>
              <button onClick={() => { setShowRotate(!showRotate); setRotateError(''); }}
                className="text-[9px] text-xmr-dim uppercase tracking-wider hover:text-xmr-accent transition-colors flex items-center gap-1">
                <RefreshCw size={10} /> New burner
              </button>
            </div>
          )}

          {/* Burner rotation: fresh address for forward privacy. The engine
              refuses while funds remain (sweep first) or a vigil is armed. */}
          {showRotate && (
            <div className="border border-xmr-ghost/30 bg-xmr-ghost/5 rounded-sm p-2 space-y-2">
              <p className="text-[9px] text-xmr-dim leading-relaxed uppercase font-mono">
                Retires the current address (old key stays recoverable) and mints a fresh one.
                Requires an empty burner — sweep leftovers first. Fund each burner from varied sources for best effect.
              </p>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={password}
                  placeholder="Vault password"
                  onChange={(e) => { setPassword(e.target.value); setRotateError(''); }}
                  onKeyDown={(e) => e.key === 'Enter' && handleRotate()}
                  className="flex-1 bg-xmr-base border border-xmr-border rounded-sm py-1.5 px-2 text-[10px] font-mono focus:outline-none focus:border-xmr-ghost"
                />
                <button onClick={handleRotate} disabled={!password || rotateBusy}
                  className="px-3 py-1.5 border border-xmr-ghost/50 text-xmr-ghost rounded-sm text-[9px] font-black uppercase hover:bg-xmr-ghost/10 disabled:opacity-30 transition-all">
                  {rotateBusy ? <Loader2 size={10} className="animate-spin" /> : 'Rotate'}
                </button>
                <button onClick={() => setShowRotate(false)} className="px-2 text-xmr-dim text-[9px] uppercase hover:text-current">Close</button>
              </div>
              {rotateError && <div className="text-[10px] text-xmr-error font-mono uppercase">{rotateError}</div>}
            </div>
          )}

          {/* Sweep leftovers: token balance + remaining ETH minus gas */}
          {showSweep && !sweepResult && (
            <div className="border border-xmr-border/40 bg-black/20 rounded-sm p-2 space-y-2">
              <p className="text-[9px] text-xmr-dim leading-relaxed uppercase font-mono">
                Sweeps {requiredTicker || 'token'} + remaining ETH (minus gas) to an address you control
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={sweepAddr}
                  placeholder="0x… destination"
                  onChange={(e) => { setSweepAddr(e.target.value.trim()); setSweepError(null); }}
                  onKeyDown={(e) => e.key === 'Enter' && handleSweep()}
                  className="flex-1 bg-xmr-base border border-xmr-border rounded-sm py-1.5 px-2 text-[10px] font-mono focus:outline-none focus:border-xmr-accent"
                />
                <button onClick={handleSweep} disabled={sweepBusy || !/^0x[0-9a-fA-F]{40}$/.test(sweepAddr)}
                  className="px-3 py-1.5 border border-xmr-accent/50 text-xmr-accent rounded-sm text-[9px] font-black uppercase hover:bg-xmr-accent/10 disabled:opacity-30 disabled:cursor-not-allowed transition-all">
                  {sweepBusy ? <Loader2 size={10} className="animate-spin" /> : 'Sweep'}
                </button>
                <button onClick={() => setShowSweep(false)} className="px-2 text-xmr-dim text-[9px] uppercase hover:text-current">Close</button>
              </div>
              {sweepError && <div className="text-[10px] text-xmr-error font-mono uppercase">{sweepError}</div>}
            </div>
          )}
          {sweepResult && (
            <div className="border border-xmr-green/30 bg-xmr-green/5 rounded-sm p-2 space-y-1">
              <div className="text-[9px] text-xmr-green font-mono uppercase font-black">Leftovers swept</div>
              <div className="text-[9px] font-mono text-xmr-dim break-all">TX: {sweepResult}</div>
              <button onClick={() => { setSweepResult(null); setShowSweep(false); }}
                className="text-[9px] text-xmr-dim uppercase hover:text-current">Done</button>
            </div>
          )}

          <div className="text-[8px] text-xmr-dim/60 uppercase tracking-wider">
            EVM RPC follows the app network mode — Tor-routed when Tor is enabled
          </div>
        </div>
      )}
    </div>
  );
}
