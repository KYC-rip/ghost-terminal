import { useState } from 'react';
import { Droplets, Loader2, Check } from 'lucide-react';
import { getApiBase } from '../../services/client';

/**
 * Stressnet-only: claim 0.5 tXMR from the kyc.rip faucet so users can try
 * the FCMP++ wallet flow without mining. Shown when the balance is zero.
 */
const ERROR_COPY: Record<string, string> = {
  RATE_LIMITED: 'RATE_LIMITED — this address or IP already claimed',
  EXHAUSTED: 'EXHAUSTED — faucet is empty, ping the operator',
  INVALID_ADDRESS: 'INVALID_ADDRESS — stressnet address rejected',
  DISABLED: 'DISABLED — faucet is switched off',
  UPSTREAM_DOWN: 'UPSTREAM_DOWN — faucet node unreachable, retry later',
};

export function FaucetCard({ address }: { address: string }) {
  const [busy, setBusy] = useState(false);
  const [txid, setTxid] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const claim = async () => {
    if (busy || !address) return;
    setBusy(true);
    setError(null);
    try {
      const base = getApiBase().replace(/\/$/, '');
      // 15s ceiling so a hung Worker never leaves an infinite spinner
      const res = await fetch(`${base}/v1/faucet/stressnet/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address }),
        signal: AbortSignal.timeout(15_000),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.txid) {
        setTxid(data.txid);
      } else {
        setError(ERROR_COPY[data.error] || data.error || `HTTP_${res.status}`);
      }
    } catch (e: any) {
      setError(`NETWORK_ERROR — ${e.message}`);
    } finally {
      setBusy(false);
    }
  };

  if (txid) {
    return (
      <div className="border border-xmr-green/40 bg-xmr-green/5 rounded-sm p-3 flex items-center gap-3 animate-in fade-in">
        <Check size={16} className="text-xmr-green shrink-0" />
        <div className="min-w-0">
          <div className="text-[10px] font-black uppercase text-xmr-green">0.5 tXMR dispatched — it will appear after confirmation</div>
          <div className="text-[9px] font-mono text-xmr-dim truncate">TX: {txid}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="border border-xmr-warning/40 bg-xmr-warning/5 rounded-sm p-3 space-y-2 animate-in fade-in">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Droplets size={16} className="text-xmr-warning shrink-0" />
          <div className="text-[10px] font-black uppercase text-xmr-warning">
            Empty stressnet wallet — grab test coins from the faucet
          </div>
        </div>
        <button
          onClick={claim}
          disabled={busy || !address}
          className="px-4 py-1.5 border border-xmr-warning/60 text-xmr-warning rounded-sm text-[10px] font-black uppercase tracking-widest hover:bg-xmr-warning/10 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shrink-0"
        >
          {busy ? <Loader2 size={12} className="animate-spin" /> : <Droplets size={12} />}
          CLAIM 0.5 tXMR
        </button>
      </div>
      {error && <div className="text-[10px] font-mono uppercase text-xmr-error">{error}</div>}
    </div>
  );
}
