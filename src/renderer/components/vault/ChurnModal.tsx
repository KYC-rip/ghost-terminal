import { useState } from 'react';
import { X, Wind, Loader2 } from 'lucide-react';

interface ChurnModalProps {
  onClose: () => void;
  onChurn: () => Promise<void>;
  unlockedBalance: number;
}

export function ChurnModal({ onClose, onChurn, unlockedBalance }: ChurnModalProps) {
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setError(null);
    setIsProcessing(true);
    try {
      await onChurn();
      onClose();
    } catch (e: any) {
      setError(e.message || "Failed to churn balance.");
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="fixed top-0 bottom-0 right-0 left-[14rem] z-[100] flex items-center justify-center p-6 bg-xmr-base/90 backdrop-blur-md animate-in fade-in duration-300">
      <div className="w-full max-w-lg bg-xmr-base/80 text-xmr-dim p-8 border-2 border-xmr-green relative rounded-sm">
        <button onClick={onClose} disabled={isProcessing} className="absolute top-4 right-4 cursor-pointer disabled:opacity-50">
          <X size={24} />
        </button>

        <div className="space-y-6 font-normal">
          <div className="flex items-center gap-3 text-xmr-green font-black">
            <Wind size={32} />
            <h3 className="text-2xl font-black uppercase tracking-tighter">UTXO_Churn_Protocol</h3>
          </div>

          <div className="text-sm font-mono leading-relaxed space-y-4">
            <p>
              Churning is the defensive counter-part to Splintering. It sweeps your entire unlocked XMR
              balance into a single, newly generated subaddress.
            </p>
            <p className="opacity-80">
              Why use it? If you receive Monero from many different untrusted sources, or receive "dust attacks" with tiny outputs,
              connecting all those distinct UTXOs together in a single standard transaction could form a heuristic linkage of your identity.
              By Churning them first, you consolidate everything behind a fresh ring-signature payload. It essentially launders your local
              funds back to yourself, resetting the heuristic depth.
            </p>
          </div>

          <div className="flex items-center justify-center gap-4 text-xmr-green py-4 opacity-80">
            <div className="flex flex-col gap-2">
              <div className="w-8 h-8 rounded-full border-2 border-xmr-green bg-xmr-green/10 flex items-center justify-center"><span className="text-[10px]">10</span></div>
              <div className="w-8 h-8 rounded-full border-2 border-xmr-green bg-xmr-green/10 flex items-center justify-center"><span className="text-[10px]">10</span></div>
              <div className="w-8 h-8 rounded-full border-2 border-xmr-green bg-xmr-green/10 flex items-center justify-center"><span className="text-[10px]">10</span></div>
            </div>
            <div className="flex flex-col gap-2">
              <div className="h-0.5 w-12 bg-xmr-green/50 text-transparent">_</div>
              <div className="h-0.5 w-12 bg-xmr-green/50 text-transparent">_</div>
              <div className="h-0.5 w-12 bg-xmr-green/50 text-transparent">_</div>
            </div>
            <div className="w-16 h-16 rounded-full border-4 border-xmr-green bg-xmr-green/20 flex items-center justify-center animate-pulse shadow-[0_0_15px_var(--brand-color)]">
              <span className="font-mono font-black text-sm">30</span>
            </div>
          </div>

          {error && <div className="text-xmr-error text-xs font-mono">{error}</div>}

          <button
            onClick={handleSubmit}
            disabled={isProcessing || unlockedBalance <= 0}
            className="w-full py-4 bg-xmr-green text-xmr-dim font-black uppercase tracking-[0.2em] font-mono cursor-pointer hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {isProcessing ? (
              <><Loader2 size={18} className="animate-spin" /> Churning...</>
            ) : (
                `Consolidate UTXOs ${unlockedBalance > 0 ? `(${unlockedBalance} XMR)` : '(0 XMR)'}`
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
