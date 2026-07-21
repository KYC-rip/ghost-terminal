import { useState } from 'react';
import { X, Scissors, Loader2 } from 'lucide-react';

interface SplinterModalProps {
  onClose: () => void;
  onSplinter: (fragments: number) => Promise<void>;
  unlockedBalance: number;
}

export function SplinterModal({ onClose, onSplinter, unlockedBalance }: SplinterModalProps) {
  const [fragments, setFragments] = useState<number>(5);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (fragments < 2 || fragments > 10) {
      setError("Fragments must be between 2 and 10.");
      return;
    }
    setError(null);
    setIsProcessing(true);
    try {
      await onSplinter(fragments);
      onClose();
    } catch (e: any) {
      setError(e.message || "Failed to splinter balance.");
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="fixed top-0 bottom-0 right-0 left-[14rem] z-[100] flex items-center justify-center p-6 bg-xmr-base/90 backdrop-blur-md animate-in fade-in duration-300">
      <div className="w-full max-w-lg max-h-[90vh] bg-xmr-base/80 text-xmr-dim border-2 border-xmr-accent relative rounded-sm flex flex-col">
        <button onClick={onClose} disabled={isProcessing} className="absolute top-4 right-4 cursor-pointer disabled:opacity-50 z-10">
          <X size={24} />
        </button>

        {/* Scrollable content */}
        <div className="overflow-y-auto custom-scrollbar p-8 pb-4 space-y-6 font-normal flex-1 min-h-0">
          <div className="flex items-center gap-3 text-xmr-accent font-black">
            <Scissors size={32} />
            <h3 className="text-2xl font-black uppercase tracking-tighter">Tactical_Splinter</h3>
          </div>

          <div className="text-sm font-mono leading-relaxed space-y-4">
            <p>
              Splintering protects your privacy by algorithmically shattering your entire unlocked XMR balance
              into multiple smaller UTXOs (Unspent Transaction Outputs) across newly generated stealth addresses.
            </p>
            <p className="opacity-80">
              Why use it? If you have a massive XMR balance sitting in a single UTXO, sending even a tiny amount
              forces you to expose and spend that massive UTXO as an input, creating "toxic change" that could
              temporarily reveal your net-worth or expose your spending patterns to advanced timing analysis.
              Splintering breaks your balance down, ensuring you always spend appropriately sized chunks instead of huge payloads.
            </p>
          </div>

          <div className="flex items-center justify-center gap-4 text-xmr-accent py-4 opacity-80">
            <div className="w-16 h-16 rounded-full border-4 border-xmr-accent bg-xmr-accent/20 flex items-center justify-center animate-pulse shadow-[0_0_15px_var(--text-accent)]">
               <span className="font-mono font-black text-sm">100</span>
            </div>
            <div className="flex flex-col gap-2">
              <div className="h-0.5 w-12 bg-xmr-accent/50 text-transparent">_</div>
              <div className="h-0.5 w-12 bg-xmr-accent/50 text-transparent">_</div>
              <div className="h-0.5 w-12 bg-xmr-accent/50 text-transparent">_</div>
            </div>
            <div className="flex flex-col gap-2">
              <div className="w-8 h-8 rounded-full border-2 border-xmr-accent bg-xmr-accent/10 flex items-center justify-center"><span className="text-[10px]">33</span></div>
              <div className="w-8 h-8 rounded-full border-2 border-xmr-accent bg-xmr-accent/10 flex items-center justify-center"><span className="text-[10px]">33</span></div>
              <div className="w-8 h-8 rounded-full border-2 border-xmr-accent bg-xmr-accent/10 flex items-center justify-center"><span className="text-[10px]">34</span></div>
            </div>
          </div>

          <div className="bg-black/5 p-4 border border-xmr-border">
            <label className="block text-xs uppercase tracking-widest text-xmr-dim/60 mb-2">Number of Fragments (2-10)</label>
            <input
              type="number"
              min="2" max="10"
              value={fragments}
              onChange={(e) => setFragments(parseInt(e.target.value) || 2)}
              className="w-full bg-xmr-surface/80 border border-xmr-border/20 p-3 text-lg outline-none focus:border-xmr-accent transition-colors"
              disabled={isProcessing}
            />
          </div>

          {error && <div className="text-xmr-error text-xs font-mono">{error}</div>}
        </div>

        {/* Sticky footer button */}
        <div className="p-6 pt-4 border-t border-xmr-accent/20 shrink-0">
          <button
            onClick={handleSubmit}
            disabled={isProcessing || unlockedBalance <= 0}
            className="w-full py-4 bg-xmr-accent text-white font-black uppercase tracking-[0.2em] font-mono cursor-pointer hover:opacity-90 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {isProcessing ? (
              <><Loader2 size={18} className="animate-spin" /> Splintering...</>
            ) : (
              `Shatter Balance ${unlockedBalance > 0 ? `(${unlockedBalance} XMR)` : '(0 XMR)'}`
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
