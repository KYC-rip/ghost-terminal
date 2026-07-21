import { useState } from 'react';
import { Coins, Shield, Lock as LockIcon, Wind, Send } from 'lucide-react';
import { Card } from '../Card';
import { TableHeader } from './TableHeader';
import { useVault } from '../../contexts/VaultContext';

interface CoinControlProps {
  outputs: any[];
  onSendFromCoin?: (keyImage: string, amount: string) => void;
}

export function CoinControl({ outputs, onSendFromCoin }: CoinControlProps) {
  const { vanishCoin, status } = useVault();
  const isSyncing = status === 'SYNCING';
  const [vanishingId, setVanishingId] = useState<string | null>(null);

  const handleVanish = async (keyImage: string) => {
    try {
      setVanishingId(keyImage);
      await vanishCoin(keyImage);
    } catch (error) {
      console.error("Vanish Failed:", error);
    } finally {
      setVanishingId(null);
    }
  };

  return (
    <Card noPadding className="h-[400px] flex flex-col">
      <TableHeader>
        <div className="flex items-center gap-2"><Coins size={12}/> <span>Deterministic_Outputs (UTXOs)</span></div>
        <span className="opacity-40">{outputs?.length || 0} Coins</span>
      </TableHeader>
      <div className="flex-grow overflow-y-auto custom-scrollbar">
        <table className="w-full text-left border-collapse">
          <thead className="text-xs text-xmr-dim border-b border-xmr-border/10 sticky top-0 bg-xmr-surface uppercase">
            <tr>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2 text-right">Amount</th>
              <th className="px-4 py-2 text-right">Key_Image_Preview</th>
              <th className="px-4 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="text-xs font-black divide-y divide-xmr-border/5">
            {outputs.map((o: any, i: number) => {
              const isProcessing = vanishingId === o.keyImage;

              return (
                <tr key={i} className={`hover:bg-xmr-green/5 transition-colors ${isProcessing ? 'opacity-50' : ''}`}>
                <td className="px-4 py-3">
                  {o.isUnlocked ? (
                    <span className="flex items-center gap-1 text-xmr-green"><Shield size={10}/> UNLOCKED</span>
                  ) : (
                    <span className="flex items-center gap-1 text-xmr-dim opacity-50"><LockIcon size={10}/> FROZEN</span>
                  )}
                </td>
                  <td className="px-4 py-3 text-right text-xmr-green">{o.amount} XMR</td>
                  <td className="px-4 py-3 text-right font-mono text-xs opacity-40 uppercase">{o.keyImage?.substring(0, 24)}...</td>
                <td className="px-4 py-3 text-right">
                    <div className="flex items-center gap-1.5 justify-end">
                      {onSendFromCoin && (
                        <button
                          onClick={() => onSendFromCoin(o.keyImage, o.amount)}
                          disabled={!o.isUnlocked || isSyncing}
                          title={!o.isUnlocked ? 'Coin is frozen' : 'Send using this specific coin'}
                          className={`text-xs px-2.5 py-1 border transition-all uppercase flex items-center justify-center gap-1 cursor-pointer ${o.isUnlocked
                              ? 'border-xmr-accent/40 text-xmr-accent hover:bg-xmr-accent/10 hover:border-xmr-accent'
                              : 'border-xmr-border text-xmr-dim opacity-40 cursor-not-allowed'
                            }`}
                        >
                          <Send size={8} /> Send
                        </button>
                      )}
                      <button
                        onClick={() => handleVanish(o.keyImage)}
                        disabled={!o.isUnlocked || isSyncing || vanishingId !== null}
                      title={
                        isSyncing ? "Wait for vault to sync before vanishing." :
                          !o.isUnlocked ? "Coin is frozen and cannot be vanished." :
                            "Vanish: Sweeps this individual coin back to your primary address."
                      }
                        className={`text-xs px-2.5 py-1 border transition-all uppercase flex items-center justify-center gap-1 min-w-[60px] cursor-pointer ${o.isUnlocked
                            ? 'border-xmr-green/40 text-xmr-green hover:bg-xmr-green/10 hover:border-xmr-green'
                            : 'border-xmr-border text-xmr-dim opacity-30 cursor-not-allowed'
                          }`}
                      >
                        {isProcessing ? <Wind size={10} className="animate-spin" /> : 'Vanish'}
                      </button>
                    </div>
                </td>
              </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

