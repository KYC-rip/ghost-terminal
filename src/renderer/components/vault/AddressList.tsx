import { useState, type MouseEvent } from 'react';
import { Copy, Edit2, Check, X, Wind, Send } from 'lucide-react';
import { Card } from '../Card';
import { TableHeader } from './TableHeader';
import { AddressDisplay } from '../common/AddressDisplay';

interface AddressListProps {
  subaddresses: any[];
  handleCopy: (text: string) => void;
  onUpdateLabel: (index: number, label: string) => void;
  onRowClick: (sub: any) => void;
  onVanishSubaddress: (index: number) => Promise<void>;
  onSendFrom: (subaddressIndex: number) => void;
  isSyncing: boolean;
  hideZeroBalances: boolean;
  onToggleFilter: (val: boolean) => void;
}

export function AddressList({
  subaddresses, handleCopy, onUpdateLabel, onRowClick, onVanishSubaddress,
  onSendFrom, isSyncing, hideZeroBalances, onToggleFilter
}: AddressListProps) {
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [editValue, setEditValue] = useState('');
  const [vanishingIndex, setVanishingIndex] = useState<number | null>(null);

  const startEdit = (index: number, currentLabel: string) => {
    setEditingIndex(index);
    setEditValue(currentLabel);
  };

  const saveEdit = () => {
    if (editingIndex !== null) {
      onUpdateLabel(editingIndex, editValue);
      setEditingIndex(null);
    }
  };

  const handleVanish = async (e: MouseEvent, index: number) => {
    e.stopPropagation();
    try {
      setVanishingIndex(index);
      await onVanishSubaddress(index);
    } catch (err) {
      console.error("Subaddress vanish failed:", err);
    } finally {
      setVanishingIndex(null);
    }
  };

  return (
    <Card noPadding className="h-[400px] flex flex-col">
      <TableHeader>
        <div className="flex items-center gap-4">
          <span>Internal_Subaddresses</span>
          <span className="opacity-40">{subaddresses?.length || 0} Entries</span>
        </div>
        <button
          onClick={() => onToggleFilter(!hideZeroBalances)}
          className={`flex items-center gap-2 px-3 py-1 border transition-all cursor-pointer text-[10px] font-black ${hideZeroBalances ? 'bg-xmr-accent/10 border-xmr-accent text-xmr-accent' : 'border-xmr-border text-xmr-dim hover:border-xmr-green hover:text-xmr-green'}`}
        >
          {hideZeroBalances ? (
            <>
              <Check size={10} /> DUST_FILTERED
            </>
          ) : (
            <>
              <X size={10} /> SHOW_ALL_DUST
            </>
          )}
        </button>
      </TableHeader>
      <div className="flex-grow overflow-y-auto custom-scrollbar">
        <table className="w-full text-left">
          <thead className="text-xs text-xmr-dim border-b border-xmr-border/10 sticky top-0 bg-xmr-surface uppercase">
            <tr>
              <th className="px-4 py-2">Index</th>
              <th className="px-4 py-2">Label</th>
              <th className="px-4 py-2">Address</th>
              <th className="px-4 py-2 text-right">Balance</th>
              <th className="px-4 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="text-xs font-black divide-y divide-xmr-border/5">
            {subaddresses.map((s: any) => {
              const hasBalance = parseFloat(s.balance) > 0;
              const isVanishing = vanishingIndex === s.index;

              return (
                <tr
                  key={s.index}
                  onClick={() => onRowClick(s)}
                  className={`hover:bg-xmr-green/5 transition-colors group cursor-pointer ${isVanishing ? 'opacity-50' : ''}`}
                >
                  <td className="px-4 py-3 text-xmr-dim">#{s.index}</td>
                  <td className="px-4 py-3 uppercase text-xmr-green/80">
                    {editingIndex === s.index ? (
                      <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                        <input
                          autoFocus
                          type="text"
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          onKeyDown={(e) => { if (e.key === 'Enter') saveEdit(); else if (e.key === 'Escape') setEditingIndex(null); }}
                          className="bg-xmr-base border border-xmr-green/50 text-xs px-2 py-1 outline-none text-xmr-green w-32"
                        />
                        <button onClick={saveEdit} className="text-xmr-green hover:scale-110 transition-transform"><Check size={12} /></button>
                        <button onClick={() => setEditingIndex(null)} className="text-xmr-error hover:scale-110 transition-transform"><X size={12} /></button>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span>{s.label}</span>
                        <button
                          onClick={(e) => { e.stopPropagation(); startEdit(s.index, s.label); }}
                          className="text-xmr-dim opacity-0 group-hover:opacity-50 hover:!opacity-100 transition-opacity cursor-pointer"
                        >
                          <Edit2 size={10} />
                        </button>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono opacity-60">
                    <div className="flex items-center gap-2">
                      <AddressDisplay address={s.address} truncate length={16} className="text-[11px]" />
                      <button
                        onClick={(e) => { e.stopPropagation(); handleCopy(s.address); }}
                        className="text-xmr-green opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer shrink-0"
                      >
                        <Copy size={10} />
                      </button>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right text-xmr-green">
                    {hasBalance ? s.balance : '--'}
                  </td>
                  <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center gap-1.5 justify-end">
                      <button
                        onClick={(e) => { e.stopPropagation(); onSendFrom(s.index); }}
                        disabled={!hasBalance}
                        title={hasBalance ? 'Send from this subaddress' : 'No balance to send'}
                        className={`text-xs px-2.5 py-1 border transition-all uppercase flex items-center justify-center gap-1 cursor-pointer ${hasBalance
                          ? 'border-xmr-accent/40 text-xmr-accent hover:bg-xmr-accent/10 hover:border-xmr-accent'
                          : 'border-xmr-border text-xmr-dim opacity-40 cursor-not-allowed'
                          }`}
                      >
                        <Send size={8} /> Send
                      </button>
                      {s.index > 0 && (
                        <button
                          onClick={(e) => handleVanish(e, s.index)}
                          disabled={!hasBalance || isSyncing || vanishingIndex !== null}
                          title={!hasBalance ? 'No balance to sweep' : 'Sweep all outputs from this subaddress to a fresh one'}
                          className={`text-xs px-2.5 py-1 border transition-all uppercase flex items-center justify-center gap-1 min-w-[60px] cursor-pointer ${hasBalance
                            ? 'border-xmr-green/40 text-xmr-green hover:bg-xmr-green/10 hover:border-xmr-green'
                            : 'border-xmr-border text-xmr-dim opacity-40 cursor-not-allowed'
                            }`}
                        >
                          {isVanishing ? <Wind size={10} className="animate-spin" /> : 'Vanish'}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
