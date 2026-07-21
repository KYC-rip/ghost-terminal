import { useState, useEffect } from 'react';
import { X, ShieldAlert } from 'lucide-react';
import { ReceiveModal } from './ReceiveModal';
import { DispatchModal } from './DispatchModal';
import { SplinterModal } from './SplinterModal';
import { ChurnModal } from './ChurnModal';

interface VaultModalsProps {
  // Seed Modal
  showSeed: boolean;
  onCloseSeed: () => void;
  mnemonic: string;
  
  // Receive Modal
  showReceive: boolean;
  onCloseReceive: () => void;
  onCreateSub: (label: string) => void;
  selectedSubaddress?: { address: string; label: string; index: number } | null;
  
  // Send Modal
  showSend: boolean;
  onCloseSend: () => void;
  onSend: (address: string, amount: number) => void;
  isSending: boolean;
  initialAddr?: string;
  sourceSubaddressIndex?: number;

  // Splinter & Churn Modals
  showSplinter: boolean;
  onCloseSplinter: () => void;
  onSplinter: (fragments: number) => Promise<void>;

  showChurn: boolean;
  onCloseChurn: () => void;
  onChurn: () => Promise<void>;
  unlockedBalance: number;
}

export function VaultModals({ 
  showSeed, onCloseSeed, mnemonic,
  showReceive, onCloseReceive, onCreateSub, selectedSubaddress,
  showSend, onCloseSend, onSend, isSending,
  initialAddr = '', sourceSubaddressIndex,
  showSplinter, onCloseSplinter, onSplinter,
  showChurn, onCloseChurn, onChurn, unlockedBalance
}: VaultModalsProps) {

  return (
    <>
      {/* SEED MODAL */}
      {showSeed && (
        <div className="fixed top-0 bottom-0 right-0 left-[14rem] z-[100] flex items-center justify-center p-6 bg-xmr-base/90 backdrop-blur-md animate-in fade-in duration-300">
          <div className="w-full max-w-lg bg-xmr-surface p-8 border-2 border-xmr-error/50 relative rounded-sm">
            <button onClick={onCloseSeed} className="absolute top-4 right-4 text-xmr-dim hover:text-xmr-error cursor-pointer"><X size={24} /></button>
            <div className="space-y-6 font-black">
              <div className="flex items-center gap-3 text-xmr-error animate-pulse font-black"><ShieldAlert size={32} /><h3 className="text-2xl font-black uppercase tracking-tighter">Backup_Protocol</h3></div>
              <div className="p-4 bg-xmr-base border border-xmr-error/20 rounded-sm font-black text-sm leading-loose select-text text-xmr-green">{mnemonic}</div>
              <button onClick={onCloseSeed} className="w-full py-4 bg-xmr-error text-xmr-base font-black uppercase tracking-[0.2em] font-mono cursor-pointer hover:brightness-110 transition-all">I_HAVE_SECURED_THE_KEY</button>
            </div>
          </div>
        </div>
      )}

      {/* RECEIVE MODAL */}
      {showReceive && (
        <ReceiveModal
          onClose={onCloseReceive}
          existingAddress={selectedSubaddress || undefined}
        />
      )}

      {/* DISPATCH MODAL */}
      {showSend && (
        <DispatchModal
          onClose={onCloseSend}
          initialAddress={initialAddr}
          sourceSubaddressIndex={sourceSubaddressIndex}
        />
      )}

      {/* SPLINTER MODAL */}
      {showSplinter && (
        <SplinterModal
          onClose={onCloseSplinter}
          onSplinter={onSplinter}
          unlockedBalance={unlockedBalance}
        />
      )}

      {/* CHURN MODAL */}
      {showChurn && (
        <ChurnModal
          onClose={onCloseChurn}
          onChurn={onChurn}
          unlockedBalance={unlockedBalance}
        />
      )}
    </>
  );
}
