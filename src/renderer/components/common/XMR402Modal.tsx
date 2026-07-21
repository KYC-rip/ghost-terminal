import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Lock, X, Zap, Bot, ExternalLink, ChevronRight, AlertCircle, Copy, Check, Users, ChevronUp, ChevronDown } from 'lucide-react';
import { useVault } from '../../hooks/useVault';

export const XMR402Modal: React.FC = () => {
  const { monero402Challenge, clearMonero402Challenge, balance, isStagenet, accounts, selectedAccountIndex, setSelectedAccountIndex } = useVault();
  const [password, setPassword] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successData, setSuccessData] = useState<{ txid: string, proof: string } | null>(null);
  const [copiedTxid, setCopiedTxid] = useState(false);
  const [copiedProof, setCopiedProof] = useState(false);
  const [showAccountSelector, setShowAccountSelector] = useState(false);
  const [paymentStep, setPaymentStep] = useState<string>('');

  if (!monero402Challenge) return null;

  const { id, address, amount, message, type, returnUrl } = monero402Challenge;

  const handleAuthorize = async () => {
    setIsProcessing(true);
    setError(null);
    setPaymentStep('Initializing...');
    try {
      if (type === 'agent') {
        setPaymentStep('Authorizing AI Agent...');
        const res = await window.api.authorizeXmr402(id, password);
        if (res.success) {
          clearMonero402Challenge();
        } else {
          setError(res.error || 'Authorization failed.');
        }
      } else {
        // Deep Link Flow - Duplicate Prevention
        setPaymentStep('Checking cached payments...');
        const cacheRes = await (window as any).api.getXmr402Payment(message);
        let finalTxid = '';
        let finalProof = '';

        if (cacheRes.success && cacheRes.payment) {
          // Re-use cached payment
          setPaymentStep('Cached payment found. Reusing...');
          console.log('[XMR402] Cached payment found. Skipping physical execution.', cacheRes.payment);
          finalTxid = cacheRes.payment.txid;
          finalProof = cacheRes.payment.proof;
        } else {
          // 1. Execute new physical XMR Transfer
          setPaymentStep('Broadcasting transaction...');
          const amountAtomic = (parseFloat(amount) * 1e12).toFixed(0);
          const txRes = await window.api.sendXmr(address, amountAtomic, selectedAccountIndex);
          if (!txRes.success) throw new Error(txRes.error || 'Transaction failed');
          finalTxid = txRes.txid || '';

          // 2. Robust Proof Generation (Retry Loop for mempool race conditions)
          setPaymentStep('Waiting for transaction to enter mempool...');
          let proofRes: any = { success: false };
          for (let i = 0; i < 4; i++) {
            proofRes = await window.api.getTxProof(finalTxid, address, message);
            if (proofRes.success && proofRes.signature) {
              finalProof = proofRes.signature;
              setPaymentStep('Cryptographic proof generated!');
              break;
            }
            setPaymentStep(`Generating proof (Attempt ${i + 1}/4)...`);
            console.warn(`[XMR402] Proof generation attempt ${i + 1} failed. Retrying in 2s...`);
            await new Promise(r => setTimeout(r, 2000));
          }

          if (!finalProof) {
            console.error('[XMR402] Proof generation completely failed after retries.');
            // We do NOT throw here so the user at least gets the TXID,
            // but we MUST NOT trigger the callback automatically.
          }

          // 3. Store Payment Record
          await (window as any).api.saveXmr402Payment(message, finalTxid, finalProof, amount, returnUrl);
        }

        // 4. Handle Transparent Handback or Fallback to Success View
        setPaymentStep('Finalizing protocol...');
        if (returnUrl && finalProof) {
          try {
            const callbackUrl = new URL(decodeURIComponent(returnUrl));
            callbackUrl.searchParams.set('xmr402_txid', finalTxid);
            callbackUrl.searchParams.set('xmr402_proof', finalProof);
            
            await window.api.openExternal(callbackUrl.toString());
            clearMonero402Challenge();
          } catch (e) {
            console.error('Invalid return_url:', returnUrl);
            setSuccessData({ txid: finalTxid, proof: finalProof });
          }
        } else {
          // If no returnUrl OR if proof generation failed, show the fallback UI
          // so the user can see the TXID. The ledger will let them retry the callback later.
          if (returnUrl && !finalProof) {
            console.warn('[XMR402] Skipping automatic callback due to missing proof.');
          }
          setSuccessData({
            txid: finalTxid,
            proof: finalProof
          });
        }
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsProcessing(false);
      setPaymentStep('');
    }
  };

  const copyToClipboard = (text: string, type: 'txid' | 'proof') => {
    navigator.clipboard.writeText(text);
    if (type === 'txid') setCopiedTxid(true);
    if (type === 'proof') setCopiedProof(true);
    setTimeout(() => {
      if (type === 'txid') setCopiedTxid(false);
      if (type === 'proof') setCopiedProof(false);
    }, 2000);
  };

  const handleDeny = async () => {
    if (type === 'agent') {
      await window.api.authorizeXmr402(id, null);
    }
    clearMonero402Challenge();
  };

  const activeAccount = accounts.find(a => a.index === selectedAccountIndex) || accounts[0];

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[200] flex items-center justify-center bg-black/90 backdrop-blur-md p-6 font-mono"
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0, y: 20 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.9, opacity: 0, y: 20 }}
          className="w-full max-w-lg bg-xmr-base border border-xmr-accent/30 shadow-[0_0_50px_rgba(0,255,65,0.1)] overflow-hidden rounded-sm"
        >
          {/* Header */}
          <div className="bg-xmr-accent/10 border-b border-xmr-accent/20 p-4 flex justify-between items-center">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-xmr-accent/20 rounded-sm">
                <Shield size={20} className="text-xmr-accent" />
              </div>
              <div>
                <h2 className="text-sm font-black uppercase tracking-[0.2em] text-xmr-accent italic">Authorization_Required</h2>
                <p className="text-[10px] text-xmr-dim uppercase tracking-widest font-black">XMR402 // Tactical Execution Request</p>
              </div>
            </div>
            <button onClick={handleDeny} className="text-xmr-dim hover:text-xmr-error transition-colors cursor-pointer">
              <X size={20} />
            </button>
          </div>

          <div className="p-8 space-y-6">
            {/* Origin Info */}
            <div className="flex items-center gap-4 p-4 bg-xmr-surface border border-xmr-border/40 rounded-sm">
              <div className="w-12 h-12 flex items-center justify-center bg-xmr-base border border-xmr-green/20 rounded-full">
                {type === 'agent' ? <Bot size={24} className="text-xmr-green" /> : <ExternalLink size={24} className="text-xmr-accent" />}
              </div>
              <div className="flex-grow">
                <div className="text-[10px] text-xmr-dim uppercase font-black tracking-widest">Request_Origin</div>
                <div className="text-xs text-xmr-green font-black uppercase tracking-wider">
                  {type === 'agent' ? 'Ripley_AI_Gateway (LOCAL)' : 'Protocol_Deep_Link'}
                </div>
              </div>
              <div className="text-right">
                <div className="text-[10px] text-xmr-dim uppercase font-black tracking-widest">Network</div>
                <div className={`text-[10px] font-black uppercase ${isStagenet ? 'text-xmr-accent' : 'text-xmr-green'}`}>
                  {isStagenet ? 'STAGENET' : 'MAINNET'}
                </div>
              </div>
            </div>

            {/* Transaction Data */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-xmr-surface border border-xmr-border/40">
                <div className="text-[10px] text-xmr-dim uppercase font-black tracking-widest mb-1">Target_Address</div>
                <div className="text-[11px] text-xmr-green font-mono break-all leading-tight opacity-80">
                  {address.substring(0, 16)}...{address.substring(address.length - 12)}
                </div>
              </div>
              <div className="p-4 bg-xmr-surface border border-xmr-border/40">
                <div className="text-[10px] text-xmr-dim uppercase font-black tracking-widest mb-1">Settlement_Amount</div>
                <div className="text-xl font-black text-xmr-accent italic flex items-baseline gap-1">
                  {amount} <span className="text-[10px] not-italic text-xmr-dim">XMR</span>
                </div>
              </div>
            </div>

            {/* Nonce / Proof Info */}
            <div className="p-4 bg-xmr-surface border border-xmr-border/40">
              <div className="flex items-center gap-2 mb-2">
                <Zap size={12} className="text-xmr-green" />
                <span className="text-[10px] text-xmr-dim uppercase font-black tracking-widest">XMR402_Nonce (Reference)</span>
              </div>
              <div className="bg-xmr-base p-2 text-[10px] font-mono text-xmr-dim break-all border border-xmr-border/20">
                {message || 'NO_NONCE_PROVIDED'}
              </div>
              <p className="text-[9px] text-xmr-dim/60 uppercase mt-2 leading-relaxed">
                This nonce will be cryptographically signed into the transaction proof to verify payment for this specific session.
              </p>
            </div>

            {successData ? (
              <div className="space-y-4 animate-in fade-in duration-500">
                <div className="flex items-center justify-center p-4 bg-xmr-green/10 border border-xmr-green rounded-sm mb-4">
                  <div className="flex flex-col items-center">
                    <Check size={32} className="text-xmr-green mb-2" />
                    <span className="text-xs font-black uppercase text-xmr-green tracking-widest">Protocol_Executed_Successfully</span>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div className="p-4 bg-xmr-surface border border-xmr-border/40 relative">
                    <div className="flex justify-between items-center mb-1">
                      <div className="text-[10px] text-xmr-dim uppercase font-black tracking-widest">Transaction_Hash (TXID)</div>
                      <button onClick={() => copyToClipboard(successData.txid, 'txid')} className="text-xmr-dim hover:text-xmr-green transition-colors flex items-center gap-1 cursor-pointer">
                        {copiedTxid ? <Check size={12} className="text-xmr-green" /> : <Copy size={12} />}
                        <span className={`text-[9px] uppercase font-black ${copiedTxid ? 'text-xmr-green' : ''}`}>{copiedTxid ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <div className="text-[11px] text-xmr-green font-mono break-all leading-tight opacity-80 bg-xmr-base p-2 border border-xmr-border/20">
                      {successData.txid}
                    </div>
                  </div>

                  <div className="p-4 bg-xmr-surface border border-xmr-border/40 relative">
                    <div className="flex justify-between items-center mb-1">
                      <div className="text-[10px] text-xmr-dim uppercase font-black tracking-widest">Cryptographic_Proof</div>
                      <button onClick={() => copyToClipboard(successData.proof, 'proof')} className="text-xmr-dim hover:text-xmr-green transition-colors flex items-center gap-1 cursor-pointer">
                        {copiedProof ? <Check size={12} className="text-xmr-green" /> : <Copy size={12} />}
                        <span className={`text-[9px] uppercase font-black ${copiedProof ? 'text-xmr-green' : ''}`}>{copiedProof ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <div className="text-[11px] text-xmr-green font-mono break-all leading-tight opacity-80 bg-xmr-base p-2 border border-xmr-border/20 h-24 overflow-y-auto">
                      {successData.proof}
                    </div>
                  </div>
                </div>

                <div className="pt-4">
                  <button
                    onClick={handleDeny}
                    className="w-full py-4 border border-xmr-green text-xmr-green font-black uppercase text-xs tracking-widest hover:bg-xmr-green hover:text-xmr-base transition-all cursor-pointer shadow-[0_0_15px_rgba(0,255,65,0.1)]"
                  >
                    Acknowledge_And_Close
                  </button>
                </div>
              </div>
            ) : (
              <>
                {/* Auth Input */}
                <div className="space-y-3">
                  <div className="flex justify-between items-center text-[10px] font-black uppercase tracking-widest text-xmr-dim">
                      <div className="flex items-center gap-2 cursor-pointer hover:text-xmr-green transition-colors" onClick={() => setShowAccountSelector(!showAccountSelector)}>
                        <Users size={12} />
                        <span>{activeAccount?.label || 'Account_0'}</span>
                        {showAccountSelector ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                      </div>
                      <span className={Number(activeAccount?.unlockedBalance) < Number(amount) ? 'text-xmr-error animate-pulse' : 'text-xmr-green'}>
                        Balance: {activeAccount?.unlockedBalance || '0.0000'} XMR
                      </span>
                    </div>

                    <AnimatePresence>
                      {showAccountSelector && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden bg-xmr-surface border border-xmr-border/40"
                        >
                          <div className="p-2 space-y-1 max-h-40 overflow-y-auto custom-scrollbar">
                            {accounts.map((acc) => (
                              <button
                                key={acc.index}
                                onClick={() => {
                                  setSelectedAccountIndex(acc.index);
                                  setShowAccountSelector(false);
                                }}
                                className={`w-full flex justify-between items-center p-2 text-[10px] font-black uppercase tracking-wider transition-all ${acc.index === selectedAccountIndex
                                  ? 'bg-xmr-green/10 text-xmr-green border border-xmr-green/30'
                                  : 'hover:bg-xmr-base text-xmr-dim'
                                  }`}
                              >
                                <div className="flex items-center gap-2">
                                  <span className="opacity-50">#{acc.index}</span>
                                  {acc.label}
                                </div>
                                <span className={Number(acc.unlockedBalance) < Number(amount) ? 'text-xmr-error/50' : 'text-xmr-green/70'}>
                                  {acc.unlockedBalance} XMR
                                </span>
                              </button>
                            ))}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>

                  <div className="relative group">
                    <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
                      <Lock size={14} className="text-xmr-dim group-focus-within:text-xmr-green" />
                    </div>
                    <input
                      type="password"
                      autoFocus
                      placeholder="ENTER_VAULT_PASSWORD_TO_SIGN"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleAuthorize()}
                      className="w-full bg-xmr-surface border border-xmr-border p-4 pl-12 text-xs text-xmr-green font-black outline-none focus:border-xmr-green transition-all"
                    />
                  </div>
                  {error && (
                    <div className="flex items-center gap-2 text-xmr-error text-[10px] font-black uppercase italic animate-pulse">
                      <AlertCircle size={12} /> {error}
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="pt-2 flex gap-4">
                  <button
                      disabled={!password || isProcessing || (Number(activeAccount?.unlockedBalance) < Number(amount))}
                    onClick={handleAuthorize}
                      className="flex-grow py-4 bg-xmr-green text-xmr-base border border-xmr-green font-black uppercase text-xs tracking-[0.2em] hover:bg-xmr-base hover:text-xmr-green transition-all shadow-[0_0_20px_rgba(0,255,65,0.2)] hover:shadow-[0_0_25px_rgba(0,255,65,0.4)] cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                      {isProcessing ? <RefreshCw size={16} className="animate-spin shrink-0" /> : <ChevronRight size={16} className="shrink-0" />}
                      <span className="truncate max-w-full inline-block">
                        {isProcessing ? (paymentStep || 'Processing...') : 'Confirm_Execution'}
                      </span>
                  </button>
                  <button
                    onClick={handleDeny}
                    className="px-6 py-4 border border-xmr-border text-xmr-dim font-black uppercase text-xs tracking-widest hover:border-xmr-error hover:text-xmr-error transition-all cursor-pointer"
                  >
                    Deny
                  </button>
                </div>
              </>
            )}
          </div>

          <div className="bg-xmr-base/50 p-3 text-center border-t border-xmr-border/20">
            <span className="text-[9px] text-xmr-dim font-black uppercase tracking-[0.3em] opacity-40 animate-pulse">
              Ripley_Tactical_Enclave // Secure_Signing_Environment
            </span>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

const RefreshCw = ({ size, className }: { size?: number, className?: string }) => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width={size || 24}
    height={size || 24}
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={className}
  >
    <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
    <path d="M21 3v5h-5" />
    <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
    <path d="M3 21v-5h5" />
  </svg>
);
