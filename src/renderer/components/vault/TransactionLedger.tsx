import { useState, useEffect } from 'react';
import { ArrowDownLeft, ArrowUpRight, Copy, ExternalLink, Info, Loader2, Key, ShieldCheck, Fingerprint, CheckCircle, ShieldAlert, Zap } from 'lucide-react';
import { Card } from '../Card';
import { TableHeader } from './TableHeader';
import { AddressDisplay } from '../common/AddressDisplay';
import { SubaddressInfo, useVault } from '../../contexts/VaultContext';
import { useStats } from '../../hooks/useStats';

interface Transaction {
  id: string;
  amount: string;
  type: 'in' | 'out' | 'pending';
  timestamp: number;
  address: string;
  confirmations: number;
  fee?: string;
  height?: number;
  paymentId?: string;
  note?: string;
  unlockTime?: number;
  doubleSpendSeen?: boolean;
  destinations?: Array<{ address: string; amount: string }>;
}

interface TransactionLedgerProps {
  txs: Transaction[];
  subaddresses?: SubaddressInfo[];
}

function getRelativeTime(timestamp: number) {
  const diffInSeconds = Math.floor((Date.now() - timestamp) / 1000);
  if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
  const diffInHours = Math.floor(diffInMinutes / 60);
  if (diffInHours < 24) return `${diffInHours}h ago`;
  const diffInDays = Math.floor(diffInHours / 24);
  if (diffInDays < 30) return `${diffInDays}d ago`;
  const diffInMonths = Math.floor(diffInDays / 30);
  if (diffInMonths < 12) return `${diffInMonths}mo ago`;
  return `${Math.floor(diffInDays / 365)}y ago`;
}

function getDateLabel(timestamp: number): string {
  const date = new Date(timestamp);
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);

  if (date.toDateString() === today.toDateString()) {
    return `Today — ${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
  }
  if (date.toDateString() === yesterday.toDateString()) {
    return `Yesterday — ${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
  }
  return date.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
}

function groupByDate(txs: Transaction[]): { label: string; txs: Transaction[] }[] {
  const groups: Map<string, Transaction[]> = new Map();
  for (const tx of txs) {
    const key = new Date(tx.timestamp).toDateString();
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(tx);
  }
  return Array.from(groups.entries()).map(([key, txs]) => ({
    label: getDateLabel(txs[0].timestamp),
    txs,
  }));
}

export function TransactionLedger({ txs, subaddresses = [] }: TransactionLedgerProps) {
  const { getTxKey, getTxProof, checkTxKey, checkTxProof, addLog } = useVault();
  const { stats } = useStats();

  // Street price (USD per XMR) for fiat estimates next to each amount.
  const xmrPrice = parseFloat((stats?.price?.street || '0').replace(/[$,]/g, '')) || 0;
  const formatFiat = (xmrAmount: string): string | null => {
    if (!xmrPrice) return null;
    const value = parseFloat(xmrAmount);
    if (!isFinite(value)) return null;
    return (value * xmrPrice).toLocaleString('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
  };

  const [expandedTxId, setExpandedTxId] = useState<string | null>(null);
  const [txKeys, setTxKeys] = useState<Record<string, string>>({});
  const [txProofs, setTxProofs] = useState<Record<string, string>>({});
  const [isLoadingDetails, setIsLoadingDetails] = useState<Record<string, boolean>>({});
  const [ghostTrades, setGhostTrades] = useState<Record<string, { tradeId: string, timestamp: number }>>({});
  const [xmr402Payments, setXmr402Payments] = useState<Record<string, any>>({});

  useEffect(() => {
    const fetchGhostTrades = async () => {
      try {
        const result = await window.api.getGhostTrades();
        if (result.success) {
          setGhostTrades(result.trades || {});
        }
      } catch (e) {
        console.error("Failed to load ghost trades:", e);
      }
    };
    const fetchXmr402Payments = async () => {
      try {
        const result = await window.api.getAllXmr402Payments();
        if (result.success) {
          setXmr402Payments(result.payments || {});
        }
      } catch (e) {
        console.error("Failed to load XMR402 payments:", e);
      }
    };
    fetchGhostTrades();
    fetchXmr402Payments();
  }, [txs]);

  // Verification UI State
  const [isVerifyOpen, setIsVerifyOpen] = useState(false);
  const [verifyTxId, setVerifyTxId] = useState('');
  const [verifyAddress, setVerifyAddress] = useState('');
  const [verifyKeyOrProof, setVerifyKeyOrProof] = useState('');
  const [verifyMessage, setVerifyMessage] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any>(null);

  const getSubaddressLabel = (addr: string) => {
    const match = subaddresses.find(s => s.address === addr);
    return match?.label || null;
  };

  const toggleExpand = async (id: string) => {
    if (expandedTxId === id) {
      setExpandedTxId(null);
      return;
    }
    setExpandedTxId(id);

    const tx = txs.find(t => t.id === id);
    if (tx && tx.type === 'out' && !txKeys[id]) {
      setIsLoadingDetails(prev => ({ ...prev, [id]: true }));
      try {
        const key = await getTxKey(id);
        if (key) setTxKeys(prev => ({ ...prev, [id]: key }));
      } catch (e) {
        console.warn("Failed to fetch tx key:", e);
      } finally {
        setIsLoadingDetails(prev => ({ ...prev, [id]: false }));
      }
    }
  };

  const generateProof = async (txid: string, address: string) => {
    setIsLoadingDetails(prev => ({ ...prev, [txid]: true }));
    try {
      const proof = await getTxProof(txid, address);
      if (proof) {
        setTxProofs(prev => ({ ...prev, [txid]: proof }));
        addLog(`✅ Payment proof generated for ${txid.substring(0, 8)}`, 'success');
      }
    } catch (e: any) {
      addLog(`❌ Proof failed: ${e.message}`, 'error');
    } finally {
      setIsLoadingDetails(prev => ({ ...prev, [txid]: false }));
    }
  };

  const handleVerify = async () => {
    if (!verifyTxId || !verifyAddress || !verifyKeyOrProof) {
      addLog("Missing fields for verification", "warning");
      return;
    }

    setIsVerifying(true);
    setVerifyResult(null);
    try {
      const isProof = verifyKeyOrProof.startsWith('InProofV') || verifyKeyOrProof.length > 100;
      let result;
      if (isProof) {
        result = await checkTxProof(verifyTxId, verifyAddress, verifyMessage, verifyKeyOrProof);
      } else {
        result = await checkTxKey(verifyTxId, verifyKeyOrProof, verifyAddress);
      }

      if (result) {
        setVerifyResult(result);
        if (result.good === false) {
          addLog("Verification FAILED: Signature/Key is invalid for this TxID.", "error");
        } else {
          addLog(`Verification SUCCESS: Received ${result.received} XMR`, "success");
        }
      }
    } catch (e: any) {
      addLog(`Verification Error: ${e.message}`, "error");
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <Card noPadding className="h-[430px] flex flex-col overflow-hidden">
      <TableHeader>
        <div className="flex items-center gap-2">
          <span>Transaction_History</span>
          <Info size={10} className="text-xmr-green opacity-40" />
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsVerifyOpen(!isVerifyOpen)}
            className={`flex items-center gap-1.5 px-2 py-0.5 rounded-sm transition-all cursor-pointer ${isVerifyOpen ? 'bg-xmr-green text-xmr-base' : 'bg-xmr-green/10 text-xmr-green hover:bg-xmr-green/20'}`}
          >
            <ShieldCheck size={10} />
            <span>Verify_External</span>
          </button>
          <span className="opacity-40">{txs?.length || 0} Records</span>
        </div>
      </TableHeader>

      <div className="flex-grow flex flex-col min-h-0 relative">
        {/* Verification Drawer/Box */}
        {isVerifyOpen && (
          <div className="absolute inset-0 z-20 bg-xmr-base/95 backdrop-blur-sm border-b border-xmr-border/40 p-4 transition-all duration-300 overflow-y-auto">
            <div className="max-w-md mx-auto space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-black uppercase tracking-widest text-xmr-green flex items-center gap-2">
                  <ShieldCheck size={14} /> Payment Verification Toolkit
                </h3>
                <button
                  onClick={() => { setIsVerifyOpen(false); setVerifyResult(null); }}
                  className="text-xmr-dim hover:text-white uppercase text-[10px] font-black tracking-widest cursor-pointer"
                >
                  [Close]
                </button>
              </div>

              <div className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[9px] uppercase font-black text-xmr-dim tracking-tighter">Transaction_ID (TxID)</label>
                  <input
                    type="text"
                    value={verifyTxId}
                    onChange={e => setVerifyTxId(e.target.value.trim())}
                    placeholder="Enter 64-char hash..."
                    className="w-full bg-xmr-surface border border-xmr-border/40 rounded-sm px-2 py-1.5 text-[10px] font-mono focus:border-xmr-green/50 outline-none transition-colors"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] uppercase font-black text-xmr-dim tracking-tighter">Recipient_Address</label>
                  <input
                    type="text"
                    value={verifyAddress}
                    onChange={e => setVerifyAddress(e.target.value.trim())}
                    placeholder="Enter recipient's public address..."
                    className="w-full bg-xmr-surface border border-xmr-border/40 rounded-sm px-2 py-1.5 text-[10px] font-mono focus:border-xmr-green/50 outline-none transition-colors"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-[9px] uppercase font-black text-xmr-dim tracking-tighter">Secret_Key or Signature_Proof</label>
                  <textarea
                    rows={2}
                    value={verifyKeyOrProof}
                    onChange={e => setVerifyKeyOrProof(e.target.value.trim())}
                    placeholder="Paste txKey or Proof signature here..."
                    className="w-full bg-xmr-surface border border-xmr-border/40 rounded-sm px-2 py-1.5 text-[10px] font-mono focus:border-xmr-green/50 outline-none transition-colors resize-none"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <label className="text-[9px] uppercase font-black text-xmr-dim tracking-tighter">Message (Optional-Proof Only)</label>
                    <input
                      type="text"
                      value={verifyMessage}
                      onChange={e => setVerifyMessage(e.target.value)}
                      placeholder="e.g. For Order #123"
                      className="w-full bg-xmr-surface border border-xmr-border/40 rounded-sm px-2 py-1.5 text-[10px] focus:border-xmr-green/50 outline-none transition-colors"
                    />
                  </div>
                  <div className="flex items-end">
                    <button
                      onClick={handleVerify}
                      disabled={isVerifying}
                      className="w-full h-[32px] bg-xmr-green text-xmr-base text-[10px] font-black uppercase tracking-widest hover:bg-xmr-base hover:text-xmr-green border border-xmr-green transition-all flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
                    >
                      {isVerifying ? <Loader2 size={12} className="animate-spin" /> : <Fingerprint size={12} />}
                      <span>{isVerifying ? 'Verifying...' : 'Verify Payment'}</span>
                    </button>
                  </div>
                </div>

                {verifyResult && (
                  <div className={`p-3 border rounded-sm animate-in zoom-in-95 duration-200 ${verifyResult.good === false ? 'bg-xmr-error/10 border-xmr-error/30' : 'bg-xmr-green/10 border-xmr-green/30'}`}>
                    <div className="flex items-start gap-3">
                      <div className={`mt-0.5 p-1 rounded-full ${verifyResult.good === false ? 'bg-xmr-error/20 text-xmr-error' : 'bg-xmr-green/20 text-xmr-green'}`}>
                        {verifyResult.good === false ? <ShieldAlert size={16} /> : <CheckCircle size={16} />}
                      </div>
                      <div className="flex-grow space-y-1">
                        <div className={`text-[11px] font-black uppercase tracking-wider ${verifyResult.good === false ? 'text-xmr-error' : 'text-xmr-green'}`}>
                          {verifyResult.good === false ? 'Verification Failed' : 'Payment Verified'}
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-[10px]">
                          <div className="flex flex-col">
                            <span className="text-xmr-dim font-bold uppercase text-[9px]">Amount_Received</span>
                            <span className="text-xmr-green font-mono">{verifyResult.received} XMR</span>
                          </div>
                          <div className="flex flex-col">
                            <span className="text-xmr-dim font-bold uppercase text-[9px]">Confirmations</span>
                            <span className="text-xmr-green font-mono">{verifyResult.confirmations}</span>
                          </div>
                        </div>
                        {verifyResult.inPool && (
                          <div className="text-[9px] text-xmr-accent uppercase font-black tracking-tighter mt-1 italic">
                            Transaction is still in Mempool
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        <div className="flex-grow overflow-y-auto custom-scrollbar relative">
          {!txs || txs.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-xmr-dim/30 italic uppercase text-[10px] tracking-widest gap-2">
              <Zap size={24} className="opacity-20 translate-y-2 animate-pulse" />
              <span>No_Ledger_Activity_Found</span>
            </div>
          ) : (
            <div>
              {groupByDate(txs).map((group) => (
                <div key={group.label}>
                  <div className="sticky top-0 z-[2] px-4 py-2 text-[9px] font-bold uppercase tracking-[0.2em] text-xmr-dim/60 bg-xmr-base border-b border-xmr-border/10">
                    {group.label}
                  </div>
                  {group.txs.map((tx) => {
                  const isExpanded = expandedTxId === tx.id;
                  const isIncoming = tx.type === 'in';
                  const xmr402Info = xmr402Payments[tx.id];

                  return (
                    <div key={tx.id} className="flex flex-col transition-all duration-200">
                      <div
                        onClick={() => toggleExpand(tx.id)}
                        className={`flex items-center px-4 py-3 cursor-pointer hover:bg-xmr-green/5 transition-colors group border-b border-xmr-border/5 relative ${isExpanded ? 'bg-xmr-green/5' : ''}`}
                      >
                        {/* Color indicator bar on hover */}
                        <div className={`absolute left-0 top-0 bottom-0 w-[2px] opacity-0 group-hover:opacity-100 transition-opacity ${isIncoming ? 'bg-xmr-green' : 'bg-xmr-accent'}`} />

                        {/* Type indicator */}
                        <div className={`w-7 h-7 rounded-sm flex items-center justify-center mr-3 shrink-0 ${isIncoming ? 'bg-xmr-green/8 border border-xmr-green/20' : 'bg-xmr-accent/8 border border-xmr-accent/20'}`}>
                          {isIncoming ? (
                            <ArrowDownLeft size={13} className="text-xmr-green" />
                          ) : (
                            <ArrowUpRight size={13} className="text-xmr-accent" />
                          )}
                        </div>

                        {/* Info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-wide">
                            <span className={isIncoming ? 'text-xmr-green' : 'text-xmr-accent'}>
                              {isIncoming ? 'Received' : 'Dispatched'}
                            </span>
                            {ghostTrades[tx.id] && (
                              <span className="text-[7px] px-1.5 py-0.5 bg-xmr-accent/10 border border-xmr-accent/20 rounded-sm text-xmr-accent font-black tracking-wider">Ghost</span>
                            )}
                            {xmr402Info && (
                              <span className="text-[7px] px-1.5 py-0.5 bg-xmr-warning/10 border border-xmr-warning/20 rounded-sm text-xmr-warning font-black tracking-wider">XMR402</span>
                            )}
                          </div>
                          <div className="text-[9px] text-xmr-dim/40 mt-0.5 truncate">
                            {isIncoming && tx.address ? `from ${tx.address.substring(0, 8)}...${tx.address.substring(tx.address.length - 6)}` : tx.destinations?.[0] ? `to ${tx.destinations[0].address.substring(0, 8)}...${tx.destinations[0].address.substring(tx.destinations[0].address.length - 6)}` : tx.type.toUpperCase()}
                            {tx.fee && !isIncoming && ` · fee: ${tx.fee}`}
                          </div>
                        </div>

                        {/* Amount */}
                        <div className="text-right shrink-0 ml-4">
                          <div className={`text-[13px] font-black ${isIncoming ? 'text-xmr-green' : 'text-xmr-accent'}`}>
                            {isIncoming ? '+' : '-'}{tx.amount}
                          </div>
                          <div className="text-[9px] text-xmr-dim/40 font-bold">
                            XMR
                            {formatFiat(tx.amount) && (
                              <span className="text-xmr-dim/30 font-mono ml-1">· ≈ {formatFiat(tx.amount)}</span>
                            )}
                          </div>
                        </div>

                        {/* Time */}
                        <div className="w-16 text-right shrink-0 ml-3 text-[9px] text-xmr-dim/40 font-bold">
                          {getRelativeTime(tx.timestamp)}
                        </div>
                      </div>

                      {/* Expanded Details */}
                      {isExpanded && (
                        <div className="px-4 py-4 bg-xmr-green/5 border-t border-b border-xmr-green/10 space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
                          {/* XMR402 Panel */}
                          {xmr402Info && (
                            <div className="p-3 bg-xmr-warning/10 border border-xmr-warning/20 rounded-sm flex justify-between items-center">
                              <div>
                                <div className="text-[9px] text-xmr-warning uppercase font-black tracking-widest">XMR402 Protocol Executed</div>
                                <div className="text-xs text-xmr-green font-mono break-all opacity-80 mt-1">Nonce: {xmr402Info.nonce}</div>
                              </div>
                              {xmr402Info.returnUrl && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const callbackUrl = new URL(decodeURIComponent(xmr402Info.returnUrl));
                                    callbackUrl.searchParams.set('xmr402_txid', tx.id);
                                    if (xmr402Info.proof) callbackUrl.searchParams.set('xmr402_proof', xmr402Info.proof);
                                    window.api.openExternal(callbackUrl.toString());
                                  }}
                                  className="shrink-0 ml-4 px-3 py-1.5 bg-xmr-warning hover:opacity-90 text-xmr-base text-[10px] font-black uppercase tracking-wider rounded-sm transition-colors cursor-pointer flex items-center gap-1 shadow-[0_0_10px_var(--warning-color)]"
                                >
                                  <ExternalLink size={12} /> Retry Callback
                                </button>
                              )}
                            </div>
                          )}

                          {/* TXID */}
                          <div className="space-y-1">
                            <div className="flex justify-between items-center">
                              <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Transaction_ID</label>
                              {ghostTrades[tx.id] && (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const tradeId = ghostTrades[tx.id].tradeId;
                                    const url = `https://kyc.rip/swap?id=${tradeId}`;
                                    window.api.openExternal(url, { width: 940, height: 820 });
                                  }}
                                  className="text-[10px] text-xmr-accent hover:text-xmr-green underline uppercase tracking-tighter flex items-center gap-1 cursor-pointer"
                                >
                                  <ExternalLink size={10} /> View_Ghost_Protocol_Status
                                </button>
                              )}
                            </div>
                            <AddressDisplay address={tx.id} className="text-xmr-green" />
                          </div>

                          <div className="grid grid-cols-2 gap-4">
                            {/* Details Column 1 */}
                            <div className="space-y-3">
                              <div className="space-y-1">
                                <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Block_Height</label>
                                <span className="text-xs font-mono font-black">{tx.height || 'Pending...'}</span>
                              </div>
                              {tx.fee && (
                                <div className="space-y-1">
                                  <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Network_Fee</label>
                                  <span className="text-xs font-mono font-black text-xmr-dim">{tx.fee} XMR</span>
                                </div>
                              )}
                              <div className="space-y-1">
                                <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Timestamp</label>
                                <span className="text-xs font-mono font-black">{new Date(tx.timestamp).toLocaleString()}</span>
                              </div>
                            </div>

                            {/* Details Column 2 */}
                            <div className="space-y-3">
                              <div className="space-y-1">
                                <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Unlock_Time</label>
                                <span className={`text-xs font-mono font-black ${tx.confirmations < 10 ? 'text-xmr-accent' : 'text-xmr-green'}`}>
                                  {tx.confirmations >= 10 ? 'SPENDABLE' : `${Math.max(0, 10 - tx.confirmations)} Blocks Locked`}
                                </span>
                              </div>
                              {tx.paymentId && (
                                <div className="space-y-1">
                                  <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Payment_ID</label>
                                  <span className="text-[11px] font-mono font-black break-all">{tx.paymentId}</span>
                                </div>
                              )}
                              {tx.doubleSpendSeen && (
                                <div className="space-y-1">
                                  <label className="text-xs text-xmr-error uppercase font-black tracking-widest block">DoubleSpend_Alert</label>
                                  <span className="text-xs font-black text-xmr-error animate-pulse">WARNING: CONFLICT DETECTED</span>
                                </div>
                              )}
                            </div>
                          </div>

                          {/* Monero Specific Secrets (OUT transfers only) */}
                          {!isIncoming && (
                            <div className="space-y-3 pt-4 border-t border-xmr-green/10">
                              <div className="space-y-1 relative group">
                                <div className="flex justify-between items-center mb-1">
                                  <label className="text-[10px] text-xmr-dim uppercase font-black tracking-widest flex items-center gap-1.5">
                                    <Key size={10} className="text-xmr-green" /> Transaction_Secret_Key
                                  </label>
                                  {isLoadingDetails[tx.id] && <Loader2 size={10} className="animate-spin text-xmr-green" />}
                                </div>
                                <div className="flex items-center gap-2 bg-xmr-surface border border-xmr-green/10 rounded-sm p-2">
                                  <span className={`text-[10px] font-mono truncate max-w-[200px] ${!txKeys[tx.id] && !isLoadingDetails[tx.id] ? 'text-xmr-dim' : 'text-xmr-green'}`}>
                                    {txKeys[tx.id] || (isLoadingDetails[tx.id] ? 'FETCHING...' : 'METADATA_NOT_STORED')}
                                  </span>
                                  {txKeys[tx.id] && (
                                    <button
                                      onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(txKeys[tx.id]); addLog("Secret Key copied", "info"); }}
                                      className="p-1 text-xmr-dim hover:text-xmr-green transition-colors cursor-pointer"
                                    >
                                      <Copy size={12} />
                                    </button>
                                  )}
                                </div>
                              </div>

                            <div className="space-y-1">
                                <label className="text-[10px] text-xmr-dim uppercase font-black tracking-widest flex items-center gap-1.5 mb-1">
                                  <ShieldCheck size={10} className="text-xmr-green" /> Payment_Proof
                                </label>
                                {txProofs[tx.id] ? (
                                  <div className="flex flex-col gap-2">
                                    <div className="bg-xmr-green/10 p-2 border border-xmr-green/20 rounded-sm">
                                      <div className="text-[9px] font-mono text-xmr-green break-all leading-tight mb-2 opacity-80">
                                        {txProofs[tx.id]}
                                      </div>
                                      <button
                                        onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(txProofs[tx.id]); addLog("Proof copied", "success"); }}
                                        className="w-full py-1.5 bg-xmr-green text-xmr-base text-[10px] uppercase font-black tracking-widest hover:bg-xmr-base hover:text-xmr-green transition-all"
                                      >
                                        Copy Signature
                                      </button>
                                    </div>
                                  </div>
                                ) : (tx.destinations?.[0]?.address || tx.address) ? (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      generateProof(tx.id, (tx.destinations?.[0]?.address || tx.address) as string);
                                    }}
                                    disabled={isLoadingDetails[tx.id]}
                                    className="w-full py-2 bg-xmr-green/5 border border-xmr-green/20 text-xmr-green text-[10px] uppercase font-black tracking-widest hover:bg-xmr-green/20 transition-colors flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
                                  >
                                    {isLoadingDetails[tx.id] ? (
                                      <>
                                        <Loader2 size={12} className="animate-spin" />
                                        <span>Generating...</span>
                                      </>
                                    ) : (
                                      <>
                                        <Fingerprint size={12} />
                                        <span>Generate Proof Signature</span>
                                      </>
                                    )}
                                  </button>
                                ) : (
                                  // No stored recipient + no tx key → this was made from another device.
                                  // An OutProof (get_tx_proof) needs both, so it's impossible here.
                                  <div className="text-[10px] text-xmr-dim/70 leading-relaxed bg-xmr-surface border border-xmr-border/20 rounded-sm p-2.5">
                                    Payment proof isn't available for this transaction — it was made from
                                    another device, so this wallet holds neither the recipient address nor
                                    the transaction key needed to prove it. Proofs work for sends you make
                                    from this wallet.
                                  </div>
                                )}
                              </div>
                            </div>
                          )}

                          {/* Destinations for OUT txs */}
                          {!isIncoming && (
                            <div className="space-y-2 border-t border-xmr-green/5 pt-3">
                              <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Outbound_To</label>
                              {tx.destinations && tx.destinations.length > 0 ? (
                                <div className="space-y-2">
                                  {tx.destinations.map((dest, idx) => {
                                    const label = getSubaddressLabel(dest.address);
                                    return (
                                      <div key={idx} className="flex justify-between items-start gap-4">
                                        <div className="flex-grow flex flex-col">
                                          {label && (
                                            <span className="text-xs font-black text-xmr-green uppercase tracking-widest bg-xmr-green/10 self-start px-1.5 py-0.5 rounded-sm mb-1">
                                              {label}
                                            </span>
                                          )}
                                          <AddressDisplay address={dest.address} className="text-[11px]" />
                                        </div>
                                        <span className="text-xs font-black text-xmr-accent whitespace-nowrap mt-0.5">-{dest.amount} XMR</span>
                                      </div>
                                    );
                                  })}
                                </div>
                              ) : (
                                <div className="text-xs font-mono text-xmr-dim opacity-60 flex items-center gap-2">
                                  <span>¿Unknown Destination?</span>
                                  <span className="text-xs bg-xmr-dim/10 px-1 rounded-sm uppercase tracking-tighter">Privacy Protected</span>
                                </div>
                              )}
                            </div>
                          )}

                          {/* Fallback address for IN txs */}
                          {isIncoming && tx.address && (
                            <div className="space-y-2 border-t border-xmr-green/5 pt-3">
                              <label className="text-xs text-xmr-dim uppercase font-black tracking-widest block">Inbound_To</label>
                              <div className="flex flex-col">
                                {getSubaddressLabel(tx.address) && (
                                  <span className="text-xs font-black text-xmr-green uppercase tracking-widest bg-xmr-green/10 self-start px-1.5 py-0.5 rounded-sm mb-1">
                                    {getSubaddressLabel(tx.address)}
                                  </span>
                                )}
                                <AddressDisplay address={tx.address} className="text-xmr-green text-[11px]" />
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
