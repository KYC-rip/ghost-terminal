import { useState, useEffect, useRef } from 'react';
import { Wallet, DollarSign, Send, Loader2, CheckCircle2, ChevronDown, ChevronUp, Coins, Copy, AlertTriangle, Info, ExternalLink } from 'lucide-react';
import { useVault } from '../../contexts/VaultContext';
import { useStats } from '../../hooks/useStats';
import { WalletService } from '../../services/walletService';

interface ParsedDest {
  address: string;
  amount: number;
}

function parseMultiSend(text: string): { destinations: ParsedDest[]; errors: string[] } {
  const lines = text.split('\n').map((l) => l.trim()).filter(Boolean);
  const destinations: ParsedDest[] = [];
  const errors: string[] = [];
  lines.forEach((line, i) => {
    const parts = line.split(/[,\s]+/).filter(Boolean);
    if (parts.length < 2) {
      errors.push(`Line ${i + 1}: missing amount`);
      return;
    }
    const address = parts[0];
    const amount = parseFloat(parts[parts.length - 1]);
    if (!address.match(/^[48]/)) {
      errors.push(`Line ${i + 1}: invalid XMR address`);
      return;
    }
    if (isNaN(amount) || amount <= 0) {
      errors.push(`Line ${i + 1}: invalid amount`);
      return;
    }
    destinations.push({ address, amount });
  });
  return { destinations, errors };
}

interface DirectSendTabProps {
  initialAddress: string;
  sourceSubaddressIndex?: number;
  outputs: any[];
  contacts?: { name: string; address: string }[];
  onRequirePassword: (action: () => Promise<void>) => void;
  onClose: () => void;
}

export function DirectSendTab({
  initialAddress,
  sourceSubaddressIndex,
  outputs,
  contacts = [],
  onRequirePassword,
  onClose,
}: DirectSendTabProps) {
  const {
    sendXmr, sendMulti, getFeeEstimates, isSending, balance,
    selectedAccountIndex,
    deepLinkData, clearDeepLinkData
  } = useVault();

  const [sendMode, setSendMode] = useState<'single' | 'multi'>('single');
  const [destAddr, setDestAddr] = useState(initialAddress);
  const [showContacts, setShowContacts] = useState(false);
  const [contactSearch, setContactSearch] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [multiText, setMultiText] = useState('');
  const [isBanned, setIsBanned] = useState(false);
  const [directSent, setDirectSent] = useState(false);
  const [directTxHash, setDirectTxHash] = useState('');
  const [priority, setPriority] = useState(0); // 0 = AUTO (Normal x4)
  const [feeEstimates, setFeeEstimates] = useState<Record<number, string>>({});
  const { stats } = useStats();

  // --- Coin Control ---
  const [showCoinControl, setShowCoinControl] = useState(sourceSubaddressIndex !== undefined);
  const [selectedOutputs, setSelectedOutputs] = useState<Set<string>>(new Set());
  const availableOutputs = outputs.filter((o: any) => o.isUnlocked);

  // --- xmr.bio Resolver ---
  const [bioProfile, setBioProfile] = useState<any>(null);
  const [isResolvingBio, setIsResolvingBio] = useState(false);
  const [bioError, setBioError] = useState('');
  const resolveBioRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (sendMode !== 'single') {
      setBioProfile(null);
      setBioError('');
      return;
    }

    const val = destAddr.trim();
    if (val.length > 0 && val.length < 50 && !val.includes(' ') && !/^[48]/.test(val)) {
      if (resolveBioRef.current) clearTimeout(resolveBioRef.current);

      setIsResolvingBio(true);
      setBioError('');
      setBioProfile(null);

      const handle = val.startsWith('@') ? val.substring(1) : val;

      resolveBioRef.current = setTimeout(async () => {
        try {
          // Routed through the uplink so resolving an @handle doesn't leak the
          // user's IP (or who they're paying) to xmr.bio over clearnet.
          const body = await window.api.proxiedGet(`https://api.xmr.bio/${handle}`);
          const data = JSON.parse(body);
          if (data && data.address) {
            setBioProfile(data);
          } else {
            setBioError('No address found for this user.');
          }
        } catch (e) {
          setBioError('User not found on xmr.bio');
        } finally {
          setIsResolvingBio(false);
        }
      }, 600);
    } else {
      setBioProfile(null);
      setBioError('');
      setIsResolvingBio(false);
      if (resolveBioRef.current) clearTimeout(resolveBioRef.current);
    }
  }, [destAddr, sendMode]);

  // 🔗 Consume Deep Link Data
  useEffect(() => {
    if (deepLinkData) {
      if (deepLinkData.address) setDestAddr(deepLinkData.address);
      if (deepLinkData.amount) setSendAmount(deepLinkData.amount);
      // Switch to single mode for standard monero: links
      setSendMode('single');
      clearDeepLinkData();
    }
  }, [deepLinkData, clearDeepLinkData]);

  // Ban check — routed through the uplink so the payee address isn't sent to a
  // clearnet server (which would reveal who you're paying) while on Tor.
  useEffect(() => {
    if (sendMode === 'single' && destAddr.length > 30) {
      window.api.proxiedGet(`https://api.kyc.rip/v1/tools/ban-list?address=${destAddr}`)
        .then((body: string) => { const data = JSON.parse(body); setIsBanned(data.results && data.results.length > 0); })
        .catch(() => setIsBanned(false));
    } else setIsBanned(false);
  }, [destAddr, sendMode]);

  const parsed = sendMode === 'multi' ? parseMultiSend(multiText) : { destinations: [], errors: [] };
  const multiTotal = parsed.destinations.reduce((sum, d) => sum + d.amount, 0);

  const toggleOutput = (keyImage: string) => {
    setSelectedOutputs((prev) => {
      const next = new Set(prev);
      next.has(keyImage) ? next.delete(keyImage) : next.add(keyImage);
      return next;
    });
  };

  const isFetchingFees = useRef(false);
  useEffect(() => {
    let timer: NodeJS.Timeout;
    const fetchFees = async () => {
      if (isFetchingFees.current) return;
      isFetchingFees.current = true;
      try {
        const result = await getFeeEstimates();
        if (result && result.fees) {
          const mapped: Record<number, string> = {
            1: result.fees[0],
            0: result.fees[1],
            2: result.fees[1],
            3: result.fees[2],
            4: result.fees[3]
          };
          setFeeEstimates(mapped);
        }
      } catch (e) {
        console.warn('[DirectSend] Fee estimate failed:', e);
      } finally {
        isFetchingFees.current = false;
        timer = setTimeout(fetchFees, 10000);
      }
    };
    fetchFees();
    return () => clearTimeout(timer);
  }, [getFeeEstimates]);

  const selectedTotal = availableOutputs
    .filter((o: any) => selectedOutputs.has(o.keyImage))
    .reduce((sum: number, o: any) => sum + parseFloat(o.amount || '0'), 0);

  const handleExecute = () => {
    if (sendMode === 'single') {
      const amount = parseFloat(sendAmount);
      if (!destAddr || isNaN(amount) || amount <= 0 || isBanned) return;

      // 🛡️ PROACTIVE BALANCE CHECK
      const unlocked = parseFloat(balance.unlocked);
      if (amount > unlocked) {
        alert(`INSUFFICIENT_FUNDS: Unlocked balance is ${balance.unlocked} XMR, but you requested ${amount} XMR.`);
        return;
      }

      onRequirePassword(async () => {
        try {
          const subIndices =
            selectedOutputs.size > 0 && sourceSubaddressIndex !== undefined ? [sourceSubaddressIndex] : undefined;

          let txHash: string | undefined;
          if (subIndices) {
            txHash = await sendMulti([{ address: destAddr, amount }], subIndices, priority);
          } else {
            txHash = await sendXmr(destAddr, amount, selectedAccountIndex, priority);
          }

          if (txHash) {
            setDirectTxHash(txHash);
            setDirectSent(true);
          }
        } catch (err: any) {
          // Error already logged by VaultContext
        }
      });
    } else {
      if (parsed.destinations.length === 0 || parsed.errors.length > 0) return;

      // 🛡️ PROACTIVE BALANCE CHECK (MULTI)
      const unlocked = parseFloat(balance.unlocked);
      if (multiTotal > unlocked) {
        alert(`INSUFFICIENT_FUNDS: Total amount ${multiTotal.toFixed(6)} XMR exceeds unlocked balance ${balance.unlocked} XMR.`);
        return;
      }

      onRequirePassword(async () => {
        try {
          const subIndices = sourceSubaddressIndex !== undefined ? [sourceSubaddressIndex] : undefined;
          const txHash = await sendMulti(parsed.destinations, subIndices, priority);
          if (txHash) {
            setDirectTxHash(txHash);
            setDirectSent(true);
          }
        } catch (err: any) {
          // Error already logged by VaultContext
        }
      });
    }
  };

  const handleSweepAll = () => {
    if (!destAddr || isBanned) return;
    const unlocked = parseFloat(balance.unlocked);
    if (unlocked <= 0) {
      alert("No unlocked funds to sweep.");
      return;
    }

    if (!confirm(`SWEEP_ALL: This will extinguish ALL funds (~${unlocked.toFixed(6)} XMR) from Account #${selectedAccountIndex} and send them to ${destAddr}. Proceed?`)) {
      return;
    }

    onRequirePassword(async () => {
      try {
        const txHashList = await WalletService.sweepAll(destAddr, selectedAccountIndex, priority);
        if (txHashList && txHashList.length > 0) {
          setDirectTxHash(txHashList[0]);
          setDirectSent(true);
        } else {
          throw new Error("No transaction hash returned from sweep.");
        }
      } catch (err: any) {
        alert(`SWEEP_ERROR: ${err.message}`);
      }
    });
  };

  if (directSent) {
    return (
      <div className="py-12 flex flex-col items-center gap-4 text-center">
        <CheckCircle2 size={48} className="text-xmr-green" />
        <div className="text-sm uppercase text-xmr-green font-black">Transaction Dispatched</div>

        {directTxHash && (
          <div className="space-y-3 flex flex-col items-center">
            <div className="bg-black/20 p-3 border border-xmr-border/30 flex items-center gap-3">
              <div className="text-[11px] font-mono text-xmr-green break-all max-w-[280px]">
                {directTxHash}
              </div>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(directTxHash);
                  // alert could be replaced with a toast but we'll stick to a simple copy for now
                }}
                className="text-xmr-dim hover:text-xmr-green transition-colors cursor-pointer"
                title="Copy TXID"
              >
                <Copy size={16} />
              </button>
            </div>
          </div>
        )}

        {sendMode === 'multi' && (
          <div className="text-[11px] text-xmr-dim">
            {parsed.destinations.length} recipients • {multiTotal.toFixed(4)} XMR total
          </div>
        )}

        <button
          onClick={onClose}
          className="mt-4 px-8 py-2.5 bg-xmr-green text-xmr-base text-xs font-black uppercase tracking-widest cursor-pointer hover:bg-xmr-green/80 transition-all"
        >
          Close
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Mode Toggle */}
      <div className="flex gap-2">
        {(['single', 'multi'] as const).map((m) => (
          <button
            key={m}
            onClick={() => setSendMode(m)}
            className={`flex-1 py-1.5 text-xs font-black uppercase tracking-widest border transition-all cursor-pointer ${
              sendMode === m
                ? 'border-xmr-accent text-xmr-accent bg-xmr-accent/5'
                : 'border-xmr-border text-xmr-dim hover:border-xmr-accent/50'
            }`}
          >
            {m === 'single' ? 'Single Send' : 'Multi-Send'}
          </button>
        ))}
      </div>

      {sendMode === 'single' ? (
        <>
          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
                <Wallet size={10} /> Destination
                {isResolvingBio && <Loader2 size={10} className="animate-spin text-xmr-accent ml-1" />}
              </label>
              <div className="flex items-center gap-2">
                {isBanned && <span className="text-xs text-xmr-error animate-pulse uppercase">Intercepted</span>}
                {contacts.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setShowContacts(v => !v)}
                    className="text-[10px] font-black uppercase tracking-widest text-xmr-accent hover:text-xmr-green transition-colors cursor-pointer flex items-center gap-1"
                  >
                    Contacts <ChevronDown size={10} className={`transition-transform ${showContacts ? 'rotate-180' : ''}`} />
                  </button>
                )}
              </div>
            </div>
            <input
              type="text"
              value={destAddr}
              onChange={(e) => setDestAddr(e.target.value)}
              placeholder="4... / 8... / @xbtoshi"
              className={`w-full bg-xmr-base border p-3 text-xs text-xmr-green focus:border-xmr-accent outline-none transition-colors ${
                isBanned ? 'border-xmr-error' : 'border-xmr-border'
              }`}
            />

            {/* Contact picker — fill the destination from the address book.
                Searchable so it scales to a large address book without a drawer. */}
            {showContacts && contacts.length > 0 && (() => {
              const q = contactSearch.trim().toLowerCase();
              const filtered = q
                ? contacts.filter(c => c.name.toLowerCase().includes(q) || c.address.toLowerCase().includes(q))
                : contacts;
              return (
                <div className="mt-1 border border-xmr-border/40 bg-xmr-surface/50 animate-in fade-in slide-in-from-top-1">
                  {contacts.length > 6 && (
                    <input
                      autoFocus
                      value={contactSearch}
                      onChange={(e) => setContactSearch(e.target.value)}
                      placeholder="Search contacts…"
                      className="w-full bg-xmr-base border-b border-xmr-border/40 px-3 py-2 text-[11px] text-xmr-green placeholder:text-xmr-dim/40 focus:outline-none"
                    />
                  )}
                  <div className="max-h-44 overflow-y-auto divide-y divide-xmr-border/20">
                    {filtered.length === 0 ? (
                      <div className="px-3 py-3 text-[10px] text-xmr-dim/60 uppercase tracking-widest text-center">No matches</div>
                    ) : filtered.map((c, i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() => { setDestAddr(c.address); setShowContacts(false); setContactSearch(''); }}
                        className="w-full flex flex-col items-start px-3 py-2 hover:bg-xmr-green/10 transition-colors cursor-pointer text-left"
                      >
                        <span className="text-xs font-black text-xmr-green uppercase">{c.name}</span>
                        <code className="text-[10px] opacity-40 truncate w-full">{c.address}</code>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* xmr.bio Profile Card */}
            {bioProfile && (
              <div className="mt-2 p-3 border border-xmr-green/30 bg-xmr-green/5 flex flex-col gap-3 animate-in fade-in slide-in-from-top-2">
                <div className="flex justify-between items-start">
                  <div className="flex items-center gap-3">
                    {bioProfile.avatar && (
                      <img
                        src={bioProfile.avatar}
                        alt="Avatar"
                        className="w-10 h-10 rounded-sm bg-black object-cover border border-xmr-green/30"
                      />
                    )}
                    <div>
                      <div className="text-xs font-black text-xmr-green flex items-center gap-2">
                        {bioProfile.display_name}
                      </div>
                      <div className="text-[10px] text-xmr-dim uppercase font-mono tracking-widest">
                        @{bioProfile.handle}
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setDestAddr(bioProfile.address);
                      setBioProfile(null);
                    }}
                    className="px-3 py-1.5 bg-xmr-green text-xmr-base text-[10px] font-black uppercase hover:bg-xmr-green/80 transition-colors cursor-pointer"
                  >
                    Use_Address
                  </button>
                </div>
                {bioProfile.bio && (
                  <div className="text-[10px] text-xmr-green/80 italic font-mono border-l-2 border-xmr-green/50 pl-2 leading-relaxed">
                    {bioProfile.bio}
                  </div>
                )}
              </div>
            )}
          </div>
          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
                <DollarSign size={10} /> Amount (XMR)
              </label>
              <div className="text-[10px] font-black text-xmr-green/60 uppercase tracking-widest">
                Unlocked: {balance.unlocked} XMR
              </div>
            </div>
            <div className="relative group">
              <input
                type="number"
                min="0"
                value={sendAmount}
                onChange={(e) => {
                  const val = e.target.value;
                  if (parseFloat(val) < 0) return;
                  setSendAmount(val);
                }}
                placeholder="0.00"
                className="w-full bg-xmr-base border border-xmr-border p-3 text-2xl font-black text-xmr-accent focus:border-xmr-accent outline-none pr-24"
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                <button
                  onClick={handleSweepAll}
                  className="px-2 py-1 bg-xmr-green/10 text-xmr-green text-[9px] font-black uppercase border border-xmr-green/30 hover:bg-xmr-green hover:text-xmr-base transition-all cursor-pointer"
                >
                  Sweep_All
                </button>
              </div>
            </div>

            {/* Live USD equivalent of the entered amount (same street price the fee uses) */}
            {(() => {
              const amt = parseFloat(sendAmount);
              const streetPrice = parseFloat((stats?.price?.street || '0').replace(/[$,]/g, ''));
              if (!isFinite(amt) || amt <= 0 || !streetPrice) return null;
              return (
                <div className="mt-1 text-[11px] text-xmr-dim font-mono">
                  ≈ ${(amt * streetPrice).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })} USD
                </div>
              );
            })()}

            {/* Percentage Slider / Quick Select */}
            <div className="grid grid-cols-4 gap-1 mt-2">
              {[25, 50, 75, 100].map(pct => (
                <button
                  key={pct}
                  onClick={() => {
                    const unlocked = parseFloat(balance.unlocked);
                    if (unlocked > 0) {
                      if (pct === 100) {
                        // For 100% selection in the UI, we subtract a small fee buffer 
                        // but ensure it never goes below zero.
                        // Note: Users should use the 'Sweep_All' button for percision.
                        setSendAmount(Math.max(0, unlocked - 0.0001).toFixed(6));
                      } else {
                        setSendAmount((unlocked * (pct / 100)).toFixed(6));
                      }
                    }
                  }}
                  className="py-1.5 bg-xmr-surface/50 border border-xmr-border/30 text-[9px] text-xmr-dim font-black uppercase hover:border-xmr-accent hover:text-xmr-accent transition-all cursor-pointer"
                >
                  {pct}%
                </button>
              ))}
            </div>
          </div>
        </>
      ) : (
        <div className="space-y-1.5">
          <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
            <Send size={10} /> Recipients (address, amount per line)
          </label>
          <textarea
            value={multiText}
            onChange={(e) => setMultiText(e.target.value)}
            placeholder={'4...address1, 0.5\n8...address2, 1.2\n4...address3, 0.05'}
            rows={5}
            className="w-full bg-xmr-base border border-xmr-border p-3 text-xs text-xmr-green focus:border-xmr-accent outline-none font-mono resize-y"
          />
          {parsed.destinations.length > 0 && (
            <div className="flex justify-between text-xs uppercase">
              <span className="text-xmr-green">{parsed.destinations.length} recipient(s)</span>
              <span className="text-xmr-accent">Total: {multiTotal.toFixed(6)} XMR</span>
            </div>
          )}
          {parsed.errors.length > 0 && (
            <div className="text-xs text-xmr-error space-y-0.5">
              {parsed.errors.map((e, i) => (
                <div key={i}>{e}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Fee Priority Selection (CakeWallet Style) ── */}
      <div className="space-y-2">
        <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5 px-1">
          <Coins size={10} /> Network_Fee_Priority
        </label>
        <div className="grid grid-cols-5 gap-1 bg-xmr-surface/30 p-1 border border-xmr-border/30 rounded-sm">
          {[
            { label: 'Slow', val: 1 },
            { label: 'Auto', val: 0 },
            { label: 'Med', val: 2 },
            { label: 'Fast', val: 3 },
            { label: 'Urgent', val: 4 }
          ].map((lvl) => {
            const xmrFee = feeEstimates[lvl.val];
            const streetPriceStr = stats?.price?.street || '0';
            const streetPrice = parseFloat(streetPriceStr.replace(/[$,]/g, ''));
            // get_fee_estimate is per-byte. Average tx is ~3000 bytes.
            const usdFee = xmrFee && streetPrice ? (parseFloat(xmrFee) * streetPrice * 3000).toFixed(4) : null;

            return (
              <button
                key={lvl.val}
                onClick={() => setPriority(lvl.val)}
                className={`h-[42px] px-1 flex flex-col items-center justify-center transition-all cursor-pointer rounded-sm ${priority === lvl.val
                  ? 'bg-xmr-accent text-xmr-base'
                  : 'text-xmr-dim hover:text-xmr-green hover:bg-xmr-green/5'
                  }`}
              >
                <span className="text-[10px] font-black uppercase">{lvl.label}</span>
                {usdFee && (
                  <span className={`text-[10px] font-mono mt-0.5 font-bold ${priority === lvl.val ? 'text-xmr-base' : 'text-xmr-green/80'}`}>
                    ${usdFee}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Advanced Coin Control ── */}
      <div className="border border-xmr-border/30 rounded-sm overflow-hidden">
        <button
          onClick={() => setShowCoinControl(!showCoinControl)}
          className="w-full flex items-center justify-between px-3 py-2 text-xs text-xmr-dim uppercase tracking-widest hover:bg-xmr-green/5 transition-colors cursor-pointer"
        >
          <span className="flex items-center gap-1.5">
            <Coins size={10} /> Coin Control {selectedOutputs.size > 0 && `(${selectedOutputs.size} selected)`}
          </span>
          {showCoinControl ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
        </button>
        {showCoinControl && (
          <div className="border-t border-xmr-border/20 max-h-[150px] overflow-y-auto custom-scrollbar">
            {availableOutputs.length === 0 ? (
              <div className="px-3 py-4 text-xs text-xmr-dim text-center uppercase">
                No unlocked outputs available
              </div>
            ) : (
              <table className="w-full text-xs">
                <tbody>
                  {availableOutputs.map((o: any, i: number) => (
                    <tr
                      key={i}
                      onClick={() => toggleOutput(o.keyImage)}
                      className={`cursor-pointer transition-colors ${
                        selectedOutputs.has(o.keyImage) ? 'bg-xmr-accent/10' : 'hover:bg-xmr-green/5'
                      }`}
                    >
                      <td className="px-3 py-1.5 w-6">
                        <div
                          className={`w-3 h-3 border rounded-sm flex items-center justify-center ${
                            selectedOutputs.has(o.keyImage)
                              ? 'bg-xmr-accent border-xmr-accent'
                              : 'border-xmr-border'
                          }`}
                        >
                          {selectedOutputs.has(o.keyImage) && <CheckCircle2 size={8} className="text-xmr-base" />}
                        </div>
                      </td>
                      <td className="px-1 py-1.5 text-xmr-green font-black">{o.amount} XMR</td>
                      <td className="px-1 py-1.5 text-xmr-dim font-mono opacity-40">
                        {o.keyImage?.substring(0, 16)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {selectedOutputs.size > 0 && (
              <div className="px-3 py-1.5 border-t border-xmr-border/20 text-xs flex justify-between text-xmr-accent uppercase">
                <span>Selected: {selectedOutputs.size} coins</span>
                <span>{selectedTotal.toFixed(6)} XMR</span>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="flex justify-end pt-2">
        <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            window.api.openExternal('https://xmr.bio');
          }}
          className="text-[10px] text-xmr-dim hover:text-xmr-green underline transition-colors font-black tracking-widest"
        >
          CLAIM_XMR_BIO_PAGE
        </a>
      </div>

      <button
        disabled={
          isSending ||
          (sendMode === 'single'
            ? isBanned || !destAddr || !sendAmount
            : parsed.destinations.length === 0 || parsed.errors.length > 0)
        }
        onClick={handleExecute}
        className={`w-full py-4 font-black uppercase tracking-[0.3em] transition-all flex items-center justify-center gap-3 mt-2 cursor-pointer ${
          isBanned && sendMode === 'single'
            ? 'bg-xmr-error/10 text-xmr-error cursor-not-allowed'
            : 'bg-xmr-accent text-xmr-base hover:bg-xmr-green hover:text-xmr-base disabled:opacity-50 disabled:cursor-not-allowed'
        }`}
      >
        <Send size={18} />
        {isSending
          ? 'Dispatching...'
          : isBanned && sendMode === 'single'
          ? 'Mission_Aborted'
          : sendMode === 'multi'
          ? `Dispatch ${parsed.destinations.length} Transfers`
          : 'Confirm_Dispatch'}
      </button>
    </div>
  );
}
