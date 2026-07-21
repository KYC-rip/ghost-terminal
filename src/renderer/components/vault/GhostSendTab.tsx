import { useState, useEffect, useRef } from 'react';
import { Ghost, ArrowRight, DollarSign, Loader2, CheckCircle2, AlertTriangle, Wallet, RefreshCw } from 'lucide-react';
import { useVault } from '../../contexts/VaultContext';
import { useStats } from '../../hooks/useStats';
import { CurrencySelector } from '../CurrencySelector';
import { ComplianceSelector } from '../ComplianceSelector';
import { useCurrencies, Currency } from '../../hooks/useCurrencies';
import {
  fetchQuote,
  createTrade,
  getTradeStatus,
  ExchangeQuote,
  ExchangeResponse,
  type ComplianceState,
} from '../../services/swap';
import { useAddressValidator } from '../../hooks/useAddressValidator';

type GhostPhase = 'configure' | 'quoting' | 'quoted' | 'creating' | 'sending' | 'tracking' | 'complete' | 'error';

interface GhostSendTabProps {
  onRequirePassword: (action: () => Promise<void>) => void;
  onClose: () => void;
}

export function GhostSendTab({ onRequirePassword, onClose }: GhostSendTabProps) {
  const { sendXmr, getFeeEstimates, balance, selectedAccountIndex } = useVault();
  const { stats } = useStats();
  const { currencies } = useCurrencies();

  const [ghostCurrency, setGhostCurrency] = useState<Currency | null>(null);
  const [ghostReceiverAddr, setGhostReceiverAddr] = useState('');
  const [ghostTargetAmount, setGhostTargetAmount] = useState('');
  const [quote, setQuote] = useState<ExchangeQuote | null>(null);
  const [ghostPhase, setGhostPhase] = useState<GhostPhase>('configure');
  const [tradeResponse, setTradeResponse] = useState<ExchangeResponse | null>(null);
  const [tradeStatus, setTradeStatus] = useState('');
  const [ghostError, setGhostError] = useState('');
  const [compliance, setCompliance] = useState<ComplianceState>({ kyc: 'STANDARD', log: 'STANDARD' });
  const [priority, setPriority] = useState(0);
  const [feeEstimates, setFeeEstimates] = useState<Record<number, string>>({});
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const {
    isValid: isGhostAddrValid,
    isValidating: isGhostAddrValidating,
    error: ghostAddrError,
  } = useAddressValidator(ghostCurrency?.ticker || '', ghostCurrency?.network || 'Mainnet', ghostReceiverAddr);

  // Default ghost currency
  useEffect(() => {
    if (currencies.length > 0 && !ghostCurrency)
      setGhostCurrency(currencies.find((c) => c.ticker === 'usdt' && c.network === 'TRC20') || currencies[0]);
  }, [currencies, ghostCurrency]);

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
        // silent fail
      } finally {
        isFetchingFees.current = false;
        timer = setTimeout(fetchFees, 10000);
      }
    };
    fetchFees();
    return () => clearTimeout(timer);
  }, [getFeeEstimates]);

  useEffect(
    () => () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    },
    []
  );

  const handleGetQuote = async () => {
    if (!ghostCurrency || !ghostTargetAmount || parseFloat(ghostTargetAmount) <= 0) return;
    setGhostPhase('quoting');
    setGhostError('');
    try {
      const q = await fetchQuote(
        'xmr',
        'Mainnet',
        ghostCurrency.ticker,
        ghostCurrency.network || 'Mainnet',
        parseFloat(ghostTargetAmount),
        true, // isReverse: true
        compliance.kyc,
        compliance.log
      );
      setQuote(q);
      setGhostPhase('quoted');
    } catch (e: any) {
      setGhostError(e.message || 'Quote failed');
      setGhostPhase('error');
    }
  };

  const handleGhostExecute = () => {
    if (!quote || !ghostCurrency || !ghostReceiverAddr) return;

    // 🛡️ PROACTIVE BALANCE CHECK
    const amountToSpend = quote.amount_from;
    const unlocked = parseFloat(balance.unlocked);

    if (amountToSpend > unlocked) {
      alert(`INSUFFICIENT_FUNDS: Swap requires ${amountToSpend} XMR, but unlocked balance is ${balance.unlocked} XMR.`);
      return;
    }

    onRequirePassword(async () => {
      setGhostPhase('creating');
      setGhostError('');
      try {
        const route = quote.routes?.[0];
        const trade = await createTrade({
          id: quote.id,
          amountFrom: quote.amount_from,
          amountTo: quote.amount_to,
          fromTicker: 'xmr',
          fromNetwork: 'Mainnet',
          toTicker: ghostCurrency!.ticker,
          toNetwork: ghostCurrency!.network || 'Mainnet',
          destinationAddress: ghostReceiverAddr,
          provider: route?.provider || quote.provider,
          engine: route?.engine || quote.engine,
          source: 'ghost',
        });
        setTradeResponse(trade);
        setGhostPhase('sending');

        const depositAddr = trade.deposit_address || trade.address_provider;
        const depositAmt = trade.deposit_amount || trade.amount_from;

        // sendXmr is now guaranteed to throw on failure or return txHash
        const txHash = await sendXmr(depositAddr, depositAmt, selectedAccountIndex, priority);
        if (!txHash) throw new Error("TRANSACTION_FAILED: No hash returned.");

        // Save trade persistence for ledger tracking
        const tradeId = trade.trade_id || trade.id || '';
        if (tradeId && txHash) {
          (window as any).api.saveGhostTrade(txHash, tradeId);
        }

        setGhostPhase('tracking');
        setTradeStatus('WAITING');
        pollingRef.current = setInterval(async () => {
          try {
            const status = await getTradeStatus(tradeId);
            const s = (status as any)?.status?.toUpperCase() || 'WAITING';
            setTradeStatus(s);
            if (['FINISHED', 'COMPLETE', 'COMPLETED'].includes(s)) {
              setGhostPhase('complete');
              if (pollingRef.current) clearInterval(pollingRef.current);
            } else if (['FAILED', 'REFUNDED', 'EXPIRED'].includes(s)) {
              setGhostError(`Trade ${s.toLowerCase()}`);
              setGhostPhase('error');
              if (pollingRef.current) clearInterval(pollingRef.current);
            }
          } catch (e) {
            console.warn('[GhostSend] Poll failed, retrying:', e);
          }
        }, 10000);
      } catch (e: any) {
        setGhostError(e.message || 'Ghost send failed');
        setGhostPhase('error');
      }
    });
  };

  const resetGhost = () => {
    setGhostPhase('configure');
    setQuote(null);
    setTradeResponse(null);
    setTradeStatus('');
    setGhostError('');
    if (pollingRef.current) clearInterval(pollingRef.current);
  };

  return (
    <>
      {ghostPhase === 'configure' && (
        <div className="space-y-4">
          <div className="bg-xmr-green/5 border border-xmr-green/20 p-3 text-[11px] text-xmr-green/80 uppercase tracking-wider">
            You send XMR • Receiver gets their chosen asset • No identity link
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
              <Ghost size={10} /> Receiver's Asset
            </label>
            {ghostCurrency && (
              <CurrencySelector selected={ghostCurrency} onSelect={setGhostCurrency} label="" currencies={currencies} variant="drawer" drawerTitle="Receiver's Asset" />
            )}
          </div>

          <div className="space-y-1.5">
            <div className="flex justify-between items-center">
              <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
                <Wallet size={10} /> Receiver's Address
                {isGhostAddrValidating && <Loader2 size={10} className="animate-spin text-xmr-accent ml-1" />}
              </label>
              {ghostReceiverAddr.length > 0 && !isGhostAddrValidating && (
                <span
                  className={`text-xs uppercase tracking-widest ${isGhostAddrValid ? 'text-xmr-green' : 'text-xmr-error animate-pulse'
                    }`}
                >
                  {isGhostAddrValid ? 'Valid Format' : ghostAddrError || 'Invalid Format'}
                </span>
              )}
            </div>
            <input
              type="text"
              value={ghostReceiverAddr}
              onChange={(e) => setGhostReceiverAddr(e.target.value)}
              placeholder={`${ghostCurrency?.ticker.toUpperCase() || 'Asset'} address`}
              className={`w-full bg-xmr-base border p-3 text-xs text-xmr-green focus:border-xmr-accent outline-none transition-colors ${ghostReceiverAddr.length > 0 && isGhostAddrValid === false ? 'border-xmr-error' : 'border-xmr-border'
                }`}
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5">
              <DollarSign size={10} /> {ghostCurrency?.ticker.toUpperCase() || 'Asset'} to Receive
            </label>
            <input
              type="number"
              value={ghostTargetAmount}
              onChange={(e) => setGhostTargetAmount(e.target.value)}
              placeholder="0.00"
              className="w-full bg-xmr-base border border-xmr-border p-3 text-2xl font-black text-xmr-accent focus:border-xmr-accent outline-none"
            />
          </div>

          <ComplianceSelector value={compliance} onChange={setCompliance} variant="ghost" />

          {/* Fee Priority Selection */}
          <div className="space-y-1.5">
            <label className="text-[11px] text-xmr-dim uppercase tracking-widest flex items-center gap-1.5 px-0.5">
              <RefreshCw size={10} /> Network_Fee_Priority
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

          <button
            disabled={
              !ghostReceiverAddr ||
              !ghostTargetAmount ||
              parseFloat(ghostTargetAmount) <= 0 ||
              isGhostAddrValid === false
            }
            onClick={handleGetQuote}
            className="w-full py-3 bg-xmr-accent/20 border border-xmr-accent/40 text-xmr-accent font-black uppercase tracking-widest text-xs transition-all hover:bg-xmr-accent/30 disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center justify-center gap-2"
          >
            <ArrowRight size={14} /> Get Quote
          </button>
        </div>
      )}

      {ghostPhase === 'quoting' && (
        <div className="py-16 flex flex-col items-center gap-3 text-xmr-accent/60 animate-pulse">
          <Loader2 size={32} className="animate-spin" />
          <span className="text-[11px] uppercase font-mono tracking-widest">Fetching best rate...</span>
        </div>
      )}

      {ghostPhase === 'quoted' && quote && (
        <div className="space-y-5">
          <div className="bg-xmr-base border border-xmr-border p-4 space-y-3">
            <div className="text-[11px] text-xmr-dim uppercase tracking-widest">Quote Summary</div>
            <div className="flex items-center justify-between">
              <div>
                <div className="text-lg font-black text-xmr-accent">{Number(quote.amount_from || 0).toFixed(6)} XMR</div>
                <div className="text-xs text-xmr-dim uppercase">You send</div>
              </div>
              <ArrowRight size={20} className="text-xmr-dim" />
              <div className="text-right">
                <div className="text-lg font-black text-xmr-green">
                  {Number(quote.amount_to || ghostTargetAmount).toFixed(6)} {ghostCurrency?.ticker.toUpperCase()}
                </div>
                <div className="text-xs text-xmr-dim uppercase">Receiver gets</div>
              </div>
            </div>
            <div className="flex justify-between text-xs text-xmr-dim uppercase pt-2 border-t border-xmr-border/20">
              <span>Provider: {quote.routes?.[0]?.provider || quote.provider}</span>
              <span>ETA: ~{quote.eta || quote.routes?.[0]?.eta || '?'} min</span>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={resetGhost}
              className="flex-1 py-3 border border-xmr-border text-xmr-dim font-black uppercase tracking-widest text-[11px] cursor-pointer hover:border-xmr-accent transition-colors"
            >
              Revise
            </button>
            <button
              onClick={handleGhostExecute}
              className="flex-1 py-3 bg-xmr-accent text-xmr-base font-black uppercase tracking-widest text-[11px] cursor-pointer hover:bg-xmr-green transition-colors flex items-center justify-center gap-2"
            >
              <Ghost size={14} /> Execute Ghost Send
            </button>
          </div>
        </div>
      )}

      {(ghostPhase === 'creating' || ghostPhase === 'sending') && (
        <div className="py-16 flex flex-col items-center gap-4 text-xmr-accent/60">
          <Loader2 size={32} className="animate-spin" />
          <span className="text-[11px] uppercase font-mono tracking-widest animate-pulse">
            {ghostPhase === 'creating' ? 'Creating trade...' : 'Dispatching XMR to relay...'}
          </span>
        </div>
      )}

      {ghostPhase === 'tracking' && (
        <div className="py-8 flex flex-col items-center gap-4">
          <RefreshCw size={32} className="text-xmr-accent animate-spin" />
          <div className="text-sm uppercase text-xmr-accent font-black">Ghost Protocol Active</div>
          <div className="text-[11px] text-xmr-dim uppercase tracking-widest">
            Status: <span className="text-xmr-green">{tradeStatus}</span>
          </div>
          {tradeResponse && (
            <div className="w-full bg-xmr-base border border-xmr-border p-3 mt-2 text-xs font-mono text-xmr-dim space-y-1">
              <div>
                Trade ID: <span className="text-xmr-green">{tradeResponse.trade_id || tradeResponse.id}</span>
              </div>
              <div>
                Deposit:{' '}
                <span className="text-xmr-green">
                  {tradeResponse.deposit_amount || tradeResponse.amount_from} XMR
                </span>
              </div>
              <div>
                Receiving:{' '}
                <span className="text-xmr-green">
                  {tradeResponse.amount_to} {tradeResponse.ticker_to?.toUpperCase()}
                </span>
              </div>
            </div>
          )}
          <div className="text-xs text-xmr-dim opacity-50 uppercase">Polling every 10s...</div>
          <div
            onClick={() => {
              const url = `https://kyc.rip/swap?id=${tradeResponse?.trade_id || tradeResponse?.id}`;
              (window as any).api.openExternal(url, { width: 940, height: 820 });
            }}
            className="text-[10px] text-xmr-accent hover:text-xmr-green underline uppercase tracking-tighter mt-2 cursor-pointer"
          >
            External_Status_Tracker
          </div>
        </div>
      )}

      {ghostPhase === 'complete' && (
        <div className="py-12 flex flex-col items-center gap-4 text-center">
          <CheckCircle2 size={48} className="text-xmr-green" />
          <div className="text-sm uppercase text-xmr-green font-black">Ghost Send Complete</div>
          <div className="text-[11px] text-xmr-dim uppercase">
            {tradeResponse?.amount_to || ghostTargetAmount} {tradeResponse?.ticker_to?.toUpperCase()} delivered
          </div>
          <div
            onClick={() => {
              const url = `https://kyc.rip/swap?id=${tradeResponse?.trade_id || tradeResponse?.id}`;
              (window as any).api.openExternal(url, { width: 940, height: 820 });
            }}
            className="text-[10px] text-xmr-accent hover:text-xmr-green underline uppercase tracking-tighter cursor-pointer"
          >
            View_On_KYC.RIP
          </div>
          <button
            onClick={onClose}
            className="mt-4 px-6 py-2 bg-xmr-green text-xmr-base text-xs uppercase tracking-widest cursor-pointer"
          >
            Close
          </button>
        </div>
      )}

      {ghostPhase === 'error' && (
        <div className="py-12 flex flex-col items-center gap-4 text-center">
          <AlertTriangle size={48} className="text-xmr-error" />
          <div className="text-sm uppercase text-xmr-error font-black">Ghost Send Failed</div>
          <div className="text-[11px] text-xmr-dim">{ghostError}</div>
          <button
            onClick={resetGhost}
            className="mt-4 px-6 py-2 border border-xmr-border text-xmr-dim text-xs uppercase tracking-widest cursor-pointer hover:border-xmr-accent"
          >
            Retry
          </button>
        </div>
      )}
    </>
  );
}
