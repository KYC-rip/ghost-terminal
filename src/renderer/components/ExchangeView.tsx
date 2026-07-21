/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect, useRef, useMemo, Fragment } from 'react';
import { Ghost, ArrowDown, ArrowRight, ArrowUpDown, Zap, Shield, RefreshCw, AlertCircle, Copy, Check, X, Radio, CheckCircle2, Loader2, ChevronRight, Clock, Server } from 'lucide-react';
import { CurrencySelector } from './CurrencySelector';
import { Card } from './Card';
import { AddressDisplay } from './common/AddressDisplay';
import { ComplianceSelector } from './ComplianceSelector';
import { useCurrencies, type Currency } from '../hooks/useCurrencies';
import {
  fetchQuote, createTrade, getTradeStatus,
  fetchBridgeEstimateV2, createBridgeTradeV2, fetchBridgeStatusV2,
  type ExchangeQuote, type ExchangeRoute, type ComplianceState,
  type BridgeEstimateV2, type BridgeRoute, type BridgeTradeV2,
} from '../services/swap';
import { useVault } from '../hooks/useVault';
import { getOrCreateSubaddress } from '../services/subaddressService';

interface ExchangeViewProps {
  localXmrAddress: string;
}

type ExchangeMode = 'swap' | 'ghost';
type ExchangeStep = 'config' | 'active' | 'completed';

interface LogLine {
  id: number;
  time: string;
  text: string;
  type: 'info' | 'success' | 'error' | 'warn';
}

// Unified route type — both swap ExchangeRoute and BridgeRoute share amount_to, eta, kyc, provider
type UnifiedRoute = (ExchangeRoute | BridgeRoute) & { [key: string]: any };

export function ExchangeView({ localXmrAddress }: ExchangeViewProps) {
  const { currencies } = useCurrencies();
  const { createSubaddress, subaddresses } = useVault();

  // ─── Mode ───
  const [mode, setMode] = useState<ExchangeMode>('swap');
  const isGhost = mode === 'ghost';
  const themeColor = isGhost ? 'xmr-ghost' : 'xmr-accent';
  const ThemeIcon = isGhost ? Ghost : Zap;

  // ─── Form state ───
  const [fromCoin, setFromCoin] = useState<Currency>(CurrencySelector.Monero);
  const [toCoin, setToCoin] = useState<Currency | null>(CurrencySelector.Bitcoin);
  const [amount, setAmount] = useState('');
  const [destAddress, setDestAddress] = useState('');
  const [memo, setMemo] = useState('');
  const [refundAddress, setRefundAddress] = useState('');
  const [compliance, setCompliance] = useState<ComplianceState>({ kyc: 'ANY', log: 'ANY' });

  // ─── Quote state (unified) ───
  const [routes, setRoutes] = useState<UnifiedRoute[]>([]);
  const [selectedRoute, setSelectedRoute] = useState<UnifiedRoute | null>(null);
  const [isQuoting, setIsQuoting] = useState(false);
  const [quoteError, setQuoteError] = useState('');
  // Swap-specific: keep quote ref for createTrade
  const [swapQuote, setSwapQuote] = useState<ExchangeQuote | null>(null);

  // ─── Trade state ───
  const [step, setStep] = useState<ExchangeStep>('config');
  const [isCreating, setIsCreating] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);

  // Swap-specific active trade
  const [activeTrade, setActiveTrade] = useState<any | null>(null);
  const [tradeStatus, setTradeStatus] = useState('WAITING');
  const [txOut, setTxOut] = useState<string | null>(null);

  // Ghost-specific active trades (multi-leg)
  const [ghostTrades, setGhostTrades] = useState<BridgeTradeV2[]>([]);

  // ─── Route drawer ───
  const [routeDrawerOpen, setRouteDrawerOpen] = useState(false);
  const [sortBy, setSortBy] = useState<'suggested' | 'rate' | 'speed'>('suggested');

  const debounceRef = useRef<ReturnType<typeof setTimeout>>();
  const pollRef = useRef<ReturnType<typeof setInterval>>();
  const logIdRef = useRef(0);
  const logEndRef = useRef<HTMLDivElement>(null);
  const generatingSubRef = useRef(false);

  // ─── Sorted routes ───
  const sortedRoutes = useMemo(() => {
    const r = [...routes];
    if (sortBy === 'rate') {
      r.sort((a, b) => (b.amount_to ?? 0) - (a.amount_to ?? 0));
    } else if (sortBy === 'speed') {
      r.sort((a, b) => {
        const etaDiff = (a.eta ?? 999) - (b.eta ?? 999);
        if (etaDiff !== 0) return etaDiff;
        return (b.amount_to ?? 0) - (a.amount_to ?? 0);
      });
    }
    return r;
  }, [routes, sortBy]);

  // ─── Reset when switching modes ───
  const handleModeSwitch = (newMode: ExchangeMode) => {
    if (newMode === mode || step !== 'config') return;
    setMode(newMode);
    setRoutes([]);
    setSelectedRoute(null);
    setQuoteError('');
    setSwapQuote(null);
    setAmount('');
    setDestAddress('');
    setRefundAddress('');
    setMemo('');
    // Set sensible defaults for each mode
    if (newMode === 'ghost') {
      setFromCoin(CurrencySelector.Bitcoin);
      setToCoin(CurrencySelector.Monero);
    } else {
      setFromCoin(CurrencySelector.Monero);
      setToCoin(CurrencySelector.Bitcoin);
    }
  };

  // ─── Init coins from currencies ───
  useEffect(() => {
    if (currencies.length > 0 && !toCoin) {
      const usdt = currencies.find(c => c.ticker === 'USDT' && c.network?.toLowerCase().includes('tron'));
      setToCoin(usdt || currencies.find(c => c.ticker !== 'XMR') || currencies[1]);
    }
  }, [currencies, toCoin]);

  // ─── Auto subaddress for XMR destination ───
  useEffect(() => {
    if (toCoin?.ticker?.toLowerCase() !== 'xmr' || !localXmrAddress) return;
    if (generatingSubRef.current) return;

    (async () => {
      generatingSubRef.current = true;
      try {
        const prefix = isGhost ? 'Ghost' : 'Swap';
        const addr = await getOrCreateSubaddress(prefix, subaddresses, createSubaddress);
        setDestAddress(addr || localXmrAddress);
      } catch (e) {
        console.warn('[Exchange] Subaddress generation failed, using primary:', e);
        setDestAddress(localXmrAddress);
      } finally {
        generatingSubRef.current = false;
      }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps -- subaddresses intentionally excluded to prevent infinite loop (createSubaddress updates subaddresses)
  }, [toCoin, localXmrAddress, isGhost]);

  // ─── Debounced quote/estimate ───
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    setRoutes([]);
    setSelectedRoute(null);
    setSwapQuote(null);
    setQuoteError('');

    if (!fromCoin || !toCoin || !amount || parseFloat(amount) <= 0) return;

    debounceRef.current = setTimeout(async () => {
      setIsQuoting(true);
      try {
        if (isGhost) {
          const est = await fetchBridgeEstimateV2(
            fromCoin.ticker, toCoin.ticker, parseFloat(amount),
            fromCoin.network, toCoin.network
          );
          setRoutes(est.routes as UnifiedRoute[]);
          if (est.routes.length > 0) setSelectedRoute(est.routes[0] as UnifiedRoute);
        } else {
          const q = await fetchQuote(
            fromCoin.ticker, fromCoin.network,
            toCoin.ticker, toCoin.network,
            parseFloat(amount), false,
            compliance.kyc, compliance.log
          );
          setSwapQuote(q);
          setRoutes((q.routes || []) as UnifiedRoute[]);
          if (q.routes?.length) setSelectedRoute(q.routes[0] as UnifiedRoute);
        }
      } catch (e: any) {
        setQuoteError(e.message || 'Quote failed');
      } finally {
        setIsQuoting(false);
      }
    }, 800);

    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [fromCoin, toCoin, amount, compliance, isGhost]);

  // ─── Swap status polling ───
  useEffect(() => {
    if (isGhost || step !== 'active' || !activeTrade) return;

    const poll = async () => {
      try {
        const status = await getTradeStatus(activeTrade.trade_id || activeTrade.id);
        const s = (status.status || '').toUpperCase();

        if (s !== tradeStatus) {
          setTradeStatus(s);
          addLog(`STATUS: ${s}`, s === 'FINISHED' ? 'success' : s === 'FAILED' ? 'error' : 'info');
          if (status.tx_out) setTxOut(status.tx_out);
          if (['FINISHED', 'FAILED', 'EXPIRED', 'REFUNDED'].includes(s)) {
            if (pollRef.current) clearInterval(pollRef.current);
            if (s === 'FINISHED') setStep('completed');
          }
        }
      } catch (e) { console.warn('[Exchange] Poll failed, retrying:', e); }
    };

    poll();
    pollRef.current = setInterval(poll, 10000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [step, activeTrade, isGhost]); // eslint-disable-line react-hooks/exhaustive-deps

  // ─── Ghost status polling ───
  useEffect(() => {
    if (!isGhost || step !== 'active' || ghostTrades.length === 0) return;

    const poll = async () => {
      try {
        const updated = await fetchBridgeStatusV2(ghostTrades[0].id, ghostTrades[0].engine);
        setGhostTrades(updated);

        const leg1 = updated[0];
        const leg2 = updated.length > 1 ? updated[1] : null;
        addLog(`Leg_1: ${leg1.status.toUpperCase()}`, leg1.status.toUpperCase() === 'FINISHED' ? 'success' : leg1.status.toUpperCase() === 'FAILED' ? 'error' : 'info');
        if (leg2) addLog(`Leg_2: ${leg2.status.toUpperCase()}`, leg2.status.toUpperCase() === 'FINISHED' ? 'success' : leg2.status.toUpperCase() === 'FAILED' ? 'error' : 'info');

        const allDone = updated.every(t => ['FINISHED', 'FAILED', 'REFUNDED', 'EXPIRED'].includes(t.status.toUpperCase()));
        if (allDone && pollRef.current) {
          clearInterval(pollRef.current);
          if (updated.every(t => t.status.toUpperCase() === 'FINISHED')) {
            addLog('Exchange completed successfully', 'success');
            setStep('completed');
          }
        }
      } catch (e) { console.warn('[Exchange] Poll failed, retrying:', e); }
    };

    poll();
    pollRef.current = setInterval(poll, 10000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [step, ghostTrades.length > 0 ? ghostTrades[0].id : '', isGhost]); // eslint-disable-line react-hooks/exhaustive-deps

  // ─── Auto-scroll logs ───
  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs.length]);

  const addLog = (text: string, type: LogLine['type'] = 'info') => {
    setLogs(prev => [...prev, {
      id: ++logIdRef.current,
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      text, type,
    }]);
  };

  // ─── Execute trade ───
  const handleExecute = async () => {
    if (!selectedRoute || !destAddress || isCreating) return;
    setIsCreating(true);
    setLogs([]);
    logIdRef.current = 0;

    try {
      if (isGhost) {
        const br = selectedRoute as BridgeRoute;
        addLog(`Initializing ghost: ${fromCoin.ticker} → XMR → ${toCoin!.ticker}`);
        addLog(`Route: ${br.bridgeLabel?.replace(/_/g, ' ') || br.provider}`);

        const result = await createBridgeTradeV2({
          engine: br.engine,
          from_currency: fromCoin.ticker,
          from_network: fromCoin.network,
          to_currency: toCoin!.ticker,
          to_network: toCoin!.network,
          amount_from: parseFloat(amount),
          address_to: destAddress,
          refund_address: br.requiresRefund ? refundAddress : undefined,
        });
        setGhostTrades(result);
        setStep('active');
        setRouteDrawerOpen(false);
        addLog(`Trade created: ${result[0].id}`, 'success');
        addLog('Awaiting deposit...');
      } else {
        const sr = selectedRoute as ExchangeRoute;
        addLog(`Creating trade: ${fromCoin.ticker} → ${toCoin!.ticker}`);
        addLog(`Provider: ${sr.provider}, Amount: ${amount} ${fromCoin.ticker}`);

        const trade = await createTrade({
          id: swapQuote!.id,
          amountFrom: parseFloat(amount),
          amountTo: sr.amount_to,
          fromTicker: fromCoin.ticker,
          fromNetwork: fromCoin.network,
          toTicker: toCoin!.ticker,
          toNetwork: toCoin!.network,
          destinationAddress: destAddress,
          provider: sr.provider,
          engine: sr.engine || swapQuote!.engine,
          memo: memo || undefined,
          source: 'swap',
        });

        setActiveTrade(trade);
        setTradeStatus('WAITING');
        setTxOut(null);
        setStep('active');
        setRouteDrawerOpen(false);
        addLog(`Trade created: ${trade.trade_id || trade.id}`, 'success');
        addLog('Deposit address generated. Awaiting deposit...');
      }
    } catch (e: any) {
      addLog(`Trade failed: ${e.message}`, 'error');
      setQuoteError(e.message || 'Trade creation failed');
    } finally {
      setIsCreating(false);
    }
  };

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopyFeedback(label);
    setTimeout(() => setCopyFeedback(null), 2000);
  };

  const handleReset = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    setStep('config');
    setActiveTrade(null);
    setTradeStatus('WAITING');
    setTxOut(null);
    setGhostTrades([]);
    setLogs([]);
    setRoutes([]);
    setSelectedRoute(null);
    setSwapQuote(null);
  };

  const handleSwapCoins = () => {
    if (!toCoin) return;
    const tmp = fromCoin;
    setFromCoin(toCoin);
    setToCoin(tmp);
    setAmount('');
    setDestAddress('');
  };

  const needsMemo = !isGhost && ['xrp', 'xlm', 'eos', 'atom'].includes(toCoin?.ticker?.toLowerCase() || '');
  const isFloating = selectedRoute ? !(selectedRoute as ExchangeRoute).fixed : true;

  // Swap progress
  const progressSteps = ['WAITING', 'CONFIRMING', 'EXCHANGING', 'SENDING', 'FINISHED'];
  const currentStepIndex = progressSteps.indexOf(tradeStatus);

  // ─── Mode tab ───
  const ModeTab = () => (
    <div className="flex items-center gap-1.5 bg-xmr-base border border-xmr-border/30 rounded-sm p-1">
      {([
        { id: 'swap' as const, label: 'Swap', icon: Zap },
        { id: 'ghost' as const, label: 'Ghost', icon: Ghost },
      ]).map(t => (
        <button
          key={t.id}
          onClick={() => handleModeSwitch(t.id)}
          className={`flex items-center gap-2 px-5 py-2.5 text-xs font-black uppercase tracking-widest transition-all cursor-pointer rounded-sm ${
            mode === t.id
              ? t.id === 'ghost'
                ? 'bg-xmr-ghost/15 text-xmr-ghost border border-xmr-ghost/30'
                : 'bg-xmr-accent/15 text-xmr-accent border border-xmr-accent/30'
              : 'text-xmr-dim hover:text-xmr-green border border-transparent'
          }`}
        >
          <t.icon size={14} /> {t.label}
        </button>
      ))}
    </div>
  );

  // ─── Route Drawer ───
  const RouteDrawer = () => (
    <>
      {routeDrawerOpen && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40" onClick={() => setRouteDrawerOpen(false)} />
      )}
      <div className={`fixed top-0 right-0 h-full w-80 bg-xmr-surface border-l border-xmr-border/40 z-50 flex flex-col transition-transform duration-300 ease-in-out shadow-2xl ${routeDrawerOpen ? 'translate-x-0' : 'translate-x-full'}`}>
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-xmr-border/20 bg-xmr-base/50">
          <div className="flex items-center gap-2">
            <ThemeIcon size={12} className={`text-${themeColor}`} />
            <span className={`text-[10px] font-black text-${themeColor} uppercase tracking-widest`}>{isGhost ? 'Ghost Routes' : 'Routes'}</span>
            {sortedRoutes.length > 0 && <span className="text-[9px] text-xmr-dim font-bold">{sortedRoutes.length}</span>}
          </div>
          <button onClick={() => setRouteDrawerOpen(false)} className="text-xmr-dim hover:text-xmr-green transition-colors cursor-pointer p-1">
            <X size={16} />
          </button>
        </div>

        <div className="flex items-center gap-1 px-3 py-2 border-b border-xmr-border/10 bg-xmr-base/30">
          <ArrowUpDown size={10} className="text-xmr-dim shrink-0" />
          {(['suggested', 'rate', 'speed'] as const).map(m => (
            <button
              key={m}
              onClick={() => setSortBy(m)}
              className={`px-2 py-1 text-[9px] font-black uppercase tracking-wider rounded-sm transition-all cursor-pointer ${
                sortBy === m
                  ? `bg-${themeColor}/15 text-${themeColor} border border-${themeColor}/30`
                  : 'text-xmr-dim hover:text-xmr-green border border-transparent'
              }`}
            >
              {m === 'suggested' ? 'Suggested' : m === 'rate' ? 'Best Rate' : 'Fastest'}
            </button>
          ))}
        </div>

        <div className="flex-grow overflow-y-auto custom-scrollbar p-3 space-y-2">
          {isQuoting && (
            <div className="flex items-center gap-3 text-xmr-dim p-6 justify-center">
              <RefreshCw size={14} className="animate-spin" />
              <span className="text-[10px] font-black uppercase tracking-widest">Scanning...</span>
            </div>
          )}

          {!isQuoting && sortedRoutes.map((route: any, i: number) => {
            const isSelected = isGhost
              ? selectedRoute?.engine === route.engine && selectedRoute?.provider === route.provider
              : selectedRoute?.provider === route.provider && (selectedRoute as any)?.fixed === route.fixed;
            const isPrivacy = route.kyc === 'A' && (route.log_policy === 'A' || route.log_policy === 'B');
            const etaDisplay = route.recorded_eta || route.eta;

            return (
              <button
                key={`${route.engine || route.provider}-${route.fixed ? 'f' : 'v'}-${i}`}
                className={`w-full text-left cursor-pointer transition-all border rounded-sm p-3 relative ${isSelected
                  ? isGhost
                    ? 'border-xmr-ghost bg-xmr-ghost/5 shadow-[0_0_12px_rgba(168,85,247,0.1)]'
                    : 'border-xmr-accent bg-xmr-accent/5 shadow-[0_0_12px_rgba(255,102,0,0.1)]'
                  : 'border-xmr-border/20 bg-xmr-surface hover:border-xmr-accent/30'
                }`}
                onClick={() => { setSelectedRoute(route); setRouteDrawerOpen(false); }}
              >
                {isSelected && <div className={`absolute left-0 top-0 bottom-0 w-0.5 bg-${themeColor} rounded-l-sm`} />}
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    {route.providerLogo && (
                      <img src={route.providerLogo} className="w-4 h-4 rounded-full object-contain bg-white/10" alt="" onError={(e: any) => e.currentTarget.style.display = 'none'} />
                    )}
                    <span className={`text-[10px] font-black uppercase text-${themeColor}`}>
                      {isGhost ? (route.bridgeLabel?.replace(/_/g, ' ') || route.provider) : route.provider}
                    </span>
                  </div>
                  <div className="flex items-center gap-1">
                    {isPrivacy && <span className="text-[7px] font-bold uppercase px-1 py-0.5 bg-xmr-ghost/10 text-xmr-ghost border border-xmr-ghost/20 rounded-sm">NO-KYC</span>}
                    {route.bridgeBadge && <span className="text-[7px] font-bold uppercase px-1 py-0.5 bg-xmr-ghost/10 text-xmr-ghost border border-xmr-ghost/20 rounded-sm">{route.bridgeBadge}</span>}
                    {!isGhost && !route.fixed && <span className="text-[7px] font-bold uppercase px-1 py-0.5 bg-xmr-warning/10 text-xmr-warning border border-xmr-warning/20 rounded-sm">FLOAT</span>}
                    {!isGhost && route.fixed && <span className="text-[7px] font-bold uppercase px-1 py-0.5 bg-xmr-green/10 text-xmr-green border border-xmr-green/20 rounded-sm">FIXED</span>}
                    {i === 0 && <span className="text-[7px] font-black uppercase px-1 py-0.5 bg-xmr-green/10 text-xmr-green border border-xmr-green/20 rounded-sm">{sortBy === 'rate' ? 'TOP' : sortBy === 'speed' ? 'FAST' : 'BEST'}</span>}
                  </div>
                </div>

                <div className="flex justify-between text-[10px] uppercase">
                  <span className="text-xmr-dim">Output</span>
                  <span className="text-xmr-green font-black">
                    {!isGhost && !route.fixed && <span className="opacity-60 mr-0.5">~</span>}
                    {route.amount_to?.toFixed(6)}
                  </span>
                </div>

                {isGhost && route.hops?.length > 0 && (
                  <div className="flex items-center gap-1 mt-1.5 text-[8px] text-xmr-dim">
                    {route.hops.map((hop: any, hi: number) => (
                      <Fragment key={hi}>
                        {hi > 0 && <ChevronRight size={7} className="text-xmr-border" />}
                        <span className="px-1 py-0.5 bg-xmr-base border border-xmr-border/20 uppercase">{hop.name}</span>
                      </Fragment>
                    ))}
                  </div>
                )}

                <div className="flex justify-between items-center mt-1 pt-1 border-t border-xmr-border/10 text-[9px] text-xmr-dim">
                  <div className="flex gap-3">
                    <span className="flex items-center gap-1"><Clock size={9} /> {etaDisplay}m</span>
                    {!isGhost && (route.spread ?? 0) > 0 && <span className="flex items-center gap-1"><Server size={9} /> {(route.spread * 100).toFixed(1)}%</span>}
                  </div>
                  <span>KYC: {isGhost ? `${route.ingressKyc || route.kyc}${route.egressKyc ? `/${route.egressKyc}` : ''}` : route.kyc}</span>
                </div>
              </button>
            );
          })}

          {!isQuoting && sortedRoutes.length === 0 && amount && parseFloat(amount) > 0 && !quoteError && (
            <div className="text-center py-8">
              <Shield size={24} className="text-xmr-dim mx-auto opacity-50 mb-3" />
              <p className="text-[10px] text-xmr-dim uppercase tracking-widest">No routes available</p>
            </div>
          )}

          {!amount && (
            <div className="p-4 space-y-3 text-[10px] text-xmr-dim uppercase">
              {isGhost ? (
                <>
                  <div className="flex items-start gap-2"><Shield size={12} className="text-xmr-ghost shrink-0 mt-0.5" /><span>Routes through XMR anonymity set</span></div>
                  <div className="flex items-start gap-2"><Zap size={12} className="text-xmr-ghost shrink-0 mt-0.5" /><span>Zero-log providers only</span></div>
                  <div className="flex items-start gap-2"><Ghost size={12} className="text-xmr-ghost shrink-0 mt-0.5" /><span>Enter an amount to scan routes</span></div>
                </>
              ) : (
                <>
                  <div className="flex items-start gap-2"><Zap size={12} className="text-xmr-accent shrink-0 mt-0.5" /><span>Real-time rates from 10+ providers</span></div>
                  <div className="flex items-start gap-2"><Shield size={12} className="text-xmr-accent shrink-0 mt-0.5" /><span>Filter by KYC & logging policies</span></div>
                  <div className="flex items-start gap-2"><RefreshCw size={12} className="text-xmr-accent shrink-0 mt-0.5" /><span>Enter an amount to see routes</span></div>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );

  // ─── Log Console (shared) ───
  const LogConsole = ({ label }: { label: string }) => (
    <div className="bg-xmr-base border border-xmr-border/20 rounded-sm overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-xmr-border/20 bg-xmr-surface/30">
        <div className="flex items-center gap-2">
          <span className="relative flex h-1.5 w-1.5">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full bg-${themeColor} opacity-75`} />
            <span className={`relative inline-flex rounded-full h-1.5 w-1.5 bg-${themeColor}`} />
          </span>
          <span className="text-[9px] font-mono text-xmr-dim uppercase tracking-widest">{label}</span>
        </div>
        <span className="text-[9px] font-mono text-xmr-dim">{logs.length}</span>
      </div>
      <div className="max-h-[100px] overflow-y-auto p-2 space-y-0.5 font-mono text-[10px] custom-scrollbar">
        {logs.length === 0 ? (
          <div className="text-xmr-dim/30 text-center py-2 uppercase text-[9px]">Initializing...</div>
        ) : logs.map(log => (
          <div key={log.id} className={`flex gap-2 ${log.type === 'error' ? 'text-xmr-error' : log.type === 'success' ? 'text-xmr-green' : log.type === 'warn' ? 'text-xmr-warning' : 'text-xmr-dim'}`}>
            <span className="text-xmr-dim/40 shrink-0">{log.time}</span>
            <span className="break-all">{log.text}</span>
          </div>
        ))}
        <div ref={logEndRef} />
      </div>
    </div>
  );

  // ═══════════════════════════════════════════════
  // COMPLETED VIEW
  // ═══════════════════════════════════════════════
  if (step === 'completed') {
    if (isGhost && ghostTrades.length > 0) {
      const leg1 = ghostTrades[0];
      const leg2 = ghostTrades.length > 1 ? ghostTrades[1] : null;
      const txHash = leg2?.txOut || (leg2 as any)?.details?.hashout || leg1.txOut || (leg1 as any)?.details?.hashout;

      return (
        <div className="max-w-xl mx-auto py-10 space-y-6 animate-in fade-in zoom-in-95 duration-300">
          <div className="flex flex-col items-center space-y-6">
            <div className="p-4 bg-xmr-ghost/10 rounded-full"><CheckCircle2 size={48} className="text-xmr-ghost" /></div>
            <div className="text-center space-y-2">
              <h3 className="text-xl font-black uppercase tracking-widest text-xmr-ghost font-mono">GHOST_COMPLETE</h3>
              <p className="text-[10px] text-xmr-dim uppercase tracking-[0.2em]">Privacy bridge executed successfully</p>
            </div>
            <Card className="p-6 w-full border-xmr-ghost/20 bg-xmr-surface space-y-3" topGradientAccentColor="xmr-ghost">
              <div className="flex justify-between text-[10px] font-mono uppercase"><span className="text-xmr-dim">Trade_ID</span><span className="text-xmr-ghost font-bold">{leg1.id.slice(0, 20)}...</span></div>
              <div className="flex justify-between text-[10px] font-mono uppercase"><span className="text-xmr-dim">Sent</span><span className="text-xmr-green">{leg1.fromAmount || leg1.depositAmount} {leg1.fromTicker}</span></div>
              <div className="flex justify-between text-[10px] font-mono uppercase"><span className="text-xmr-dim">Received</span><span className="text-xmr-green">{(leg2 || leg1).toAmount} {(leg2 || leg1).toTicker}</span></div>
              {txHash && (
                <div className="flex justify-between items-center text-[10px] font-mono uppercase pt-2 border-t border-xmr-border/20">
                  <span className="text-xmr-dim">TX_Out</span>
                  <div className="flex items-center gap-2"><span className="text-xmr-green truncate max-w-[200px]">{txHash}</span><button onClick={() => handleCopy(txHash, 'tx')} className="text-xmr-dim hover:text-xmr-green cursor-pointer">{copyFeedback === 'tx' ? <Check size={10} /> : <Copy size={10} />}</button></div>
                </div>
              )}
            </Card>
            <button onClick={handleReset} className="px-8 py-3 border border-xmr-ghost/50 text-xmr-ghost text-[10px] font-black uppercase tracking-[0.2em] hover:bg-xmr-ghost/10 transition-all cursor-pointer rounded-sm">NEW_EXCHANGE</button>
          </div>
        </div>
      );
    }

    // Swap completed
    return (
      <div className="max-w-xl mx-auto py-10 space-y-6 animate-in fade-in zoom-in-95 duration-300">
        <div className="flex flex-col items-center space-y-6">
          <div className="p-4 bg-xmr-green/10 rounded-full"><CheckCircle2 size={48} className="text-xmr-green" /></div>
          <div className="text-center space-y-2">
            <h3 className="text-xl font-black uppercase tracking-widest text-xmr-green font-mono">SWAP_COMPLETE</h3>
            <p className="text-[10px] text-xmr-dim uppercase tracking-[0.2em]">Transaction executed successfully</p>
          </div>
          {activeTrade && (
            <Card className="p-6 w-full border-xmr-green/20 bg-xmr-surface space-y-3">
              <div className="flex justify-between text-[10px] font-mono uppercase"><span className="text-xmr-dim">Trade_ID</span><span className="text-xmr-green font-bold">{(activeTrade.trade_id || activeTrade.id || '').slice(0, 20)}...</span></div>
              <div className="flex justify-between text-[10px] font-mono uppercase"><span className="text-xmr-dim">Sent</span><span className="text-xmr-green">{activeTrade.amount_from} {(activeTrade.ticker_from || fromCoin.ticker).toUpperCase()}</span></div>
              <div className="flex justify-between text-[10px] font-mono uppercase"><span className="text-xmr-dim">Received</span><span className="text-xmr-green">{activeTrade.amount_to} {(activeTrade.ticker_to || toCoin?.ticker || '').toUpperCase()}</span></div>
              {txOut && (
                <div className="flex justify-between items-center text-[10px] font-mono uppercase pt-2 border-t border-xmr-border/20">
                  <span className="text-xmr-dim">TX_Out</span>
                  <div className="flex items-center gap-2"><span className="text-xmr-green truncate max-w-[200px]">{txOut}</span><button onClick={() => handleCopy(txOut, 'tx')} className="text-xmr-dim hover:text-xmr-green cursor-pointer">{copyFeedback === 'tx' ? <Check size={10} /> : <Copy size={10} />}</button></div>
                </div>
              )}
            </Card>
          )}
          <button onClick={handleReset} className="px-8 py-3 border border-xmr-green/50 text-xmr-green text-[10px] font-black uppercase tracking-[0.2em] hover:bg-xmr-green/10 transition-all cursor-pointer rounded-sm">NEW_EXCHANGE</button>
        </div>
      </div>
    );
  }

  // ═══════════════════════════════════════════════
  // ACTIVE TRADE VIEW
  // ═══════════════════════════════════════════════
  if (step === 'active') {
    // ─── Ghost Active ───
    if (isGhost && ghostTrades.length > 0) {
      const leg1 = ghostTrades[0];
      const leg2 = ghostTrades.length > 1 ? ghostTrades[1] : null;
      const l1s = leg1.status.toUpperCase();
      const l2s = leg2?.status.toUpperCase();
      const allDone = ghostTrades.every(t => ['FINISHED', 'FAILED', 'REFUNDED', 'EXPIRED'].includes(t.status.toUpperCase()));

      return (
        <div className="max-w-2xl mx-auto py-8 space-y-6 animate-in fade-in duration-300">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-xmr-ghost/20 rounded-full"><Ghost size={20} className="text-xmr-ghost" /></div>
              <div>
                <h2 className="text-lg font-black uppercase tracking-tighter text-xmr-ghost">Ghost_Active</h2>
                <p className="text-[10px] text-xmr-dim uppercase tracking-widest">Privacy bridge in progress</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Radio size={10} className="text-xmr-ghost animate-pulse" />
              <span className="text-[10px] font-mono font-bold text-xmr-ghost uppercase">{l2s && l2s !== 'WAITING' ? `L2:${l2s}` : `L1:${l1s}`}</span>
            </div>
          </div>

          {/* Ghost progress */}
          <div className="flex items-center gap-1">
            {['LEG_1', 'XMR_POOL', 'LEG_2', 'COMPLETE'].map((label, i) => {
              let filled = i === 0;
              if (i === 1) filled = ['EXCHANGING', 'SENDING', 'FINISHED'].includes(l1s);
              if (i === 2) filled = l1s === 'FINISHED' && !!leg2;
              if (i === 3) filled = !!leg2 && l2s === 'FINISHED';
              const pulsing = !filled && ((i === 1 && ['CONFIRMING', 'EXCHANGING'].includes(l1s)) || (i === 2 && l1s === 'SENDING') || (i === 3 && !!leg2 && ['SENDING', 'EXCHANGING'].includes(l2s || '')));
              return <div key={label} className={`flex-1 h-1.5 rounded-full transition-all duration-500 ${filled ? 'bg-xmr-ghost shadow-[0_0_8px_var(--color-xmr-ghost)]' : pulsing ? 'bg-xmr-ghost/30 animate-pulse' : 'bg-xmr-border/20'}`} />;
            })}
          </div>
          <div className="flex justify-between text-[8px] font-mono text-xmr-dim uppercase tracking-wider -mt-4">
            {['LEG_1', 'XMR_POOL', 'LEG_2', 'COMPLETE'].map((label, i) => {
              let active = i === 0 && (!['FINISHED'].includes(l1s) || !leg2);
              if (i === 1) active = ['EXCHANGING', 'SENDING'].includes(l1s);
              if (i === 2) active = l1s === 'FINISHED' && !!leg2 && !['FINISHED', 'FAILED'].includes(l2s || '');
              if (i === 3) active = !!leg2 && l2s === 'FINISHED';
              return <span key={label} className={active ? 'text-xmr-ghost font-bold' : ''}>{label}</span>;
            })}
          </div>

          {/* Deposit card */}
          {l1s === 'WAITING' && leg1.depositAddress && (
            <Card className="p-6 border-xmr-ghost/30 bg-xmr-surface space-y-4" topGradientAccentColor="xmr-ghost">
              <div className="text-center space-y-1">
                <div className="text-[10px] text-xmr-ghost font-mono uppercase tracking-widest font-bold">Deposit_Required</div>
                <p className="text-[9px] text-xmr-dim">Send the amount below to initiate the ghost sequence</p>
              </div>
              <div className="p-4 bg-xmr-base border border-xmr-ghost/20 rounded-sm space-y-3">
                <div className="flex justify-between text-[10px] font-bold uppercase font-mono"><span className="text-xmr-dim">Amount</span><span className="text-xmr-ghost">{leg1.depositAmount} {leg1.fromTicker}</span></div>
                <div className="flex items-center gap-2">
                  <AddressDisplay address={leg1.depositAddress} className="text-[10px] text-xmr-green font-bold flex-grow" />
                  <button onClick={() => handleCopy(leg1.depositAddress!, 'deposit')} className="text-xmr-ghost shrink-0 hover:scale-110 transition-transform cursor-pointer">{copyFeedback === 'deposit' ? <Check size={14} /> : <Copy size={14} />}</button>
                </div>
              </div>
            </Card>
          )}

          {/* Summary */}
          <div className="flex items-center gap-4 justify-between text-xs font-bold uppercase tracking-tighter p-4 bg-xmr-surface/50 border border-xmr-border/20 rounded-sm">
            <div className="flex flex-col gap-1"><span className="text-xmr-dim text-[9px]">You_Send</span><span className="text-xmr-green">{leg1.fromAmount || leg1.depositAmount} {leg1.fromTicker}</span></div>
            <div className="flex items-center gap-1 text-xmr-ghost"><ArrowRight size={10} /><Ghost size={12} /><ArrowRight size={10} /></div>
            <div className="flex flex-col gap-1 text-right"><span className="text-xmr-dim text-[9px]">You_Receive</span><span className="text-xmr-green">{(leg2 || leg1).toAmount} {(leg2 || leg1).toTicker}</span></div>
          </div>

          {!allDone && (
            <div className="flex items-center justify-center gap-3 py-4">
              <Loader2 size={20} className="text-xmr-ghost animate-spin" />
              <span className="text-[10px] font-mono text-xmr-ghost font-bold uppercase tracking-widest animate-pulse">
                {l1s === 'CONFIRMING' ? 'Confirming_Deposit...' : l1s === 'EXCHANGING' ? 'Routing_Through_XMR...' : l1s === 'SENDING' && !leg2 ? 'Dispatching_Funds...' : l2s === 'CONFIRMING' ? 'Leg_2_Confirming...' : l2s === 'EXCHANGING' ? 'Leg_2_Exchanging...' : l2s === 'SENDING' ? 'Dispatching_Final...' : 'Processing...'}
              </span>
            </div>
          )}

          <LogConsole label="GHOST_LOG" />
          <button onClick={handleReset} className="w-full py-3 bg-xmr-error/5 hover:bg-xmr-error/10 border border-xmr-error/20 text-xmr-error text-[10px] font-bold uppercase tracking-[0.2em] flex items-center justify-center gap-2 transition-all cursor-pointer rounded-sm"><X size={14} /> Abort_Session</button>
        </div>
      );
    }

    // ─── Swap Active ───
    if (activeTrade) {
      const depositAddr = activeTrade.address_provider || activeTrade.deposit_address || activeTrade.depositAddress || '';
      const depositAmt = activeTrade.deposit_amount || activeTrade.amount_from;

      return (
        <div className="max-w-2xl mx-auto py-8 space-y-6 animate-in fade-in duration-300">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-xmr-accent/20 rounded-full"><Zap size={20} className="text-xmr-accent" /></div>
              <div>
                <h2 className="text-lg font-black uppercase tracking-tighter text-xmr-accent">Swap_Active</h2>
                <p className="text-[10px] text-xmr-dim uppercase tracking-widest">Trade in progress</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Radio size={10} className="text-xmr-green animate-pulse" />
              <span className="text-[10px] font-mono font-bold text-xmr-accent uppercase">{tradeStatus}</span>
            </div>
          </div>

          <div className="flex items-center gap-1">
            {progressSteps.map((s, i) => (
              <div key={s} className={`flex-1 h-1.5 rounded-full transition-all duration-500 ${i <= currentStepIndex ? 'bg-xmr-green shadow-[0_0_8px_var(--color-xmr-green)]' : i === currentStepIndex + 1 ? 'bg-xmr-accent/30 animate-pulse' : 'bg-xmr-border/20'}`} />
            ))}
          </div>
          <div className="flex justify-between text-[8px] font-mono text-xmr-dim uppercase tracking-wider -mt-4">
            {progressSteps.map((s, i) => <span key={s} className={i <= currentStepIndex ? 'text-xmr-green font-bold' : ''}>{s}</span>)}
          </div>

          {tradeStatus === 'WAITING' && depositAddr && (
            <Card className="p-6 border-xmr-accent/30 bg-xmr-surface space-y-4">
              <div className="text-center space-y-1">
                <div className="text-[10px] text-xmr-accent font-mono uppercase tracking-widest font-bold">Deposit_Required</div>
                {isFloating ? (
                  <p className="text-[9px] text-xmr-dim">Floating rate — exchange adjusts to actual deposited amount{swapQuote?.min || swapQuote?.max ? <span className="text-xmr-accent"> (range: {swapQuote.min || '?'}–{swapQuote.max || '?'} {(activeTrade.ticker_from || fromCoin.ticker).toUpperCase()})</span> : null}</p>
                ) : (
                  <p className="text-[9px] text-xmr-dim">Send the exact amount to the address below</p>
                )}
              </div>
              <div className="p-4 bg-xmr-base border border-xmr-accent/20 rounded-sm space-y-3">
                <div className="flex justify-between text-[10px] font-bold uppercase font-mono"><span className="text-xmr-dim">{isFloating ? 'Suggested Amount' : 'Amount'}</span><span className="text-xmr-accent">{depositAmt} {(activeTrade.ticker_from || fromCoin.ticker).toUpperCase()}</span></div>
                <div className="flex items-center gap-2">
                  <AddressDisplay address={depositAddr} className="text-[10px] text-xmr-green font-bold flex-grow" />
                  <button onClick={() => handleCopy(depositAddr, 'deposit')} className="text-xmr-accent shrink-0 hover:scale-110 transition-transform cursor-pointer">{copyFeedback === 'deposit' ? <Check size={14} /> : <Copy size={14} />}</button>
                </div>
              </div>
            </Card>
          )}

          <div className="flex items-center gap-4 justify-between text-xs font-bold uppercase tracking-tighter p-4 bg-xmr-surface/50 border border-xmr-border/20 rounded-sm">
            <div className="flex flex-col gap-1"><span className="text-xmr-dim text-[9px]">You_Send</span><span className="text-xmr-green">{activeTrade.amount_from} {(activeTrade.ticker_from || '').toUpperCase()}</span></div>
            <ArrowRight size={16} className="text-xmr-dim" />
            <div className="flex flex-col gap-1 text-right"><span className="text-xmr-dim text-[9px]">You_Receive</span><span className="text-xmr-green">{activeTrade.amount_to} {(activeTrade.ticker_to || '').toUpperCase()}</span></div>
          </div>

          {['CONFIRMING', 'EXCHANGING', 'SENDING'].includes(tradeStatus) && (
            <div className="flex items-center justify-center gap-3 py-4">
              <Loader2 size={20} className="text-xmr-accent animate-spin" />
              <span className="text-[10px] font-mono text-xmr-accent font-bold uppercase tracking-widest animate-pulse">{tradeStatus === 'CONFIRMING' ? 'Confirming_Deposit...' : tradeStatus === 'EXCHANGING' ? 'Executing_Swap...' : 'Dispatching_Funds...'}</span>
            </div>
          )}

          <LogConsole label="SWAP_LOG" />
          <button onClick={handleReset} className="w-full py-3 bg-xmr-error/5 hover:bg-xmr-error/10 border border-xmr-error/20 text-xmr-error text-[10px] font-bold uppercase tracking-[0.2em] flex items-center justify-center gap-2 transition-all cursor-pointer rounded-sm"><X size={14} /> Cancel_Trade</button>
        </div>
      );
    }
  }

  // ═══════════════════════════════════════════════
  // CONFIG VIEW
  // ═══════════════════════════════════════════════
  return (
    <div className="max-w-xl mx-auto py-2 space-y-3 animate-in fade-in slide-in-from-top-4 duration-500">
      <RouteDrawer />

      <div className="flex items-center justify-between mb-1">
        <ModeTab />
        <p className="text-[9px] text-xmr-dim uppercase tracking-[0.15em]">
          {isGhost ? 'Privacy bridge via XMR' : 'Aggregated rates'}
        </p>
      </div>

      <Card
        className={`p-4 bg-xmr-surface space-y-3 ${isGhost ? 'border-xmr-ghost/20' : 'border-xmr-accent/20'}`}
        topGradientAccentColor={isGhost ? 'xmr-ghost' : 'xmr-accent'}
      >
        {/* Source */}
        <div className={`flex gap-2 items-center bg-xmr-base border border-xmr-border/30 px-2 rounded-sm h-14 transition-colors ${isGhost ? 'focus-within:border-xmr-ghost/50' : 'focus-within:border-xmr-accent/50'}`}>
          <div className="w-[45%] shrink-0">
            <CurrencySelector label="" selected={fromCoin} onSelect={setFromCoin} currencies={currencies} hideBorder themeColor={isGhost ? 'xmr-ghost' : undefined} variant="drawer" drawerTitle="Source Asset" />
          </div>
          <input
            type="number"
            value={amount}
            onChange={e => setAmount(e.target.value)}
            placeholder="0.00"
            className="flex-grow bg-transparent text-right text-lg font-bold focus:outline-none pr-1 text-xmr-green min-w-0 h-full"
          />
        </div>

        {/* Swap arrow */}
        <div className="flex justify-center -my-1 relative z-10">
          <button
            onClick={handleSwapCoins}
            disabled={!toCoin}
            className={`bg-xmr-base border p-1 rounded-full hover:rotate-180 transition-all duration-300 cursor-pointer disabled:opacity-50 ${isGhost ? 'border-xmr-ghost/40 text-xmr-ghost hover:bg-xmr-ghost/10' : 'border-xmr-accent/40 text-xmr-accent hover:bg-xmr-accent/10'}`}
          >
            <ArrowDown size={12} />
          </button>
        </div>

        {/* Target */}
        <div className="flex gap-2 items-center bg-xmr-base border border-xmr-border/30 px-2 rounded-sm h-14">
          <div className="w-[45%] shrink-0">
            <CurrencySelector label="" selected={toCoin} onSelect={setToCoin} currencies={currencies} hideBorder themeColor={isGhost ? 'xmr-ghost' : undefined} variant="drawer" drawerTitle="Target Asset" />
          </div>
          <div className="flex-grow text-right text-lg font-bold pr-1 text-xmr-green min-w-0">
            {isQuoting ? <span className="animate-pulse text-xmr-dim">...</span> : selectedRoute ? selectedRoute.amount_to.toFixed(6) : '0.0000'}
          </div>
        </div>

        {quoteError && (
          <div className="flex items-center gap-2 text-xmr-error text-[10px] font-bold uppercase">
            <AlertCircle size={12} /> {quoteError}
          </div>
        )}

        {/* Route selector button */}
        <button
          onClick={() => setRouteDrawerOpen(true)}
          className={`w-full flex items-center justify-between px-3 py-2 bg-xmr-base border border-xmr-border/30 rounded-sm transition-colors cursor-pointer group ${isGhost ? 'hover:border-xmr-ghost/40' : 'hover:border-xmr-accent/40'}`}
        >
          <div className="flex items-center gap-2">
            <Radio size={11} className={`text-${themeColor}`} />
            {selectedRoute ? (
              <span className={`text-[10px] font-black uppercase text-${themeColor}`}>
                {isGhost ? ((selectedRoute as BridgeRoute).bridgeLabel?.replace(/_/g, ' ') || selectedRoute.provider) : selectedRoute.provider}
                <span className="text-xmr-dim font-bold ml-2">{selectedRoute.amount_to?.toFixed(6)} {toCoin?.ticker}</span>
                {!isGhost && !(selectedRoute as ExchangeRoute).fixed && <span className="text-xmr-dim/60 ml-1.5 text-[8px]">FLOAT</span>}
              </span>
            ) : (
              <span className="text-[10px] font-black uppercase text-xmr-dim">
                {isQuoting ? 'Scanning routes...' : routes.length ? `${routes.length} routes available` : 'Select route'}
              </span>
            )}
          </div>
          <ChevronRight size={14} className={`text-xmr-dim group-hover:text-${themeColor} transition-colors`} />
        </button>

        <div className="border-t border-xmr-border/15" />

        {/* Address */}
        <div className="space-y-1">
          <div className="flex justify-between">
            <label className="text-[9px] font-black text-xmr-dim uppercase ml-1">Destination</label>
            {toCoin?.ticker?.toLowerCase() === 'xmr' && localXmrAddress && (
              <span className="text-[8px] text-xmr-green font-black uppercase tracking-widest">LOCAL_VAULT</span>
            )}
          </div>
          <input
            type="text"
            value={destAddress}
            onChange={e => setDestAddress(e.target.value)}
            placeholder="Destination address..."
            className={`w-full bg-xmr-base border border-xmr-border/30 p-2.5 rounded-sm text-xs text-xmr-green font-bold focus:outline-none transition-colors ${isGhost ? 'focus:border-xmr-ghost/50' : 'focus:border-xmr-accent/50'}`}
          />
        </div>

        {/* Memo (swap only) */}
        {needsMemo && (
          <div className="space-y-1">
            <label className="text-[9px] font-black text-xmr-dim uppercase ml-1">Memo / Tag</label>
            <input type="text" value={memo} onChange={e => setMemo(e.target.value)} placeholder="Required for this coin..."
              className="w-full bg-xmr-base border border-xmr-border/30 p-2.5 rounded-sm text-xs text-xmr-green font-bold focus:outline-none focus:border-xmr-accent/50 transition-colors" />
          </div>
        )}

        {/* Refund address (ghost only, when required) */}
        {isGhost && (selectedRoute as BridgeRoute)?.requiresRefund && (
          <div className="space-y-1">
            <label className="text-[9px] font-black text-xmr-dim uppercase ml-1">Refund_Address</label>
            <input type="text" value={refundAddress} onChange={e => setRefundAddress(e.target.value)}
              placeholder={`${fromCoin?.ticker.toUpperCase() || ''} refund address...`}
              className="w-full bg-xmr-base border border-xmr-border/30 p-2.5 rounded-sm text-xs text-xmr-green font-bold focus:outline-none focus:border-xmr-ghost/50 transition-colors" />
          </div>
        )}

        {/* Compliance (swap only) */}
        {!isGhost && <ComplianceSelector value={compliance} onChange={setCompliance} />}

        {/* Execute */}
        <button
          disabled={!selectedRoute || !destAddress || isCreating || (isGhost && (selectedRoute as BridgeRoute)?.requiresRefund && !refundAddress)}
          onClick={handleExecute}
          className={`w-full py-3 font-black uppercase tracking-[0.2em] text-sm rounded-sm transition-all flex items-center justify-center gap-3 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer active:scale-[0.98] shadow-lg ${
            isGhost
              ? 'bg-xmr-ghost text-white hover:brightness-110 shadow-xmr-ghost/10'
              : 'bg-xmr-accent text-xmr-base hover:bg-xmr-green hover:text-xmr-base shadow-xmr-accent/10'
          }`}
        >
          <ThemeIcon size={16} className={isCreating ? 'animate-spin' : ''} />
          {isCreating ? 'Creating_Trade...' : isGhost ? 'Execute_Ghost' : 'Execute_Swap'}
        </button>
      </Card>
    </div>
  );
}
