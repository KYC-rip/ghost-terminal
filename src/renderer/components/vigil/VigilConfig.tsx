/* eslint-disable @typescript-eslint/no-explicit-any */
import { useMemo, useEffect, useState, useRef, useCallback } from 'react';
import { Crosshair, LogOut, Loader2, CheckCircle2, AlertCircle, ArrowDown, ShieldAlert, TrendingUp, Activity } from 'lucide-react';
import { useAddressValidator } from '../../hooks/useAddressValidator';
import { CurrencyInput } from '../CurrencyInput';
import { useCurrencies, type Currency } from '../../hooks/useCurrencies';
import { useFiatValue } from '../../hooks/useFiatValue';
import { ComplianceSelector } from '../ComplianceSelector';
import type { ComplianceState } from '../../services/swap';

// ─── Types ───

export interface VigilConfigData {
  inputCurrency: any;
  outputCurrency: any;
  triggerPrice: string;
  stopPrice: string;
  targetAddress: string;
  amount: string;
  memo?: string;
  compliance: ComplianceState;
}

interface Props {
  mode: 'SNIPE' | 'EJECT';
  setMode: (m: 'SNIPE' | 'EJECT') => void;
  data: VigilConfigData;
  setData: (data: any) => void;
  onArm: () => void;
  currentPrice: number;
  /** External arming block (e.g. strike wallet not funded yet) */
  armDisabled?: boolean;
  armDisabledReason?: string;
}

// ─── Hold-to-Arm Button ───

function HoldToArmButton({
  onComplete,
  disabled,
  label = 'INITIALIZE VIGIL',
}: {
  onComplete: () => void;
  disabled?: boolean;
  label?: string;
}) {
  const [progress, setProgress] = useState(0);
  const [holding, setHolding] = useState(false);
  const startTimeRef = useRef(0);
  const rafRef = useRef(0);

  const HOLD_DURATION = 1200; // 1.2 seconds

  const animate = useCallback(() => {
    const elapsed = Date.now() - startTimeRef.current;
    const pct = Math.min(elapsed / HOLD_DURATION, 1);
    setProgress(pct);

    if (pct >= 1) {
      setHolding(false);
      setProgress(0);
      onComplete();
      return;
    }
    rafRef.current = requestAnimationFrame(animate);
  }, [onComplete]);

  const handleStart = () => {
    if (disabled) return;
    setHolding(true);
    startTimeRef.current = Date.now();
    rafRef.current = requestAnimationFrame(animate);
  };

  const handleEnd = () => {
    setHolding(false);
    setProgress(0);
    if (rafRef.current) cancelAnimationFrame(rafRef.current);
  };

  useEffect(() => {
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  return (
    <button
      onMouseDown={handleStart}
      onMouseUp={handleEnd}
      onMouseLeave={handleEnd}
      onTouchStart={handleStart}
      onTouchEnd={handleEnd}
      disabled={disabled}
      className={`
        relative w-full py-3 border rounded-sm font-mono text-[11px] font-black uppercase tracking-[0.25em]
        overflow-hidden transition-all select-none
        ${disabled
          ? 'border-xmr-border text-xmr-dim/30 cursor-not-allowed'
          : holding
            ? 'border-xmr-green text-xmr-green shadow-[0_0_30px_rgba(0,255,65,0.15)]'
            : 'border-xmr-green/50 text-xmr-green hover:border-xmr-green hover:shadow-[0_0_20px_rgba(0,255,65,0.1)] cursor-pointer'
        }
      `}
    >
      {/* Fill progress */}
      <div
        className="absolute inset-0 bg-xmr-green/15 transition-none"
        style={{ width: `${progress * 100}%` }}
      />

      <span className="relative z-10 flex items-center justify-center gap-2">
        {holding ? (
          <>
            <Loader2 size={14} className="animate-spin" />
            HOLD... {Math.round(progress * 100)}%
          </>
        ) : (
          label
        )}
      </span>
    </button>
  );
}

// ─── Main Component ───

export function VigilConfig({ mode, setMode, data, setData, onArm, currentPrice, armDisabled, armDisabledReason }: Props) {
  const isSnipe = mode === 'SNIPE';
  const { currencies, loading: isCurrencyLoading } = useCurrencies();
  const [useStop, setUseStop] = useState(false);
  const [amountError, setAmountError] = useState<string | null>(null);

  // ─── Filter currencies for each mode ───
  // EJECT: input is XMR (Mainnet), output is stablecoins/EVM
  // SNIPE: input is stablecoins/EVM, output is XMR
  const xmrCoin = useMemo(
    () => currencies.find((c: Currency) => c.ticker.toLowerCase() === 'xmr' && c.network === 'Mainnet') || null,
    [currencies]
  );

  const evmTokens = useMemo(
    () => currencies.filter((c: Currency) => {
      const t = c.ticker.toLowerCase();
      const n = c.network.toLowerCase();
      // Stablecoins, native EVM, major tokens
      return (
        t.includes('usd') || t === 'dai' ||
        t === 'eth' || t === 'bnb' || t === 'matic' ||
        n.includes('erc20') || n.includes('bep20') || n.includes('trc20') ||
        n === 'ethereum' || n === 'bsc'
      );
    }),
    [currencies]
  );

  const inputTokens = isSnipe ? evmTokens : (xmrCoin ? [xmrCoin] : []);
  const outputTokens = isSnipe ? (xmrCoin ? [xmrCoin] : []) : evmTokens;

  // Defaults
  const defaultXmr = xmrCoin || { ticker: 'XMR', network: 'Mainnet', name: 'Monero' };
  const defaultEvm = evmTokens.find((c: Currency) => c.ticker.toLowerCase() === 'usdt') || evmTokens[0] || { ticker: 'USDT', network: 'ERC20', name: 'Tether' };

  // Set default currencies on mode change
  useEffect(() => {
    if (!currencies.length) return;
    setData((d: VigilConfigData) => ({
      ...d,
      inputCurrency: isSnipe ? (d.inputCurrency?.ticker?.toLowerCase() !== 'xmr' ? d.inputCurrency : defaultEvm) : defaultXmr,
      outputCurrency: isSnipe ? defaultXmr : (d.outputCurrency?.ticker?.toLowerCase() !== 'xmr' ? d.outputCurrency : defaultEvm),
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, currencies.length]);

  // ─── Min/Max Validation ───
  useEffect(() => {
    const val = parseFloat(data.amount);
    if (!data.amount || isNaN(val)) {
      setAmountError(null);
      return;
    }
    const coin = data.inputCurrency;
    const min = coin?.minimum ?? 0;
    const max = coin?.maximum ?? 0;

    if (val < min) {
      setAmountError(`MIN: ${min} ${coin?.ticker}`);
    } else if (max > 0 && val > max) {
      setAmountError(`MAX: ${max} ${coin?.ticker}`);
    } else {
      setAmountError(null);
    }
  }, [data.amount, data.inputCurrency]);

  // ─── Fiat prices ───
  const inputTicker = data.inputCurrency?.ticker || 'USDT';
  const outputTicker = data.outputCurrency?.ticker || 'USDT';
  const { fiatText: rawInputPrice } = useFiatValue(inputTicker, 1, false);
  const { fiatText: rawOutputPrice } = useFiatValue(outputTicker, 1, false);
  const inputPrice = parseFloat(rawInputPrice || '0');
  const outputPrice = parseFloat(rawOutputPrice || '0');

  const formatPrice = (val: number) => {
    if (!val || isNaN(val)) return '';
    if (val < 1) return val.toPrecision(4);
    return val.toFixed(2);
  };

  // ─── Auto-fill trigger/stop on mode change ───
  useEffect(() => {
    if (currentPrice <= 0) return;
    const tMult = isSnipe ? 0.95 : 1.05;
    const sMult = isSnipe ? 1.05 : 0.90;

    setData((d: VigilConfigData) => ({
      ...d,
      triggerPrice: formatPrice(currentPrice * tMult),
      stopPrice: useStop ? formatPrice(currentPrice * sMult) : d.stopPrice,
    }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, useStop]);

  // Fill trigger when price first arrives
  useEffect(() => {
    if (currentPrice <= 0) return;
    if (!data.triggerPrice || data.triggerPrice === '0') {
      const tMult = isSnipe ? 0.95 : 1.05;
      setData((d: VigilConfigData) => ({ ...d, triggerPrice: formatPrice(currentPrice * tMult) }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentPrice > 0]);

  // ─── Price status checks ───
  const getPriceStatus = (priceStr: string, type: 'MAIN' | 'STOP') => {
    const val = parseFloat(priceStr);
    if (!val || !currentPrice) return 'ok';

    if (isSnipe) {
      if (type === 'MAIN' && val >= currentPrice) return 'immediate';
      if (type === 'STOP' && val <= currentPrice) return 'immediate';
    } else {
      if (type === 'MAIN' && val <= currentPrice) return 'immediate';
      if (type === 'STOP' && val >= currentPrice) return 'immediate';
    }
    return 'ok';
  };

  const mainStatus = getPriceStatus(data.triggerPrice, 'MAIN');
  const stopStatus = getPriceStatus(data.stopPrice, 'STOP');

  // ─── Address validation ───
  const targetTicker = data.outputCurrency?.ticker || (isSnipe ? defaultXmr.ticker : defaultEvm.ticker);
  const targetNetwork = data.outputCurrency?.network || (isSnipe ? defaultXmr.network : defaultEvm.network);
  const { isValid, isValidating } = useAddressValidator(targetTicker, targetNetwork, data.targetAddress);

  // ─── Output estimation ───
  const estimatedOutput = useMemo(() => {
    const amount = parseFloat(data.amount);
    const trigger = parseFloat(data.triggerPrice);
    if (isNaN(amount) || amount <= 0 || isNaN(trigger) || trigger <= 0) return '';

    const SLIPPAGE_ESTIMATE = 0.98;
    let result = 0;

    if (isSnipe) {
      const safeInputPrice = inputPrice || 0;
      if (safeInputPrice <= 0) return '---';
      result = (amount * safeInputPrice / trigger) * SLIPPAGE_ESTIMATE;
    } else {
      const safeOutputPrice = outputPrice || 1;
      if (safeOutputPrice <= 0) return '---';
      result = (amount * trigger / safeOutputPrice) * SLIPPAGE_ESTIMATE;
    }

    const currentOutTicker = data.outputCurrency?.ticker || (isSnipe ? defaultXmr.ticker : defaultEvm.ticker);
    const isStableOut = currentOutTicker.toLowerCase().includes('usd') || currentOutTicker.toLowerCase().includes('dai');
    const precision = isStableOut ? 2 : (result < 1 ? 6 : 4);
    return result.toFixed(precision);
  }, [data.amount, data.triggerPrice, isSnipe, inputPrice, outputPrice, data.outputCurrency, defaultXmr.ticker, defaultEvm.ticker]);

  return (
    <div className="space-y-3 animate-in fade-in slide-in-from-bottom-2 w-full max-w-3xl mx-auto">

      {/* ─── Mode Toggle ─── */}
      <div className="grid grid-cols-2 gap-2">
        <button
          onClick={() => setMode('SNIPE')}
          className={`relative overflow-hidden group px-3 py-2.5 border rounded-sm transition-all duration-300 flex items-center gap-3
            ${isSnipe
              ? 'bg-xmr-green/10 border-xmr-green/50 text-xmr-green ring-1 ring-xmr-green/50'
              : 'bg-xmr-base border-xmr-border text-xmr-dim hover:border-xmr-dim/50 hover:text-current'
            }`}
        >
          <div className="bg-current/10 p-1.5 rounded-full">
            <Crosshair size={16} />
          </div>
          <div className="text-left flex-1">
            <span className="block text-sm font-bold tracking-wider">SNIPE</span>
            <span className="text-[9px] uppercase tracking-wider opacity-60">Auto-buy when price dips</span>
          </div>
          {isSnipe && <div className="absolute inset-0 bg-xmr-green/5 blur-xl" />}
        </button>

        <button
          onClick={() => setMode('EJECT')}
          className={`relative overflow-hidden group px-3 py-2.5 border rounded-sm transition-all duration-300 flex items-center gap-3
            ${!isSnipe
              ? 'bg-xmr-error/10 border-xmr-error/50 text-xmr-error ring-1 ring-xmr-error/50'
              : 'bg-xmr-base border-xmr-border text-xmr-dim hover:border-xmr-dim/50 hover:text-current'
            }`}
        >
          <div className="bg-current/10 p-1.5 rounded-full">
            <LogOut size={16} />
          </div>
          <div className="text-left flex-1">
            <span className="block text-sm font-bold tracking-wider">EJECT</span>
            <span className="text-[9px] uppercase tracking-wider opacity-60">Auto-sell at target</span>
          </div>
          {!isSnipe && <div className="absolute inset-0 bg-xmr-error/5 blur-xl" />}
        </button>
      </div>

      {/* ─── Config Panel ─── */}
      <div className="bg-xmr-base/30 border border-xmr-border rounded-sm p-3 flex flex-col gap-3 relative">

        {/* Header */}
        <div className="flex justify-between items-end border-b border-xmr-border/30 pb-1.5">
          <div className="flex items-center gap-2">
            <div className={`p-1 rounded-sm ${useStop ? 'bg-xmr-ghost/20 text-xmr-ghost' : 'bg-xmr-dim/10 text-xmr-dim'}`}>
              <Activity size={12} />
            </div>
            <span className="text-[10px] text-xmr-dim font-mono uppercase tracking-widest">
              {useStop ? 'OCO_STRATEGY_ACTIVE' : 'SINGLE_TARGET_MODE'}
            </span>
          </div>

          <div className="flex items-center gap-2 bg-black/40 px-2 py-1 rounded-sm border border-xmr-border/30">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-xmr-green opacity-75" />
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-xmr-green" />
            </span>
            <span className="text-[10px] font-mono text-xmr-dim">
              MARKET: <span className="text-white font-bold tracking-wide">${currentPrice.toFixed(2)}</span>
            </span>
          </div>
        </div>

        {/* ─── Price Inputs ─── */}
        <div className="flex gap-3">
          {/* Primary Target */}
          <div className="flex-1 space-y-1">
            <label className="text-[10px] text-xmr-dim font-mono uppercase tracking-wider flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-xmr-green" />
              {isSnipe ? 'TARGET (BUY DIP)' : 'TARGET (TAKE PROFIT)'}
            </label>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-xmr-dim text-sm font-mono">$</span>
              <input
                type="number"
                placeholder="0.00"
                value={data.triggerPrice}
                onChange={(e: any) => setData({ ...data, triggerPrice: e.target.value })}
                className={`w-full bg-xmr-base border rounded-sm py-2 px-3 pl-6 text-sm font-mono text-current focus:outline-none transition-colors
                  ${mainStatus === 'immediate' ? 'border-xmr-warning text-xmr-warning' : 'border-xmr-border focus:border-xmr-ghost'}
                `}
              />
            </div>
            {mainStatus === 'immediate' && (
              <div className="text-[9px] text-xmr-warning animate-pulse font-mono uppercase">!! IMMEDIATE EXECUTION</div>
            )}
          </div>

          {/* Stop Loss (Toggleable) */}
          {useStop && (
            <div className="flex-1 space-y-1 animate-in fade-in slide-in-from-right-2">
              <label className="text-[10px] text-xmr-dim font-mono uppercase tracking-wider flex items-center gap-1.5">
                <div className="w-1.5 h-1.5 rounded-full bg-xmr-error" />
                {isSnipe ? 'STOP (BREAKOUT)' : 'STOP (LOSS)'}
              </label>
              <div className="relative">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 text-xmr-dim text-sm font-mono">$</span>
                <input
                  type="number"
                  placeholder="0.00"
                  value={data.stopPrice}
                  onChange={(e: any) => setData({ ...data, stopPrice: e.target.value })}
                  className={`w-full bg-xmr-base border rounded-sm py-2 px-3 pl-6 text-sm font-mono text-current focus:outline-none transition-colors
                    ${stopStatus === 'immediate' ? 'border-xmr-warning text-xmr-warning' : 'border-xmr-border focus:border-xmr-error/50'}
                  `}
                />
              </div>
              {stopStatus === 'immediate' && (
                <div className="text-[9px] text-xmr-warning animate-pulse font-mono uppercase">!! IMMEDIATE EXECUTION</div>
              )}
            </div>
          )}
        </div>

        {/* Toggle OCO */}
        <div className="flex justify-end">
          <button
            onClick={() => {
              if (useStop) setData({ ...data, stopPrice: '' });
              setUseStop(!useStop);
            }}
            className={`text-[9px] uppercase tracking-wider border rounded-sm px-3 py-1.5 transition-all flex items-center gap-2
              ${useStop
                ? 'bg-xmr-ghost/10 border-xmr-ghost text-xmr-ghost shadow-[0_0_10px_rgba(168,85,247,0.2)]'
                : 'border-xmr-border text-xmr-dim hover:text-xmr-green hover:border-xmr-dim'
              }
            `}
          >
            {useStop ? <ShieldAlert size={12} /> : <TrendingUp size={12} />}
            {useStop ? 'DISABLE OCO (One Cancels Other)' : 'ACTIVATE OCO / STOP LOSS'}
          </button>
        </div>

        <div className="h-px bg-xmr-border/50" />

        {/* ─── Exchange Inputs ─── */}
        <div className="flex flex-col relative gap-1">
          <CurrencyInput
            label={`YOU PAY (${isSnipe ? 'Stablecoins / Native' : 'Monero'})`}
            amount={data.amount}
            onAmountChange={(val) => setData({ ...data, amount: val })}
            currency={data.inputCurrency}
            onCurrencySelect={(token) => setData({ ...data, inputCurrency: token })}
            tokenList={inputTokens}
            loading={isCurrencyLoading}
            disableSelector={!isSnipe} // EJECT: input is always XMR
            showFiatValue={isSnipe && !amountError}
            error={amountError || undefined}
          />

          <div className="z-10 flex justify-center -my-3 pointer-events-none">
            <div className="bg-xmr-surface border border-xmr-border p-1.5 rounded-full text-xmr-dim shadow-sm">
              <ArrowDown size={14} />
            </div>
          </div>

          <CurrencyInput
            label="YOU RECEIVE (ESTIMATED)"
            amount={estimatedOutput}
            placeholder="0.00"
            readOnly
            onAmountChange={() => {}}
            currency={data.outputCurrency}
            onCurrencySelect={(token) => setData({ ...data, outputCurrency: token })}
            tokenList={outputTokens}
            loading={isCurrencyLoading}
            disableSelector={isSnipe} // SNIPE: output is always XMR
            showFiatValue={mode !== 'SNIPE'}
          />
        </div>

        {/* ─── Target Address ─── */}
        <div className="space-y-1 pt-2 border-t border-xmr-border/50">
          <div className="flex justify-between">
            <label className="text-[10px] text-xmr-dim font-mono uppercase tracking-wider truncate max-w-[200px]">
              RECEIVE {data.outputCurrency?.ticker?.toUpperCase() || 'ASSET'} ADDRESS
            </label>
            {data.targetAddress && (
              <div className="flex items-center gap-1 text-[10px] animate-in fade-in shrink-0">
                {isValidating ? (
                  <><Loader2 size={10} className="animate-spin text-xmr-dim" /> <span className="text-xmr-dim">CHECKING</span></>
                ) : isValid ? (
                  <><CheckCircle2 size={10} className="text-xmr-green" /> <span className="text-xmr-green font-bold">VALID</span></>
                ) : (
                  <><AlertCircle size={10} className="text-xmr-error" /> <span className="text-xmr-error font-bold">INVALID</span></>
                )}
              </div>
            )}
          </div>
          <input
            type="text"
            placeholder={
              data.outputCurrency?.ticker?.toLowerCase() === 'xmr' ? '4... (XMR Address)' :
              data.outputCurrency?.ticker?.toLowerCase() === 'btc' ? 'bc1... (BTC Address)' :
              '0x... (Wallet Address)'
            }
            value={data.targetAddress}
            onChange={(e: any) => setData({ ...data, targetAddress: e.target.value })}
            className={`w-full bg-xmr-base border rounded-sm py-2 px-3 font-mono text-xs text-current focus:outline-none transition-colors placeholder:text-xmr-dim/30
              ${data.targetAddress && !isValid && !isValidating ? 'border-xmr-error/50 focus:border-xmr-error' : 'border-xmr-border focus:border-xmr-ghost'}
            `}
          />
          {data.outputCurrency?.memo && (
            <div className="mt-2 animate-in fade-in slide-in-from-top-1">
              <label className="text-[9px] text-xmr-dim font-mono uppercase tracking-widest block mb-1">
                DESTINATION_MEMO (EXTRA_ID)
              </label>
              <input
                type="text"
                placeholder="0 (Required by destination)"
                value={data.memo || ''}
                onChange={(e: any) => setData({ ...data, memo: e.target.value })}
                className="w-full bg-xmr-base border border-xmr-border rounded-sm py-2 px-3 font-mono text-xs text-current focus:outline-none focus:border-xmr-ghost"
              />
            </div>
          )}
        </div>

        {/* ─── Compliance ─── */}
        <div className="pt-2 border-t border-xmr-border/30">
          <ComplianceSelector
            value={data.compliance || { kyc: 'ANY', log: 'ANY' }}
            onChange={(val) => setData({ ...data, compliance: val })}
            variant="vigil"
            defaultExpanded={false}
            className="border-none bg-black/20"
          />
        </div>
      </div>

      {/* ─── Arm Button ─── */}
      <HoldToArmButton
        onComplete={onArm}
        disabled={!data.triggerPrice || !data.amount || !data.inputCurrency || !data.outputCurrency || !isValid || !!amountError || armDisabled}
        label={armDisabled && armDisabledReason ? armDisabledReason : 'INITIALIZE VIGIL'}
      />
      {!isSnipe && (
        <p className="text-[9px] text-xmr-dim font-mono uppercase tracking-wider text-center">
          While armed, the vault stays open behind the lock screen so this order can execute unattended. Abort the vigil to fully lock.
        </p>
      )}
    </div>
  );
}
