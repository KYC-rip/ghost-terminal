import { useState, useRef, useEffect, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, Search, X, Check } from 'lucide-react';
import { Spinner } from './common/Spinner';
import type { Currency } from '../hooks/useCurrencies';
import { useFiatValue } from '../hooks/useFiatValue';

interface CurrencyInputProps {
  label?: string;
  amount: string;
  currency: Currency | null;
  onAmountChange: (val: string) => void;
  onCurrencySelect: (token: Currency) => void;
  tokenList: Currency[];
  loading?: boolean;
  readOnly?: boolean;
  disableSelector?: boolean;
  usdValue?: string;
  error?: string;
  placeholder?: string;
  disabled?: boolean;
  reserveArrowSpace?: boolean;
  showFiatValue?: boolean;
  exclude?: string[];
}


const TokenRow = ({ token, isActive, onClick }: { token: Currency, isActive: boolean, onClick: () => void }) => (
  <button
    onClick={onClick}
    className={`
          w-full flex items-center justify-between p-3 rounded-sm cursor-pointer transition-all border content-visibility-auto
          ${['testnet', 'stagenet', 'sepolia'].includes(token?.network.toLowerCase() || '') ? 'border-xmr-warning text-xmr-surface' : ''}
          ${isActive
        ? 'bg-xmr-green/10 border-xmr-green/30'
        : 'hover:bg-xmr-surface border-transparent hover:border-xmr-border'}
      `}
  >
    <div className="flex items-center gap-3">
      <div className="w-8 h-8 rounded-full bg-xmr-surface border border-xmr-border flex items-center justify-center text-xmr-green font-bold text-xs overflow-hidden shrink-0">
        {token.image ? <img src={token.image} className="w-full h-full object-cover" loading="lazy" /> : token.ticker[0]}
      </div>
      <div className="text-left">
        <div className={`font-bold text-sm ${isActive ? 'text-xmr-green' : 'text-xmr-dim'}`}>
          {token.ticker.toUpperCase()}
        </div>
        <div className="text-xs text-xmr-dim/70 uppercase font-bold tracking-wider flex items-center gap-2">
          {token.name}
          <span className="bg-xmr-surface border border-xmr-border px-1 rounded-sm opacity-80">{token.network}</span>
        </div>
      </div>
    </div>

    {isActive && <Check size={16} className="text-xmr-green" />}
  </button>
);

export function CurrencyInput({
  label = "AMOUNT",
  amount,
  currency,
  onAmountChange,
  onCurrencySelect,
  tokenList,
  loading = false,
  readOnly = false,
  disableSelector = false,
  usdValue,
  error,
  placeholder = "0.00",
  disabled = false,
  reserveArrowSpace = false,
  showFiatValue = false,
  exclude = []
}: CurrencyInputProps) {

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [animate, setAnimate] = useState(false);

  const [isListReady, setIsListReady] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const { fiatText } = useFiatValue(currency?.ticker, amount);

  const handleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    let val = e.target.value;
    val = val.replace(/[^0-9.]/g, '');
    const parts = val.split('.');
    if (parts.length > 2) val = parts[0] + '.' + parts.slice(1).join('');
    if (parts[1] && parts[1].length > 8) val = parts[0] + '.' + parts[1].substring(0, 8);

    onAmountChange(val);
    setAnimate(true);
  };

  useEffect(() => {
    if (animate) {
      const timer = setTimeout(() => setAnimate(false), 200);
      return () => clearTimeout(timer);
    }
  }, [animate]);

  // Handle Modal Open/Close
  useEffect(() => {
    if (isModalOpen) {
      document.body.style.overflow = 'hidden';

      requestAnimationFrame(() => {
        setTimeout(() => {
          searchRef.current?.focus();
          setIsListReady(true);
        }, 10);
      });
    } else {
      document.body.style.overflow = '';
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setSearchTerm('');
      setIsListReady(false);
    }
    return () => { document.body.style.overflow = ''; };
  }, [isModalOpen]);

  const filteredList = useMemo(() => tokenList.filter((c) => !exclude.includes(c.network === "Mainnet" ? c.id : `${c.ticker}-${c.network}`)), [tokenList, exclude]);

  // --- Filtering & Logic ---
  const displayList = useMemo(() => {
    if (!isModalOpen || !isListReady) return [];
    if (!searchTerm) return filteredList.slice(0, 100);

    const lowerSearch = searchTerm.toLowerCase();
    const getScore = (c: Currency) => {
      const tickerLower = c.ticker.toLowerCase();

      if (tickerLower === lowerSearch) return 10;
      if (tickerLower.startsWith(lowerSearch)) return 8;
      if (tickerLower.includes(lowerSearch)) return 5;
      if (c.name?.toLowerCase().includes(lowerSearch)) return 3;
      if (c.network?.toLowerCase().includes(lowerSearch)) return 1;
      return 0;
    };
    const scored = [];
    for (let i = 0; i < filteredList.length; i++) {
      const t = filteredList[i];
      const score = getScore(t);
      if (score > 0) scored.push({ t, score });
    }

    return scored
      .sort((a, b) => b.score - a.score)
      .map(item => item.t)
      .slice(0, 100);

  }, [searchTerm, isModalOpen, isListReady, filteredList]);

  const modalContent = (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-xmr-base/90 backdrop-blur-md animate-in fade-in duration-200 p-4">
      <div className="absolute inset-0" onClick={() => setIsModalOpen(false)}></div>

      <div className="relative w-full max-w-sm bg-xmr-base border border-xmr-green/50 shadow-[0_0_50px_rgba(0,255,65,0.1)] rounded-sm overflow-hidden flex flex-col max-h-[70vh] animate-in zoom-in-95 duration-200 z-10">
        {/* Header */}
        <div className="p-4 border-b border-xmr-border flex justify-between items-center bg-xmr-surface">
          <h3 className="font-bold text-xmr-green tracking-[0.2em] text-sm flex items-center gap-2">
            <Search size={14} /> SELECT_ASSET
          </h3>
          <button onClick={() => setIsModalOpen(false)} className="text-xmr-dim hover:text-xmr-error transition-colors">
            <X size={20} />
          </button>
        </div>

        {/* Search Input */}
        <div className="p-3 border-b border-xmr-border/30 bg-xmr-base">
          <input
            ref={searchRef}
            autoFocus
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="SEARCH (Ticker, Name)..."
            className="w-full bg-xmr-surface border border-xmr-border rounded-sm px-3 py-2 text-sm text-xmr-dim focus:border-xmr-green outline-none placeholder-xmr-dim/50 uppercase"
          />
        </div>

        {/* List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1 custom-scrollbar min-h-[200px]">
          {!isListReady ? (

            <div className="flex flex-col items-center justify-center h-48 space-y-2">
              <Spinner />
              <span className="text-xs text-xmr-dim animate-pulse">LOADING_ASSETS...</span>
            </div>
          ) : (
            <>
              {displayList.map((token, idx) => (
                <TokenRow
                  key={`${token.ticker}-${token.network}-${idx}`}
                  token={token}
                  isActive={currency?.ticker === token.ticker && currency?.network === token.network}
                  onClick={() => {
                    onCurrencySelect(token);
                    setIsModalOpen(false);
                  }}
                />
              ))}

              {tokenList.length > 100 && searchTerm && (
                <div className="text-center py-3 text-xs text-xmr-dim/50 border-t border-dashed border-xmr-border mt-2">
                  ... AND MORE
                </div>
              )}

              {displayList.length === 0 && (
                <div className="p-8 text-center text-xmr-dim text-xs border border-dashed border-xmr-dim/20 rounded-sm m-2">
                  NO_ASSETS_FOUND
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer Status */}
        <div className="p-2 border-t border-xmr-border bg-xmr-surface text-xs text-xmr-dim flex justify-between rounded-b-sm font-mono">
          <span>STATUS: {isListReady ? 'ONLINE' : 'SYNCING'}</span>
          <span>{tokenList.length} ASSETS</span>
        </div>
      </div>
    </div>
  );

  return (
    <div className={`w-full font-mono transition-opacity duration-200 ${disabled ? 'opacity-50 pointer-events-none' : ''}`}>

      <div className="flex justify-between text-xs md:text-xs mb-1 px-1 uppercase tracking-widest text-xmr-dim">
        <label className="font-bold">{label}</label>
        {currency?.balance && (
          <span
            className="cursor-pointer hover:text-xmr-green transition-colors flex items-center gap-1"
            onClick={() => onAmountChange(currency.balance!)}
          >
            BAL: {currency.balance}
          </span>
        )}
        {showFiatValue && (
          <span
            className="cursor-pointer hover:text-xmr-green transition-colors flex items-center gap-1">
            {fiatText}
          </span>
        )}
      </div>

      <div className={`
        relative flex items-center bg-xmr-surface border rounded-sm transition-all duration-300 group
        ${error
          ? 'border-xmr-error/50 shadow-[0_0_15px_rgba(239,68,68,0.1)]'
          : 'border-xmr-border hover:border-xmr-green/50 focus-within:border-xmr-green focus-within:shadow-[0_0_20px_rgba(0,255,65,0.05)]'
        }
      `}>

        <input
          ref={inputRef}
          type="text"
          inputMode="decimal"
          value={amount}
          onChange={handleInput}
          readOnly={readOnly}
          placeholder={placeholder}
          className={`
            w-full bg-transparent p-2.5 md:p-3 text-sm md:text-md placeholder:text-xl font-bold outline-none text-xmr-dim placeholder-xmr-dim/30
            ${readOnly ? 'cursor-default' : ''}
            ${animate ? 'text-xmr-green drop-shadow-[0_0_2px_rgba(0,255,65,0.5)]' : ''}
            transition-all duration-200 font-mono
          `}
        />

        <div className="pr-2 md:pr-3 flex items-center gap-2 shrink-0">
          {loading && <Spinner size="sm" />}

          <button
            onClick={() => !disableSelector && setIsModalOpen(true)}
            disabled={disableSelector}
            className={`
               flex items-center gap-2 pl-2 pr-3 py-1.5 rounded-sm border border-transparent transition-all
               ${disableSelector
                ? 'cursor-default opacity-80'
                : 'hover:bg-xmr-base hover:border-xmr-border cursor-pointer active:scale-95'
              }
            `}
          >
            {currency ? (
              <>
                <div className="w-6 h-6 rounded-full bg-xmr-base border border-xmr-border flex items-center justify-center text-xs font-bold text-xmr-green overflow-hidden">
                  {currency.image ? <img src={currency.image} className="w-full h-full object-cover" /> : currency.ticker[0]}
                </div>

                <div className="flex flex-col items-start mr-1">
                  <span className="text-sm font-bold text-xmr-dim leading-none">{currency.ticker.toUpperCase()}</span>
                  <span className="text-[11px] text-xmr-dim uppercase font-bold">{currency.network}</span>
                </div>
              </>
            ) : (
              <span className="text-xmr-green font-bold text-sm animate-pulse">SELECT</span>
            )}

            {!disableSelector && <ChevronDown size={14} className="text-xmr-dim group-hover:text-xmr-green transition-colors" />}
            {(disableSelector && reserveArrowSpace) && <ChevronDown size={14} className="invisible text-xmr-dim group-hover:text-xmr-green transition-colors" />}
          </button>
        </div>

        {usdValue && (
          <div className="absolute -bottom-5 left-1 text-[11px] font-mono text-xmr-dim flex items-center gap-1">
            ≈ ${usdValue} <span className="opacity-50">USD</span>
          </div>
        )}
      </div>

      {error && (
        <div className="text-xmr-error text-xs mt-2 pl-1 font-bold animate-pulse flex items-center gap-1">
          !!! {error}
        </div>
      )}

      {isModalOpen && createPortal(modalContent, document.body)}
    </div>
  );
}