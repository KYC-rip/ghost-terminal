/* eslint-disable react-hooks/set-state-in-effect */
import { useState, useEffect, useMemo, useRef } from "react";
import { createPortal } from "react-dom";
import { Search, ChevronDown, Check, Coins, X } from "lucide-react";
import type { Currency } from "../hooks/useCurrencies";

type ThemeColor = 'xmr-green' | 'xmr-ghost' | 'xmr-accent' | 'xmr-warning' | 'xmr-error';

interface Props {
  selected: Currency;
  onSelect: (c: Currency) => void;
  label?: string;
  exclude?: string[];
  currencies?: Currency[];
  forceDark?: boolean;
  themeColor?: ThemeColor;
  hideBorder?: boolean;
  variant?: 'dropdown' | 'drawer';
  drawerTitle?: string;
}

function CurrencyList({ loading, displayList, filteredCount, selected, onSelect }: {
  loading: boolean;
  displayList: Currency[];
  filteredCount: number;
  selected: Currency;
  onSelect: (c: Currency) => void;
}) {
  if (loading) {
    return (
      <div className="py-8 text-center space-y-2">
        <Coins className="w-8 h-8 text-[var(--local-brand)]/50 mx-auto animate-bounce" />
        <div className="text-xs text-[var(--local-text-dim)] font-mono animate-pulse">SYNCING_ASSETS...</div>
      </div>
    );
  }
  if (displayList.length === 0) {
    return <div className="py-8 text-center text-[var(--local-text-dim)] text-xs font-mono">[ NO_ASSET_FOUND ]</div>;
  }
  return (
    <div className="space-y-1">
      {displayList.map((c) => {
        const isActive = selected.ticker === c.ticker && selected.network === c.network;
        return (
          <button
            type="button"
            key={`${c.ticker}-${c.network}`}
            onClick={() => onSelect(c)}
            className={`w-full flex items-center justify-between p-2 rounded-sm transition-colors group ${
              isActive
                ? "bg-[var(--local-bg-active)] border border-[var(--local-brand)]/30"
                : "hover:bg-[var(--local-bg-active)] border border-transparent"
            }`}
          >
            <div className="flex items-center gap-3">
              <div className={`w-8 h-8 rounded-full bg-[var(--color-xmr-surface)] flex items-center justify-center border shrink-0 ${isActive ? 'border-[var(--local-brand)]' : 'border-[var(--local-border)]'}`}>
                {c.image ? (
                  <img src={c.image} className="w-6 h-6 rounded-full" loading="lazy" />
                ) : (
                  <div className="text-xs text-[var(--local-text-dim)]">{c.ticker.substring(0, 1).toUpperCase()}</div>
                )}
              </div>
              <div className="text-left">
                <div className={`font-bold text-sm ${isActive ? "text-[var(--local-brand)]" : "text-[var(--local-text-dim)] group-hover:text-[var(--local-brand)]"}`}>
                  {c.ticker.toUpperCase()}
                </div>
                <div className="text-xs text-[var(--local-text-dim)] flex items-center gap-2">
                  {c.name}
                  <span className="bg-[var(--color-xmr-surface)] border border-[var(--local-border)] px-1 rounded-sm text-[var(--local-text-dim)]/80">
                    {c.network}
                  </span>
                </div>
              </div>
            </div>
            {isActive && <Check size={16} className="text-[var(--local-brand)]" />}
          </button>
        );
      })}
      {filteredCount > 100 && (
        <div className="text-center py-2 text-xs text-[var(--local-text-dim)] border-t border-[var(--local-border)] mt-2">
          + {filteredCount - 100} MORE COINS... SEARCH TO FIND
        </div>
      )}
    </div>
  );
}

export function CurrencySelector({
  selected,
  onSelect,
  label = "Pay using",
  currencies: externalCurrencies,
  exclude = [],
  forceDark = false,
  themeColor = 'xmr-green',
  hideBorder = false,
  variant = 'dropdown',
  drawerTitle = 'Select Asset',
}: Props) {
  const [isOpen, setIsOpen] = useState(false);
  const [_currencies, setCurrencies] = useState<Currency[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);

  const buttonRef = useRef<HTMLButtonElement>(null);
  const portalRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const [position, setPosition] = useState<{
    top: number;
    left: number;
    width: number;
  } | null>(null);

  // Dynamic Theme Style
  const themeStyle = {
    '--local-brand': `var(--color-${themeColor})`,
    '--local-border': `color-mix(in srgb, var(--color-${themeColor}), transparent 70%)`,
    '--local-bg-active': `color-mix(in srgb, var(--color-${themeColor}), transparent 90%)`,
    // If using custom theme, derive dim color from brand, otherwise use global dim (greenish)
    '--local-text-dim': themeColor === 'xmr-green'
      ? `var(--color-xmr-dim)`
      : `color-mix(in srgb, var(--color-${themeColor}), gray 40%)`,
  } as React.CSSProperties;


  useEffect(() => {
    if (externalCurrencies && externalCurrencies.length > 0) {
      setCurrencies(externalCurrencies);
    }
  }, [externalCurrencies]);


  useEffect(() => {
    if (isOpen && _currencies.length === 0 && !externalCurrencies) {
      setLoading(true);
      fetch("https://api.kyc.rip/v2/exchange/currencies")
        .then((res) => res.json())
        .then((data) => {
          setCurrencies(data);
          setLoading(false);
          setTimeout(() => inputRef.current?.focus(), 100);
        })
        .catch((err) => {
          console.error(err);
          setLoading(false);
        });
    }
  }, [isOpen]);


  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        buttonRef.current &&
        !buttonRef.current.contains(event.target as Node) &&
        portalRef.current &&
        !portalRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
        setSearch("");
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);


  useEffect(() => {
    if (!isOpen) {
      setPosition(null);
      return;
    }

    const updatePosition = () => {
      if (buttonRef.current) {
        const rect = buttonRef.current.getBoundingClientRect();
        setPosition({
          top: rect.bottom + 8,
          left: rect.left,
          width: rect.width,
        });
      }
    };

    updatePosition();
    window.addEventListener("scroll", updatePosition, true);
    window.addEventListener("resize", updatePosition);

    return () => {
      window.removeEventListener("scroll", updatePosition, true);
      window.removeEventListener("resize", updatePosition);
    };
  }, [isOpen]);


  const includedCurrencies = useMemo(() => _currencies.filter((c) => !exclude.includes(c.id)), [_currencies, exclude]);

  const filteredList = useMemo(() => {
    if (!search) return includedCurrencies;

    const lowerSearch = search.toLowerCase();

    const getScore = (c: Currency) => {
      const tickerLower = c.ticker.toLowerCase();
      const nameLower = c.name.toLowerCase();
      const networkLower = c.network?.toLowerCase() ?? "";

      if (tickerLower === lowerSearch) return 5;
      if (tickerLower.startsWith(lowerSearch)) return 4;
      if (tickerLower.includes(lowerSearch)) return 3;

      if (nameLower.includes(lowerSearch)) return 2;
      if (networkLower.includes(lowerSearch)) return 1;

      return 0;
    };

    const isMainnet = (c: Currency) => {
      const tickerLower = c.ticker.toLowerCase();
      const networkLower = c.network?.toLowerCase() ?? "";

      if (networkLower.includes("mainnet")) return true;

      if (tickerLower === "usdt" || tickerLower === "usdc") {
        if (networkLower.includes("erc20") || networkLower.includes("trc20")) {
          return true;
        }
      }

      return false;
    };

    return includedCurrencies
      .filter(
        (c) =>
          c.ticker.toLowerCase().includes(lowerSearch) ||
          c.name.toLowerCase().includes(lowerSearch) ||
          (c.network && c.network.toLowerCase().includes(lowerSearch))
      )
      .sort((a, b) => {
        const scoreA = getScore(a);
        const scoreB = getScore(b);

        if (scoreA !== scoreB) return scoreB - scoreA;

        const mainnetA = isMainnet(a);
        const mainnetB = isMainnet(b);
        if (mainnetA && !mainnetB) return -1;
        if (!mainnetA && mainnetB) return 1;

        return a.ticker.localeCompare(b.ticker);
      });
  }, [includedCurrencies, search]);

  const displayList = filteredList.slice(0, 100);
  const bg = hideBorder ? 'bg-transparent' : 'bg-[var(--color-xmr-surface)]  shadow-sm';

  return (

    <div
      className={`w-full space-y-2 ${forceDark ? 'dark' : ''}`}
      style={themeStyle}
    >
      {label && (
        <label className="text-xs text-[var(--local-text-dim)] uppercase tracking-wider font-mono">
          {label}
        </label>
      )}

      <div className="relative">
        <button
          ref={buttonRef}
          type="button"
          onClick={() => setIsOpen(!isOpen)}

          className={`w-full flex items-center justify-between px-2 md:px-4 py-2.5 rounded-sm transition-all duration-200 ${hideBorder ? 'border-0' : 'border'}
            ${bg} text-[var(--local-text-dim)] 
            ${isOpen
              ? "ring-1 ring-[var(--local-brand)]/50 border-[var(--local-brand)] text-[var(--local-brand)]"
              : "border-[var(--local-border)] hover:border-[var(--local-brand)]/50 hover:text-[var(--local-brand)]"
            } 
          `}
        >
          <div className="flex items-center gap-1 md:gap-3 overflow-hidden">
            <div className={`w-5 h-5 rounded-full bg-[var(--color-xmr-surface)] flex items-center justify-center shrink-0 overflow-hidden border ${isOpen ? "border-[var(--local-brand)]" : "border-[var(--local-border)]"}`}>
              {selected?.image ? (
                <img
                  src={selected.image}
                  alt={selected.ticker}
                  className="w-full h-full object-cover"
                  onError={(e) => (e.currentTarget.style.display = "none")}
                />
              ) : (
                <span className="text-[11px] font-bold text-[var(--local-brand)]">
                  {selected.ticker.substring(0, 2).toUpperCase()}
                </span>
              )}
            </div>

            <div className="flex items-baseline gap-2 overflow-hidden">
              <span className={`font-bold text-sm ${isOpen ? "text-[var(--local-brand)]" : "text-[var(--local-text-dim)]"}`}>
                {selected.ticker.toUpperCase()}
              </span>
              {selected.network !== "Mainnet" &&
                <span className="text-xs text-[var(--local-text-dim)] opacity-70 font-mono truncate max-w-[150px]">
                  {selected.network}
                </span>
              }
            </div>
          </div>

          <ChevronDown
            size={16}
            className={`transition-transform duration-200 ${isOpen ? "rotate-180 text-[var(--local-brand)]" : "text-[var(--local-text-dim)]"
              }`}
          />
        </button>

        {/* ── Shared list content (used by both dropdown and drawer) ── */}
        {isOpen && createPortal(
          variant === 'drawer' ? (
            /* ══════ DRAWER VARIANT ══════ */
            <>
              <div
                className="fixed inset-0 bg-black/40 backdrop-blur-sm z-[99]"
                onClick={() => { setIsOpen(false); setSearch(""); }}
                style={themeStyle}
              />
              <div
                ref={portalRef}
                className={`fixed top-0 right-0 h-full w-80 bg-[var(--color-xmr-surface)] border-l border-[var(--local-border)] z-[100] flex flex-col shadow-2xl animate-in slide-in-from-right duration-200 ${forceDark ? 'dark' : ''}`}
                style={themeStyle}
              >
                {/* Drawer header */}
                <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--local-border)] bg-[var(--color-xmr-base)]/50">
                  <div className="flex items-center gap-2">
                    <Coins size={14} className="text-[var(--local-brand)]" />
                    <span className="text-[11px] font-black uppercase tracking-widest text-[var(--local-brand)]">{drawerTitle}</span>
                  </div>
                  <button
                    onClick={() => { setIsOpen(false); setSearch(""); }}
                    className="text-[var(--local-text-dim)] hover:text-[var(--local-brand)] transition-colors cursor-pointer p-1"
                  >
                    <X size={16} />
                  </button>
                </div>

                {/* Search */}
                <div className="p-3 border-b border-[var(--local-border)] bg-[var(--color-xmr-surface)]">
                  <div className="relative">
                    <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--local-text-dim)]" />
                    <input
                      ref={inputRef}
                      type="text"
                      placeholder="SEARCH ASSETS..."
                      className="w-full rounded-sm pl-9 pr-4 py-2 text-xs focus:outline-none uppercase bg-[var(--color-xmr-base)] border border-[var(--local-border)] text-[var(--text-primary)] focus:border-[var(--local-brand)] placeholder:text-[var(--local-text-dim)]"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </div>
                </div>

                {/* List */}
                <div className="overflow-y-auto flex-1 custom-scrollbar p-1.5 bg-[var(--color-xmr-base)]">
                  <CurrencyList
                    loading={loading}
                    displayList={displayList}
                    filteredCount={filteredList.length}
                    selected={selected}
                    onSelect={(c) => { onSelect(c); setIsOpen(false); setSearch(""); }}
                  />
                </div>

                {/* Footer */}
                {!loading && (
                  <div className="px-4 py-2 border-t border-[var(--local-border)] bg-[var(--color-xmr-surface)] text-[10px] text-[var(--local-text-dim)] flex justify-between font-mono uppercase tracking-wider">
                    <span>Online</span>
                    <span>{includedCurrencies.length} assets</span>
                  </div>
                )}
              </div>
            </>
          ) : (
            /* ══════ DROPDOWN VARIANT ══════ */
            position ? (
              <div
                ref={portalRef}
                className={`fixed z-[100] rounded-sm shadow-2xl flex flex-col max-h-[48vh] md:max-h-[40vh] animate-in fade-in zoom-in-95 duration-100
                   ${forceDark ? 'dark' : ''}
                   bg-[var(--color-xmr-surface)] border border-[var(--local-border)]
                `}
                style={{
                  top: position.top,
                  left: position.left,
                  width: Math.max(position.width, 280),
                  ...themeStyle
                }}
              >
                {/* Search Input */}
                <div className="p-3 border-b border-[var(--local-border)] sticky top-0 bg-[var(--color-xmr-surface)] z-10 rounded-t-sm">
                  <div className="relative">
                    <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--local-text-dim)]" />
                    <input
                      ref={inputRef}
                      type="text"
                      placeholder="SEARCH ASSETS..."
                      className="w-full rounded-sm pl-10 pr-4 py-2 text-xs focus:outline-none uppercase bg-[var(--color-xmr-base)] border border-[var(--local-border)] text-[var(--text-primary)] focus:border-[var(--local-brand)] placeholder:text-[var(--local-text-dim)]"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </div>
                </div>

                {/* List */}
                <div className="overflow-y-auto flex-1 custom-scrollbar p-1 bg-[var(--color-xmr-base)]">
                  <CurrencyList
                    loading={loading}
                    displayList={displayList}
                    filteredCount={filteredList.length}
                    selected={selected}
                    onSelect={(c) => { onSelect(c); setIsOpen(false); setSearch(""); }}
                  />
                </div>

                {/* Footer Status */}
                {!loading && (
                  <div className="p-2 border-t border-[var(--local-border)] bg-[var(--color-xmr-surface)] text-xs text-[var(--local-text-dim)] flex justify-between rounded-b-sm font-mono">
                    <span>STATUS: ONLINE</span>
                    <span>{includedCurrencies.length} ASSETS</span>
                  </div>
                )}
              </div>
            ) : null
          ),
          document.body
        )}
      </div>
    </div>
  );
}

CurrencySelector.defaultCurrency = CurrencySelector.Monero = {
  id: "xmr",
  ticker: "xmr",
  name: "Monero",
  network: "Mainnet",
  image: "https://trocador.app/static/img/icons/xmr.svg",
  memo: false,
  minimum: 0.014836,
  maximum: 4635.966921408024,
};

CurrencySelector.Bitcoin = {
  id: "btc",
  ticker: "btc",
  name: "Bitcoin",
  network: "Mainnet",
  image: "https://trocador.app/static/img/icons/btc.svg",
  is_fiat: false,
  minimum: 0.000064,
  maximum: 20,
  memo: false,
};

CurrencySelector.TetherTRC20 = {
  id: "usdt-trc20",
  ticker: "usdt",
  name: "Tether (TRC20)",
  network: "TRC20",
  image: "https://trocador.app/static/img/icons/usdt.svg",
  is_fiat: false,
  minimum: 6,
  maximum: 1824790.4140712677,
  memo: false,
};