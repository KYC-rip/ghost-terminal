// ui/src/hooks/useFiatValue.ts
import { useState, useEffect } from 'react';
import { getApiBase } from '../services/client';

// struct: { "BTC": { price: 98000, timestamp: 1712345678900 } }
const priceCache: Record<string, { price: number; timestamp: number }> = {};
const CACHE_DURATION = 10000; // 10 seconds cache time

export function useFiatValue(ticker?: string, amount?: string | number, withPrefix: boolean = true, faceValue?: number | string) {
  const [fiatText, setFiatText] = useState<string | null>(null);
  const [premium, setPremium] = useState<string | null>(null);

  const calculatePremium = (realCost: number, targetValue: number | string) => {
    const target = typeof targetValue === 'string' ? parseFloat(targetValue) : targetValue;
    if (!target || isNaN(target) || target === 0) return;
    
    const diff = realCost - target;
    const percent = (diff / target) * 100;

    // Only show if the spread is within a "human" range (less than 200%)
    if (Math.abs(percent) < 200) { 
      const sign = percent > 0 ? '+' : '';
      setPremium(`${sign}${percent.toFixed(1)}%`);
    } else {
      setPremium(null);
    }
  };

  useEffect(() => {
    if (!ticker || amount === undefined || amount === null || amount === '') {
        setFiatText(null);
        setPremium(null);
        return;
    }

    const sym = ticker.replace(/SXMR/i, "XMR").replace(/SETH/i, "ETH").toUpperCase();
    const val = typeof amount === 'string' ? parseFloat(amount) : amount;

    if (isNaN(val)) return;

    if (['USDT', 'USDC', 'DAI', 'BUSD'].includes(sym) || sym.startsWith("USD")) {
      const formatted = withPrefix ? `$${val.toFixed(2)}` : val.toString();
      setFiatText(formatted);
      if (faceValue) calculatePremium(val, faceValue);
      else setPremium(null);
      return;
    }

    const updateUI = (unitPrice: number) => {
        const total = val * unitPrice;
        
        if (withPrefix) {
            const decimals = total > 1 ? 2 : 4; 
            setFiatText(`≈ $${total.toFixed(decimals)}`);
        } else {
            setFiatText(total.toString());
        }
        
        if (faceValue !== undefined && faceValue !== null) {
          calculatePremium(total, faceValue);
        } else {
          setPremium(null);
        }
    };

    const now = Date.now();
    const cachedData = priceCache[sym];

    if (cachedData && (now - cachedData.timestamp < CACHE_DURATION)) {
      updateUI(cachedData.price);
      return;
    }

    // Primary: our own API (CORS-enabled, multi-source server-side chain,
    // KV-cached ~5min, reachable over Tor like all api.kyc.rip traffic).
    // Kraken/Binance REST block browser CORS, so they are useless from the
    // renderer; CoinGecko allows CORS and serves as the only direct fallback.
    const fetchKycRip = async (): Promise<number | null> => {
      const base = getApiBase().replace(/\/$/, '');
      const res = await fetch(`${base}/v1/price/${sym}`);
      if (!res.ok) return null;
      const data = await res.json();
      return data?.usd > 0 ? data.usd : null;
    };

    const COINGECKO_IDS: Record<string, string> = {
      BTC: 'bitcoin', ETH: 'ethereum', XMR: 'monero', SOL: 'solana',
      LTC: 'litecoin', BCH: 'bitcoin-cash', DOGE: 'dogecoin', BNB: 'binancecoin',
      TRX: 'tron', XRP: 'ripple', AVAX: 'avalanche-2', POL: 'matic-network',
      MATIC: 'matic-network', ZEC: 'zcash',
    };

    const fetchCoinGecko = async (): Promise<number | null> => {
      const id = COINGECKO_IDS[sym];
      if (!id) return null;
      const res = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${id}&vs_currencies=usd`);
      const data = await res.json();
      const price = data?.[id]?.usd;
      return price > 0 ? price : null;
    };

    const fetchValue = async () => {
      for (const source of [fetchKycRip, fetchCoinGecko]) {
        try {
          const price = await source();
          if (price) {
            priceCache[sym] = { price, timestamp: Date.now() };
            updateUI(price);
            return;
          }
        } catch (e) {
          console.warn('Fiat fetch error:', e);
        }
      }
    };

    fetchValue();
    
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ticker, amount, withPrefix]);

  return { fiatText, premium };
}