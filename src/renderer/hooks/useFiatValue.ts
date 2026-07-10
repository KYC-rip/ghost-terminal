// ui/src/hooks/useFiatValue.ts
import { useState, useEffect } from 'react';
import { isStressnet } from '../utils/networkMode';

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
    // Stressnet coins have no fiat price — suppress all fiat display
    if (isStressnet()) {
        setFiatText(null);
        setPremium(null);
        return;
    }
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

    const fetchValue = async () => {
      try {
        const res = await fetch(`https://min-api.cryptocompare.com/data/price?fsym=${sym}&tsyms=USD`);
        const data = await res.json();
        
        if (data.USD) {
          priceCache[sym] = { price: data.USD, timestamp: Date.now() };
          updateUI(data.USD);
        }
      } catch (e) {
        console.warn('Fiat fetch error:', e);
      }
    };

    fetchValue();
    
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ticker, amount, withPrefix]);

  return { fiatText, premium };
}