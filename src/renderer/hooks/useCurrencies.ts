/* eslint-disable @typescript-eslint/no-explicit-any */
// src/hooks/useCurrencies.ts
import { useState, useEffect } from 'react';
import { CurrencySelector } from '../components/CurrencySelector';
import { apiClient } from '../services/client';

export interface Currency {
  id: string;
  ticker: string;
  network: string;
  name: string;
  image?: string;
  minimum?: number;
  maximum?: number;
  memo?: boolean;
  balance?: string;
}

let cachedCurrencies: Currency[] = [];

const TESTNET_COINS: Currency[] = [
  {
    id: 'eth-sepolia',
    ticker: 'sETH',
    network: 'sepolia',
    name: 'Sepolia ETH (Testnet)',
    image: 'https://cryptologos.cc/logos/ethereum-eth-logo.png', // Reusing ETH logo
    minimum: 0.001,
    maximum: 10
  },
  {
    id: 'xmr-stagenet',
    ticker: 'sXMR',
    network: 'stagenet',
    name: 'Monero (Stagenet)',
    image: CurrencySelector.Monero.image,
    minimum: 0.001,
    maximum: 100
  },
  {
    id: 'tltc',
    ticker: 'tltc',
    name: 'Litecoin Testnet (tLTC)',
    network: 'Mainnet',
    image: 'https://trocador.app/static/img/icons/ltc.svg',
    minimum: 0.01,
    maximum: 100,
  }
];

export function useCurrencies() {
  const [currencies, setCurrencies] = useState<Currency[]>(cachedCurrencies);
  const [loading, setLoading] = useState(cachedCurrencies.length === 0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const searchParams = new URLSearchParams(window.location.search);
    const isTestnet = searchParams.get('testnet') === 'true';

    if (cachedCurrencies.length > 0) {
      setLoading(false);
      return;
    }

    const fetchCurrencies = async () => {
      try {
        setLoading(true);

        // Add a 10-second timeout to the fetch call
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        try {
          const data = await apiClient<Currency[]>("/v2/exchange/currencies", {
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          let finalData = data;
          if (isTestnet) {
            finalData = [...data, ...TESTNET_COINS];
          }

          cachedCurrencies = finalData;
          setCurrencies(finalData);
        } catch (fetchErr: any) {
          clearTimeout(timeoutId);
          console.warn("[useCurrencies] Fetch failed or timed out, using empty fallback.");
          // If we have nothing, we keep the empty array but stop loading
          setError(fetchErr.name === 'AbortError' ? "Network Timeout" : fetchErr.message);
        }
      } catch (err: any) {
        console.error(err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchCurrencies();
  }, []);


  const findCurrency = (ticker: string, network?: string, additionalComparer?: (c: Currency) => boolean) => {
    if (!ticker) return null;
    return currencies.find(c =>
      c.ticker.toLowerCase() === ticker.toLowerCase() &&
      (!network || c.network.toLowerCase() === network.toLowerCase()) &&
      (!additionalComparer || additionalComparer(c))
    );
  };

  return { currencies, loading, error, findCurrency };
}
