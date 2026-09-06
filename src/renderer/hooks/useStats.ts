import { useState, useEffect, useMemo } from 'react';

export interface Stats {
  price: { paper: string; street: string; premium: string, source: string };
  market: { cap: string; volume: string; xmr_btc: string, supply: string, inflation: string };
  network: { 
    hashrate: string; 
    fees: string; 
    tx_count: string; 
    tx_count_24h: string; 
    mempool: number; 
    height: string; 
    difficulty: string; 
    reward: string; 
    algo: string 
  };
  resistance: { 
    cex_status: string; 
    decentralization: string; 
    privacy_percentage: string; 
    total_nodes: string; 
    privacy_nodes: string; 
    p2p_liquidity: string 
  };
  timestamp: string;
  _source: string;
}

export function useStats() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = async () => {
    try {
      // Direct call to main process proxy which handles Tor internally
      const result = await fetch('https://api.kyc.rip/v1/stats', {
        method: 'GET'
      });
      
      if (result && result.ok) {
        const data = await result.json();
        setStats(data);
      }
    } catch (err: any) {
      console.warn("[Stats] Uplink issue:", err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 60000);
    return () => clearInterval(interval);
  }, []);

  return useMemo(() => ({ stats, loading, refresh: fetchData }), [stats, loading]);
}
