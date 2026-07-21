import React, { Suspense } from 'react';
import { Activity, BarChart3, Globe, Lock, Ghost, TrendingUp, AlertTriangle } from 'lucide-react';
import { useTheme } from '../hooks/useTheme';
import { Card } from './Card';

const SpreadChart = React.lazy(() => import('./SpreadChart'));

interface HomeViewProps {
   setView: (v: 'home' | 'vault' | 'settings') => void;
  stats: any;
  loading: boolean;
}

export function HomeView({ setView, stats, loading }: HomeViewProps) {
  const { resolvedTheme } = useTheme();

  const Row = ({ label, value, highlight = false, alert = false }: any) => (
    <div className="flex justify-between items-center py-1.5 border-b border-xmr-border/10 group/row">
      <span className="text-xs text-xmr-dim uppercase tracking-wider group-hover/row:text-xmr-green transition-colors">{label}</span>
      <span className={`text-[11px] font-black tracking-tight ${alert ? 'text-xmr-accent animate-pulse' : (highlight ? 'text-xmr-green' : 'text-xmr-green/80')}`}>
        {loading ? '---' : value}
      </span>
    </div>
  );

  return (
    <div className="max-w-6xl mx-auto space-y-10 py-4 animate-in fade-in duration-700 font-mono">
      {/* 1. HERO PRICE SECTION */}
      <Card topGradientAccentColor="xmr-accent" className="relative !p-10 flex flex-col md:flex-row items-center justify-between gap-8 group">
        <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
           <Globe size={200} className="animate-[spin_60s_linear_infinite]" />
        </div>
        
        <div className="relative z-10 space-y-4 text-center md:text-left">
           <div className="flex items-center gap-2 text-xmr-dim text-xs font-black uppercase tracking-[0.4em]">
              <div className="w-2 h-2 bg-xmr-green rounded-full animate-pulse"></div>
              Real_Market_Price (No-KYC)
           </div>
           <div className="relative inline-block">
              <h1 className="text-8xl font-black text-xmr-accent tracking-tighter" style={{ fontFamily: 'var(--font-display)' }}>
                ${loading ? '---.--' : stats?.price.street}
              </h1>
              {!loading && stats?.price.premium && (
                <div className="absolute -top-2 -right-12 px-2 py-0.5 border border-xmr-accent text-xmr-accent text-[11px] font-black rotate-12 bg-xmr-base">
                  +{stats?.price.premium}% PREMIUM
                </div>
              )}
           </div>
           <div className="text-xs text-xmr-dim font-black uppercase tracking-widest flex items-center gap-4">
              <span>Paper_Price: <span className="line-through opacity-50">${stats?.price.paper || '---.--'}</span></span>
              <span>Source: <span className="text-xmr-green">[{stats?.price.source || 'SCANNING'}]</span></span>
           </div>
        </div>

        <div className="relative z-10 w-full md:w-64 space-y-3 bg-xmr-green/[0.03] p-4 border border-xmr-border/30 backdrop-blur-md">
           <div className="text-[11px] font-black text-xmr-green border-b border-xmr-border/20 pb-2 mb-2 uppercase italic flex items-center gap-2">
              <TrendingUp size={12} /> Quick_Stats
           </div>
           <div className="flex justify-between text-xs font-black">
              <span className="text-xmr-dim uppercase">24H_Pulse</span>
              <span className="text-xmr-green">{stats?.network.tx_count_24h?.toLocaleString() || '---'} TXs</span>
           </div>
           <div className="flex justify-between text-xs font-black">
              <span className="text-xmr-dim uppercase">Privacy_Score</span>
              <span className="text-xmr-green">{stats?.resistance.privacy_percentage || '--'}%</span>
           </div>
           <div className="flex justify-between text-xs font-black">
              <span className="text-xmr-dim uppercase">CEX_Status</span>
              <span className="text-xmr-accent animate-pulse">{stats?.resistance.cex_status || 'OK'}</span>
           </div>
        </div>
      </Card>

      {/* 2. DATA GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card topGradientAccentColor="xmr-green" className="relative transition-all">
          <h3 className="text-sm font-black text-xmr-green uppercase mb-6 flex items-center gap-2 border-b border-xmr-border/20 pb-4 italic tracking-widest">
            <Activity size={16} /> Network_Uplink_Intel
          </h3>
          <div className="space-y-1">
             <Row label="Current_Height" value={stats?.network.height} highlight />
             <Row label="Hashrate_Agg" value={stats?.network.hashrate} />
             <Row label="Network_Difficulty" value={stats?.network.difficulty} />
             <Row label="Tx_Fees_Est" value={stats?.network.fees} highlight />
             <Row label="Block_Reward" value={stats?.network.reward} />
             <Row label="Mempool_Congestion" value={`${stats?.network.mempool || 0} TXs`} alert={(stats?.network.mempool || 0) > 50} />
          </div>
        </Card>

        <Card topGradientAccentColor="xmr-accent" className="relative transition-all">
          <h3 className="text-sm font-black text-xmr-accent uppercase mb-6 flex items-center gap-2 border-b border-xmr-border/20 pb-4 italic tracking-widest">
            <BarChart3 size={16} /> Market_Resistance_Analysis
          </h3>
          <div className="space-y-1">
             <Row label="XMR_BTC_Ratio" value={stats?.market.xmr_btc} highlight />
             <Row label="Market_Cap" value={stats?.market.cap} />
             <Row label="24H_Volume" value={stats?.market.volume} />
             <Row label="Circulating_Supply" value={stats?.market.supply} />
             <Row label="P2P_Liquidity_Est" value={stats?.resistance.p2p_liquidity} highlight />
             <Row label="Total_Nodes_Global" value={stats?.resistance.total_nodes} />
          </div>
        </Card>
      </div>

      {/* 3. TACTICAL SHORTCUTS */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
         <button onClick={() => setView('vault')} className="group text-left cursor-pointer">
            <Card topGradientAccentColor="xmr-green" className="hover:bg-xmr-green/5 transition-all relative overflow-hidden h-full">
               <Lock size={20} className="mb-4 text-xmr-green" />
               <h4 className="text-xs font-black uppercase text-xmr-green mb-1">Vault_Access</h4>
               <p className="text-xs text-xmr-dim uppercase leading-tight">Secure ledger management and subaddress generation.</p>
               <div className="absolute -bottom-2 -right-2 opacity-5 rotate-12 group-hover:opacity-10 transition-opacity"><Lock size={80}/></div>
            </Card>
         </button>

           <button onClick={() => setView('vault')} className="group text-left cursor-pointer">
            <Card topGradientAccentColor="xmr-accent" className="hover:bg-xmr-accent/5 transition-all relative overflow-hidden h-full">
               <Ghost size={20} className="mb-4 text-xmr-accent" />
                 <h4 className="text-xs font-black uppercase text-xmr-accent mb-1">Ripley_Send</h4>
                 <p className="text-xs text-xmr-dim uppercase leading-tight">Send XMR — receiver gets any asset. Zero identity link.</p>
               <div className="absolute -bottom-2 -right-2 opacity-5 rotate-12 group-hover:opacity-10 transition-opacity"><Ghost size={80}/></div>
            </Card>
         </button>

         <Card topGradientAccentColor="xmr-dim" className="flex flex-col justify-center relative overflow-hidden">
            <div className="flex items-center gap-3 text-xmr-error animate-pulse">
               <AlertTriangle size={20} />
               <span className="text-xs font-black uppercase tracking-tighter">Sentinel_Active</span>
            </div>
            <p className="text-xs text-xmr-dim uppercase mt-2 leading-relaxed">
               Local environment is hardware-isolated. All outgoing traffic is routed through encrypted SOCKS5 tunnels.
            </p>
         </Card>
      </div>

      {/* 4. LOCAL TACTICAL CHART */}
      <Card withGlow={false} noPadding className="border-xmr-border/30 overflow-hidden">
         <Suspense fallback={<div className="h-64 flex items-center justify-center text-xs text-xmr-dim uppercase tracking-widest animate-pulse font-black">Initializing_Chart_Engine...</div>}>
            <SpreadChart />
         </Suspense>
      </Card>
    </div>
  );
}
