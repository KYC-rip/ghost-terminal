/* eslint-disable @typescript-eslint/no-explicit-any */
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTheme } from '../hooks/useTheme';
import {
  createChart,
  ColorType,
  type IChartApi,
  AreaSeries,
  LineSeries,
  HistogramSeries,
  type MouseEventParams
} from 'lightweight-charts';

type TimeFrame = '24h' | '7d' | '30d' | 'all';

export default function SpreadChart() {
  const { resolvedTheme: theme } = useTheme(); 
  const chartContainerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<IChartApi | null>(null);

  const areaSeriesRef = useRef<any>(null);
  const lineSeriesRef = useRef<any>(null);
  const histogramSeriesRef = useRef<any>(null);
  const liquiditySeriesRef = useRef<any>(null);
  const nodeSeriesRef = useRef<any>(null);

  const [timeframe, setTimeframe] = useState<TimeFrame>('7d');
  const [isLoading, setIsLoading] = useState(false);
  const [hasDeepIntel, setHasDeepIntel] = useState(false);
  const [historyData, setHistoryData] = useState<any[]>([]);
  
  const [visibleSeries, setVisibleSeries] = useState({ street: true, paper: true, vol: true, liq: true, nodes: true });

  const [hoverData, setHoverData] = useState<{
    street: number; paper: number; premium: string;
    txActivity?: number; liquidity?: number; nodes?: number;
    dateStr: string;
  } | null>(null);

  const colors = useMemo(() => {
    const root = getComputedStyle(document.documentElement);
    const brandColor = root.getPropertyValue('--brand-color').trim();
    const borderColor = root.getPropertyValue('--border-color').trim();
    const textPrimary = root.getPropertyValue('--text-primary').trim();
    const textDim = root.getPropertyValue('--text-dim').trim();
    const chartLine = root.getPropertyValue('--chart-line').trim();
    const chartAreaTop = root.getPropertyValue('--chart-area-top').trim();
    const chartGrid = root.getPropertyValue('--chart-grid').trim();
    const textAccent = root.getPropertyValue('--text-accent').trim();
    return {
      text: textPrimary || '#00ff41',
      grid: chartGrid || 'rgba(20, 60, 20, 0.3)',
      border: borderColor || '#004d13',
      areaLine: chartLine || brandColor,
      areaTop: chartAreaTop || 'rgba(0, 255, 65, 0.15)',
      paperLine: textDim || '#64748b',
      liqLine: textAccent || '#ea580c',
      nodeLine: '#0891b2',
      volColor: theme === 'light' ? 'rgba(4, 120, 87, 0.3)' : 'rgba(0, 50, 0, 0.5)',
    };
  }, [theme]);

  const toggleSeries = (key: keyof typeof visibleSeries) => {
    setVisibleSeries((prev: any) => ({ ...prev, [key]: !prev[key] }));
  };

  useEffect(() => {
    let active = true;
    const fetchData = async () => {
      setIsLoading(true);
      try {
        // Routed through the uplink (Tor .onion mirror / clearnet) — no IP leak.
        const body = await window.api.proxiedGet(`https://api.kyc.rip/v1/history?period=${timeframe}`);
        const result = JSON.parse(body);
        
        if (active && Array.isArray(result)) {
          const cleanData = result
            .filter((d: any) => d.timestamp && !isNaN(d.timestamp))
            .sort((a: any, b: any) => a.timestamp - b.timestamp)
            .filter((item: any, index: number, self: any[]) => 
              index === 0 || item.timestamp !== self[index - 1].timestamp
            );
          
          setHistoryData(cleanData);
        }
      } catch (e) {
        console.error("Fetch history failed", e);
      } finally {
        if (active) setIsLoading(false);
      }
    };
    fetchData();
    return () => { active = false; };
  }, [timeframe]);

  useEffect(() => {
    if (!chartContainerRef.current) return;

    const chart = createChart(chartContainerRef.current, {
      layout: {
        textColor: colors.text,
        background: { type: ColorType.Solid, color: 'transparent' },
        fontFamily: "'JetBrains Mono', monospace",
        attributionLogo: false
      },
      grid: { vertLines: { color: colors.grid }, horzLines: { color: colors.grid } },
      width: chartContainerRef.current.clientWidth,
      height: 280,
      timeScale: { timeVisible: true, borderColor: colors.border },
      rightPriceScale: { borderColor: colors.border, scaleMargins: { top: 0.2, bottom: 0.2 } },
    });

    histogramSeriesRef.current = chart.addSeries(HistogramSeries, { color: colors.volColor, priceScaleId: 'volume', visible: visibleSeries.vol });
    chart.priceScale('volume').applyOptions({ scaleMargins: { top: 0.85, bottom: 0 }, visible: false });

    areaSeriesRef.current = chart.addSeries(AreaSeries, { lineColor: colors.areaLine, topColor: colors.areaTop, bottomColor: 'rgba(0,0,0,0)', lineWidth: 2, visible: visibleSeries.street });
    lineSeriesRef.current = chart.addSeries(LineSeries, { color: colors.paperLine, lineWidth: 1, lineStyle: 2, crosshairMarkerVisible: false, visible: visibleSeries.paper });
    liquiditySeriesRef.current = chart.addSeries(LineSeries, { color: colors.liqLine, lineWidth: 1, priceScaleId: 'liquidity', visible: visibleSeries.liq });
    chart.priceScale('liquidity').applyOptions({ scaleMargins: { top: 0.1, bottom: 0.4 }, visible: false });
    nodeSeriesRef.current = chart.addSeries(LineSeries, { color: colors.nodeLine, lineWidth: 1, priceScaleId: 'nodes', visible: visibleSeries.nodes });
    chart.priceScale('nodes').applyOptions({ scaleMargins: { top: 0.7, bottom: 0.1 }, visible: false });

    if (historyData.length > 0) {
      try {
        areaSeriesRef.current.setData(historyData.map(d => ({ time: d.timestamp, value: d.street_price })));
        lineSeriesRef.current.setData(historyData.map(d => ({ time: d.timestamp, value: d.paper_price })));
        
        const hasIntel = historyData.some(d => (d.tx_activity || 0) > 0);
        setHasDeepIntel(hasIntel);
        
        if (hasIntel) {
          histogramSeriesRef.current.setData(historyData.map(d => ({
            time: d.timestamp, value: d.tx_activity || 0,
            color: (d.tx_activity || 0) > 4000 ? colors.areaLine : colors.volColor
          })));
          liquiditySeriesRef.current.setData(historyData.map(d => ({ time: d.timestamp, value: d.p2p_liquidity || 0 })));
          nodeSeriesRef.current.setData(historyData.map(d => ({ time: d.timestamp, value: d.privacy_nodes || 0 })));
        }
        chart.timeScale().fitContent();
      } catch (err) {
        console.error("Chart Render Error:", err);
      }
    }

    chart.subscribeCrosshairMove((param: MouseEventParams) => {
      if (!param.point || !param.time || param.point.x < 0 || param.point.y < 0) {
        setHoverData(null);
        return;
      }
      const street = (param.seriesData.get(areaSeriesRef.current) as any)?.value || 0;
      const paper = (param.seriesData.get(lineSeriesRef.current) as any)?.value || 0;
      if (street && paper) {
        const diff = street - paper;
        const prem = ((diff / paper) * 100).toFixed(2);
        const date = new Date((param.time as number) * 1000);
        setHoverData({
          street, paper, premium: `${diff >= 0 ? '+' : ''}${prem}%`,
          txActivity: (param.seriesData.get(histogramSeriesRef.current) as any)?.value,
          liquidity: (param.seriesData.get(liquiditySeriesRef.current) as any)?.value,
          nodes: (param.seriesData.get(nodeSeriesRef.current) as any)?.value,
          dateStr: `${(date.getMonth()+1).toString().padStart(2,'0')}-${date.getDate().toString().padStart(2,'0')} ${date.getHours().toString().padStart(2,'0')}:${date.getMinutes().toString().padStart(2,'0')}`
        });
      }
    });

    chartRef.current = chart;
    const handleResize = () => chart.applyOptions({ width: chartContainerRef.current?.clientWidth || 800 });
    window.addEventListener('resize', handleResize);
    return () => { window.removeEventListener('resize', handleResize); chart.remove(); };
  }, [theme, historyData]);

  useEffect(() => {
    if (!chartRef.current) return;
    areaSeriesRef.current?.applyOptions({ visible: visibleSeries.street });
    lineSeriesRef.current?.applyOptions({ visible: visibleSeries.paper });
    histogramSeriesRef.current?.applyOptions({ visible: visibleSeries.vol });
    liquiditySeriesRef.current?.applyOptions({ visible: visibleSeries.liq });
    nodeSeriesRef.current?.applyOptions({ visible: visibleSeries.nodes });
  }, [visibleSeries]);

  const TimeBtn = ({ period, label }: { period: TimeFrame, label: string }) => (
    <button
      onClick={() => setTimeframe(period)}
      className={`px-2 py-0.5 text-[11px] font-black border transition-all cursor-pointer ${timeframe === period ? 'bg-xmr-green text-xmr-base border-xmr-green' : 'text-xmr-dim border-xmr-border/30 hover:border-xmr-green/50'}`}
    >
      {label}
    </button>
  );

  return (
    <div className="relative w-full border border-xmr-border bg-xmr-surface py-6 px-4 rounded-sm animate-in fade-in duration-500">
      <div className="flex justify-between items-start mb-6 min-h-[48px]">
        <div className="flex flex-col flex-1 min-w-0">
          {hoverData ? (
            <div className="flex flex-col animate-in fade-in duration-100">
              <div className="text-xs text-xmr-green font-black tracking-widest mb-1 flex items-center gap-2">
                <span className="opacity-50">[{hoverData.dateStr}]</span>
                <span className="bg-xmr-green text-xmr-base px-1">PREMIUM: {hoverData.premium}</span>
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] font-black uppercase">
                <button onClick={() => toggleSeries('street')} className={`transition-all ${visibleSeries.street ? 'text-xmr-green' : 'text-xmr-dim opacity-30'}`}>STREET: ${hoverData.street.toFixed(2)}</button>
                <button onClick={() => toggleSeries('paper')} className={`transition-all ${visibleSeries.paper ? 'text-xmr-green opacity-60' : 'text-xmr-dim opacity-30'}`}>PAPER: ${hoverData.paper.toFixed(2)}</button>
                {hasDeepIntel && (
                  <>
                    <button onClick={() => toggleSeries('vol')} className={`transition-all border-l border-xmr-border/30 pl-3 ${visibleSeries.vol ? 'text-xmr-green' : 'text-xmr-dim opacity-30'}`}>TXs: {Math.floor(hoverData.txActivity || 0)}</button>
                    <button onClick={() => toggleSeries('liq')} className={`transition-all ${visibleSeries.liq ? 'text-xmr-accent' : 'text-xmr-dim opacity-30'}`}>LIQ: {Math.floor(hoverData.liquidity || 0)}</button>
                    <button onClick={() => toggleSeries('nodes')} className={`transition-all ${visibleSeries.nodes ? 'text-xmr-green opacity-70' : 'text-xmr-dim opacity-30'}`}>NODES: {Math.floor(hoverData.nodes || 0)}</button>
                  </>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col">
              <div className="text-xs text-xmr-green font-black tracking-widest mb-1 flex items-center gap-2 uppercase">
                <div className={`w-1.5 h-1.5 rounded-full ${isLoading ? 'bg-xmr-warning' : 'bg-xmr-green animate-pulse'}`}></div>
                INTEL_FEED :: {isLoading ? 'SYNCING...' : 'LIVE'}
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] font-black uppercase">
                <button onClick={() => toggleSeries('street')} className={`transition-all ${visibleSeries.street ? 'text-xmr-green' : 'text-xmr-dim opacity-30'}`}>◼ STREET</button>
                <button onClick={() => toggleSeries('paper')} className={`transition-all ${visibleSeries.paper ? 'text-xmr-green opacity-50' : 'text-xmr-dim opacity-30'}`}>-- PAPER</button>
                {hasDeepIntel && (
                  <>
                    <button onClick={() => toggleSeries('vol')} className={`transition-all border-l border-xmr-border/30 pl-3 ${visibleSeries.vol ? 'text-xmr-green' : 'text-xmr-dim opacity-30'}`}>▮ VOL</button>
                    <button onClick={() => toggleSeries('liq')} className={`transition-all ${visibleSeries.liq ? 'text-xmr-accent' : 'text-xmr-dim opacity-30'}`}>~ LIQ</button>
                    <button onClick={() => toggleSeries('nodes')} className={`transition-all ${visibleSeries.nodes ? 'text-xmr-green opacity-70' : 'text-xmr-dim opacity-30'}`}>~ NODES</button>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
        <div className="flex gap-1 shrink-0 ml-4">
          <TimeBtn period="24h" label="24H" /><TimeBtn period="7d" label="7D" /><TimeBtn period="30d" label="30D" /><TimeBtn period="all" label="MAX" />
        </div>
      </div>
      <div ref={chartContainerRef} className="w-full h-[280px]" style={{ opacity: isLoading ? 0.4 : 1 }} />
      <div className="absolute bottom-6 right-6 pointer-events-none opacity-[0.03] select-none">
        <span className="text-5xl font-black text-xmr-green italic">KYC.RIP</span>
      </div>
    </div>
  );
}
