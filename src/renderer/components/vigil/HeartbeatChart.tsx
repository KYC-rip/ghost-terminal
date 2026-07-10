/* eslint-disable @typescript-eslint/no-explicit-any */
import { useEffect, useRef } from 'react';
import { createChart, ColorType, type IChartApi, type ISeriesApi, type Time, AreaSeries, LineSeries } from 'lightweight-charts';

interface Props {
  triggerPrice: number;
  stopPrice?: number;
  mode: 'SNIPE' | 'EJECT';
  isTriggered: boolean;
  realPrice?: number | null;
  /** Unix seconds, ascending, deduped — produced by the engine's tick buffer. */
  priceHistory: { time: number; value: number }[];
}

export function HeartbeatChart({ triggerPrice, stopPrice, mode, isTriggered, realPrice, priceHistory }: Props) {
  const chartContainerRef = useRef<HTMLDivElement>(null);
  const chartRef = useRef<IChartApi | null>(null);

  const seriesRef = useRef<ISeriesApi<"Area"> | null>(null);      // Price trend
  const mainLineRef = useRef<ISeriesApi<"Line"> | null>(null);    // Main target line (green)
  const stopLineRef = useRef<ISeriesApi<"Line"> | null>(null);    // Stop loss line (red)

  // Last time written to the series (lightweight-charts requires non-decreasing times)
  const lastTimeRef = useRef<number>(0);

  // Theme: read CSS variables once per mount (desktop has no useTheme-driven chart colors)
  const root = getComputedStyle(document.documentElement);
  const textDim = root.getPropertyValue('--text-dim').trim();
  const axisTextColor = textDim || '#64748b';

  // Color configuration
  const ghostColor = '#a855f7';
  const dangerColor = '#ef4444';
  const successColor = '#22c55e'; // xmr-green

  const lineColor = isTriggered ? dangerColor : ghostColor;
  const areaTopColor = isTriggered ? 'rgba(239, 68, 68, 0.4)' : 'rgba(168, 85, 247, 0.4)';
  const areaBottomColor = isTriggered ? 'rgba(239, 68, 68, 0.0)' : 'rgba(168, 85, 247, 0.0)';

  // --- A. Initialize chart ---
  useEffect(() => {
    if (!chartContainerRef.current) return;

    // Create the Chart instance
    const chart = createChart(chartContainerRef.current, {
      layout: {
        background: { type: ColorType.Solid, color: 'transparent' },
        textColor: axisTextColor,
        attributionLogo: false,
      },
      width: chartContainerRef.current.clientWidth,
      height: chartContainerRef.current.clientHeight,
      grid: {
        vertLines: { visible: false },
        horzLines: { visible: false },
      },
      rightPriceScale: { visible: false, borderVisible: false },
      leftPriceScale: {
        visible: false,
        borderVisible: false,
        ticksVisible: false,
        scaleMargins: { top: 0.2, bottom: 0.2 } // Leave top/bottom margins so lines don't touch the edges
      },
      timeScale: {
        visible: false,
        borderVisible: false,
        fixLeftEdge: false,
        fixRightEdge: true,
      },
      crosshair: {
        vertLine: { visible: false, labelVisible: false },
        horzLine: { visible: false, labelVisible: false },
      },
      handleScroll: false,
      handleScale: false,
    });

    // 1. Price trend (Area)
    const series = chart.addSeries(AreaSeries, {
      lineColor: lineColor,
      topColor: areaTopColor,
      bottomColor: areaBottomColor,
      lineWidth: 2,
      priceLineVisible: false,
      lastValueVisible: false,
      // Enforce a minimum visible range of ±0.25% around the mid so a quiet
      // market reads as a calm line instead of full-height micro-noise, and
      // genuinely flat stretches still get a sensible scale.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      autoscaleInfoProvider: (original: () => any) => {
        const res = original();
        if (res?.priceRange) {
          const { minValue, maxValue } = res.priceRange;
          const mid = (minValue + maxValue) / 2;
          const minSpan = mid * 0.005;
          if (maxValue - minValue < minSpan) {
            return { ...res, priceRange: { minValue: mid - minSpan / 2, maxValue: mid + minSpan / 2 } };
          }
        }
        return res;
      },
      crosshairMarkerVisible: true,
      priceScaleId: 'left',
    });

    // 2. Main target line (Target - Green/Primary)
    // Use a LineSeries to draw a horizontal line, which forces the chart scale to include this price
    const mainSeries = chart.addSeries(LineSeries, {
      color: 'transparent', // The line itself is transparent (we only look at the PriceLine)
      lastValueVisible: false,
      priceLineVisible: false,
      crosshairMarkerVisible: false,
      priceScaleId: 'left',
    });

    // Add the visible PriceLine
    mainSeries.createPriceLine({
      price: triggerPrice,
      color: successColor,
      lineWidth: 1,
      lineStyle: 2, // Dashed
      axisLabelVisible: false,
      title: mode === 'SNIPE' ? 'BUY DIP' : 'TAKE PROFIT',
    });

    // 3. Stop / breakout line (Stop - Red)
    // Only added when stopPrice exists and is > 0
    let stopSeries: ISeriesApi<"Line"> | null = null;

    if (stopPrice && stopPrice > 0) {
      stopSeries = chart.addSeries(LineSeries, {
        color: 'transparent',
        lastValueVisible: false,
        priceLineVisible: false,
        crosshairMarkerVisible: false,
        priceScaleId: 'left',
      });

      stopSeries.createPriceLine({
        price: stopPrice,
        color: dangerColor,
        lineWidth: 1,
        lineStyle: 1, // Dotted
        axisLabelVisible: false,
        title: mode === 'SNIPE' ? 'BREAKOUT' : 'STOP LOSS',
      });
    }

    chartRef.current = chart;
    seriesRef.current = series;
    mainLineRef.current = mainSeries;
    stopLineRef.current = stopSeries;
    lastTimeRef.current = 0;

    // Resize Observer
    const resizeObserver = new ResizeObserver(entries => {
      if (entries.length === 0 || !entries[0].target) return;
      const newRect = entries[0].contentRect;
      chart.applyOptions({ width: newRect.width, height: newRect.height });
      chart.timeScale().fitContent();
    });
    resizeObserver.observe(chartContainerRef.current);

    return () => {
      resizeObserver.disconnect();
      chart.remove();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [triggerPrice, stopPrice, mode]); // Dependencies include stopPrice

  // --- B. Seed history data (from the engine's tick buffer, no REST fetch on desktop) ---
  useEffect(() => {
    if (seriesRef.current && priceHistory.length > 0) {
      // 1. Seed price data
      seriesRef.current.setData(priceHistory.map(d => ({ time: d.time as Time, value: d.value })));

      // 2. Seed helper line data (to stretch the Y axis range)
      // The hidden series must contain data so the chart auto-scales to
      // include these prices — but ONLY when the target is within reach.
      // Forcing a far-away target (e.g. +60%) into frame flattens the live
      // price into a dead horizontal line; beyond the band we let the price
      // action own the scale and the dashed line sits off-frame.
      const lastValue = priceHistory[priceHistory.length - 1].value;
      const inBand = (p: number) => lastValue > 0 && Math.abs(p - lastValue) / lastValue <= 0.15;

      const dataPoints = inBand(triggerPrice)
        ? priceHistory.map(d => ({ time: d.time as Time, value: triggerPrice }))
        : [];
      mainLineRef.current?.setData(dataPoints);

      if (stopLineRef.current && stopPrice) {
        const stopPoints = inBand(stopPrice)
          ? priceHistory.map(d => ({ time: d.time as Time, value: stopPrice }))
          : [];
        stopLineRef.current.setData(stopPoints);
      }

      lastTimeRef.current = priceHistory[priceHistory.length - 1].time;

      chartRef.current?.timeScale().fitContent();
    }
  }, [priceHistory, triggerPrice, stopPrice]);

  // --- C. Update live data ---
  useEffect(() => {
    if (seriesRef.current && realPrice) {
      const now = Math.floor(Date.now() / 1000);

      // Guard: lightweight-charts requires non-decreasing times
      if (now <= lastTimeRef.current) return;
      lastTimeRef.current = now;

      // Update price
      seriesRef.current.update({ time: now as Time, value: realPrice });

      // Update helper lines (keep the straight lines extending)
      mainLineRef.current?.update({ time: now as Time, value: triggerPrice });

      if (stopLineRef.current && stopPrice) {
        stopLineRef.current.update({ time: now as Time, value: stopPrice });
      }
    }
  }, [realPrice, triggerPrice, stopPrice]);

  // --- D. Dynamic style update ---
  useEffect(() => {
    if (seriesRef.current) {
      seriesRef.current.applyOptions({
        lineColor: lineColor,
        topColor: areaTopColor,
        bottomColor: areaBottomColor,
      });
    }
  }, [isTriggered, lineColor, areaTopColor, areaBottomColor]);

  return (
    <div className="relative w-full h-full group">
      {/* Chart Container */}
      <div
        ref={chartContainerRef}
        className={`w-full h-full transition-opacity duration-1000 ease-in-out ${priceHistory.length === 0 ? 'opacity-0' : 'opacity-80'}`}
      />

      {/* Building-chart overlay while the tick buffer warms up */}
      {priceHistory.length < 2 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <span className="text-[9px] uppercase font-mono text-xmr-dim">LIVE FEED — building chart…</span>
        </div>
      )}

      {/* Scanline effect */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-xmr-ghost/20 dark:via-xmr-ghost/10 to-transparent h-[50%] animate-scan" />
        <div className="absolute inset-0 shadow-0 dark:shadow-[inset_0_0_50px_rgba(0,0,0,0.5)]" />
      </div>
    </div>
  );
}
