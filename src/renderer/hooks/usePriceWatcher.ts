import { useState, useRef, useCallback, useEffect } from 'react';

/**
 * Kraken trade-feed price watcher with trigger evaluation.
 *
 * Owns the WebSocket lifecycle: reconnects with exponential backoff
 * (5s -> 60s); after MAX_CONSECUTIVE_FAILURES it stops retrying and surfaces
 * `degraded: true` so the UI can show a stale-feed banner with a manual
 * reconnect — armed triggers are kept, never silently dropped.
 *
 * The WS rides the app-wide session proxy (Tor when enabled), like all
 * renderer network traffic.
 */

export interface PriceTrigger {
  id: string;
  operator: '>=' | '<=';
  price: number;
}

export function evaluateTriggers(triggers: PriceTrigger[], price: number): PriceTrigger | null {
  for (const trigger of triggers) {
    if (trigger.operator === '>=' && price >= trigger.price) return trigger;
    if (trigger.operator === '<=' && price <= trigger.price) return trigger;
  }
  return null;
}

export interface TickPoint { time: number; value: number }

/**
 * Rolling tick buffer for the heartbeat chart: keeps the LATEST tick per
 * 2-second window (latest-wins preserves the trigger-relevant extreme at
 * window close; no averaging), capped at 1800 points (~1 hour).
 * Pure so it can be unit-tested; mutates and returns the same array unless
 * the cap forces a shift.
 */
export const TICK_WINDOW_S = 2;
export const TICK_CAP = 1800;
export function pushTick(buffer: TickPoint[], time: number, value: number): TickPoint[] {
  const windowTime = Math.floor(time / TICK_WINDOW_S) * TICK_WINDOW_S;
  const last = buffer[buffer.length - 1];
  if (last && last.time === windowTime) {
    last.value = value; // same window: latest wins
    return buffer;
  }
  if (last && windowTime < last.time) return buffer; // ignore out-of-order
  buffer.push({ time: windowTime, value });
  if (buffer.length > TICK_CAP) buffer.shift();
  return buffer;
}

const KRAKEN_WS = 'wss://ws.kraken.com';
const BACKOFF_BASE_MS = 5_000;
const BACKOFF_MAX_MS = 60_000;
const MAX_CONSECUTIVE_FAILURES = 5;

export function usePriceWatcher(onTrigger: (price: number, trigger: PriceTrigger) => void) {
  const [price, setPrice] = useState<number | null>(null);
  const [connected, setConnected] = useState(false);
  const [degraded, setDegraded] = useState(false);
  const [lastTickAt, setLastTickAt] = useState<number | null>(null);
  const [priceHistory, setPriceHistory] = useState<TickPoint[]>([]);
  const historyRef = useRef<TickPoint[]>([]);

  const wsRef = useRef<WebSocket | null>(null);
  const priceRef = useRef<number | null>(null);
  const connectedRef = useRef(false);
  const retryTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const triggersRef = useRef<PriceTrigger[]>([]);
  const pairRef = useRef<string>('');
  const failuresRef = useRef(0);
  const connectingRef = useRef(false);
  const onTriggerRef = useRef(onTrigger);
  useEffect(() => { onTriggerRef.current = onTrigger; }, [onTrigger]);

  const closeSocket = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.onmessage = null;
      try { wsRef.current.close(); } catch { /* noop */ }
      wsRef.current = null;
    }
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }
  }, []);

  const connect = useCallback((krakenPair: string) => {
    if (connectingRef.current) return;
    closeSocket();
    connectingRef.current = true;
    pairRef.current = krakenPair;

    try {
      const ws = new WebSocket(KRAKEN_WS);

      // Proxies that blackhole the connection (no RST) leave the socket in
      // CONNECTING until the OS TCP timeout (~75s), which delays the whole
      // backoff->degraded escalation by minutes. Force-close stuck handshakes
      // so onclose fires and the normal retry path takes over quickly.
      const connectTimeout = setTimeout(() => {
        if (ws.readyState === WebSocket.CONNECTING) {
          console.warn('[PriceWatcher] WS handshake timed out after 15s (proxy blackhole?). Forcing retry.');
          connectingRef.current = false;
          try { ws.close(); } catch { /* noop */ }
        }
      }, 15_000);

      ws.onopen = () => {
        clearTimeout(connectTimeout);
        connectingRef.current = false;
        failuresRef.current = 0;
        connectedRef.current = true;
        setConnected(true);
        setDegraded(false);
        // Trade channel fires only on executed trades — on a thin pair that
        // can be minutes apart. Ticker fires on every book update, keeping
        // the price and the chart buffer lively; both carry the last price.
        ws.send(JSON.stringify({
          event: 'subscribe',
          pair: [krakenPair],
          subscription: { name: 'trade' },
        }));
        ws.send(JSON.stringify({
          event: 'subscribe',
          pair: [krakenPair],
          subscription: { name: 'ticker' },
        }));
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.event === 'heartbeat' || data.event === 'systemStatus') return;

          if (data.event === 'subscriptionStatus') {
            if (data.status === 'error') {
              console.error(`[PriceWatcher] Kraken subscription error: ${data.errorMessage}`);
              // Unknown pair: retrying won't help, stop and surface degraded
              if (data.errorMessage?.includes('pair') || data.errorMessage?.includes('Currency')) {
                closeSocket();
                setConnected(false);
                setDegraded(true);
              }
            }
            return;
          }

          // Trade data: [channelId, [[price, vol, time, side]], "trade", pair]
          // Ticker data: [channelId, {c: [lastPrice, lastVol], ...}, "ticker", pair]
          if (Array.isArray(data) && (data[2] === 'trade' || data[2] === 'ticker')) {
            let currentPrice = NaN;
            if (data[2] === 'trade') {
              const trades = data[1];
              currentPrice = parseFloat(trades[trades.length - 1][0]);
            } else {
              currentPrice = parseFloat(data[1]?.c?.[0]);
            }
            if (!(currentPrice > 0)) return;
            priceRef.current = currentPrice;
            setPrice(currentPrice);
            setLastTickAt(Date.now());

            const before = historyRef.current.length;
            pushTick(historyRef.current, Math.floor(Date.now() / 1000), currentPrice);
            if (historyRef.current.length !== before) {
              setPriceHistory([...historyRef.current]); // new window committed
            }

            const hit = evaluateTriggers(triggersRef.current, currentPrice);
            if (hit) onTriggerRef.current(currentPrice, hit);
          }
        } catch { /* ignore malformed packets */ }
      };

      ws.onclose = (event) => {
        clearTimeout(connectTimeout);
        connectingRef.current = false;
        connectedRef.current = false;
        setConnected(false);

        if (triggersRef.current.length === 0) return; // nothing armed, stay quiet

        failuresRef.current += 1;
        if (failuresRef.current >= MAX_CONSECUTIVE_FAILURES) {
          console.warn(`[PriceWatcher] WS failed ${failuresRef.current}x — entering degraded mode (manual reconnect required).`);
          setDegraded(true);
          return;
        }

        const delay = Math.min(BACKOFF_BASE_MS * 2 ** (failuresRef.current - 1), BACKOFF_MAX_MS);
        console.warn(`[PriceWatcher] WS closed (code ${event.code}). Reconnecting in ${delay / 1000}s...`);
        retryTimeoutRef.current = setTimeout(() => {
          if (triggersRef.current.length > 0) connect(krakenPair);
        }, delay);
      };

      ws.onerror = () => { /* onclose fires next and handles retry */ };

      wsRef.current = ws;
    } catch (e) {
      connectingRef.current = false;
      console.error('[PriceWatcher] WS init failed:', e);
    }
  }, [closeSocket]);

  /** Arm triggers and start (or retarget) the feed. */
  const watch = useCallback((krakenPair: string, triggers: PriceTrigger[]) => {
    triggersRef.current = triggers;
    failuresRef.current = 0;
    setDegraded(false);
    connect(krakenPair);

    // Seed the chart with 1-min OHLC closes (fetched in the main process —
    // Kraken REST blocks renderer CORS) so the chart is complete instantly
    // instead of accumulating from zero. Live ticks append after the last
    // candle; older candles are merged in front of anything already buffered.
    window.api.fetchPriceHistory(krakenPair).then((res) => {
      if (!res.success || !res.points?.length) {
        if (res.error) console.warn('[PriceWatcher] History seed unavailable:', res.error);
        return;
      }
      const existing = historyRef.current;
      const cutoff = existing.length > 0 ? existing[0].time : Infinity;
      const older = res.points.filter(p => p.time < cutoff).sort((a, b) => a.time - b.time);
      if (older.length === 0) return;
      historyRef.current = [...older, ...existing].slice(-TICK_CAP);
      setPriceHistory([...historyRef.current]);
      if (!priceRef.current) {
        const latest = historyRef.current[historyRef.current.length - 1];
        priceRef.current = latest.value;
        setPrice(latest.value);
      }
    }).catch((e) => console.warn('[PriceWatcher] History seed failed:', e));
  }, [connect]);

  /** Manual reconnect from the degraded-state banner. */
  const reconnect = useCallback(() => {
    failuresRef.current = 0;
    setDegraded(false);
    if (pairRef.current) connect(pairRef.current);
  }, [connect]);

  /** Disarm and close the feed. */
  const stop = useCallback(() => {
    triggersRef.current = [];
    closeSocket();
    setConnected(false);
    setDegraded(false);
  }, [closeSocket]);

  // Quiet markets starve the buffer, making the chart jump between scales
  // whenever a lone tick finally lands. While the feed is up, repeat the
  // last known price into each empty 2s window — the line stays continuous
  // and the scale stays put even with no incoming trades.
  useEffect(() => {
    const heartbeat = setInterval(() => {
      if (!connectedRef.current || !priceRef.current) return;
      const before = historyRef.current.length;
      pushTick(historyRef.current, Math.floor(Date.now() / 1000), priceRef.current);
      if (historyRef.current.length !== before) {
        setPriceHistory([...historyRef.current]);
      }
    }, TICK_WINDOW_S * 1000);
    return () => clearInterval(heartbeat);
  }, []);

  useEffect(() => () => { triggersRef.current = []; closeSocket(); }, [closeSocket]);

  return { price, connected, degraded, lastTickAt, priceHistory, watch, reconnect, stop, hasTriggers: () => triggersRef.current.length > 0, clearTriggers: () => { triggersRef.current = []; } };
}

/**
 * Derives the Kraken monitoring pair from swap currencies.
 * e.g. SNIPE USDT->XMR => "XMR/USD", EJECT XMR->USDT => "XMR/USD"
 */
export function getKrakenMonitoringPair(mode: 'SNIPE' | 'EJECT', from: string, to: string): string {
  const clean = (t: string) =>
    t.toUpperCase()
      .replace(/S(XMR|ETH)/i, '$1')
      .replace('USDT', 'USD')
      .replace('USDC', 'USD')
      .replace('DAI', 'USD');

  const cFrom = clean(from);
  const cTo = clean(to);

  let subject = mode === 'SNIPE' ? cTo : cFrom;
  if (['USD', 'EUR'].includes(subject)) {
    subject = mode === 'SNIPE' ? cFrom : cTo;
  }
  return `${subject}/USD`;
}
