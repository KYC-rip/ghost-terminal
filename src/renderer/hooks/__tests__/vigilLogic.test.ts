import { describe, it, expect } from 'vitest';
import { evaluateTriggers, getKrakenMonitoringPair, type PriceTrigger } from '../usePriceWatcher';
import { buildTriggers, loadPersistedSession, VIGIL_SESSION_VERSION, type PersistedVigilSession } from '../useVigilEngine';
import { isNativeEVM, getTokenConfig } from '@kyc-rip/stealth-engines/chains';

describe('chains registry (strike wallet dependencies)', () => {
  it('classifies native coins the strike wallet relies on', () => {
    expect(isNativeEVM('eth')).toBe(true);
    expect(isNativeEVM('ETH')).toBe(true);
    expect(isNativeEVM('bnb')).toBe(true);
    expect(isNativeEVM('usdt')).toBe(false);
    expect(isNativeEVM('usdc')).toBe(false);
  });

  it('resolves ERC-20 contracts for the default SNIPE tokens', () => {
    expect(getTokenConfig('usdt', 'ERC20')?.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(getTokenConfig('usdc', 'ERC20')?.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
  });
});

describe('evaluateTriggers', () => {
  const triggers: PriceTrigger[] = [
    { id: 'BUY_DIP', operator: '<=', price: 150 },
    { id: 'BUY_BREAKOUT', operator: '>=', price: 200 },
  ];

  it('fires <= when price is at or below the threshold', () => {
    expect(evaluateTriggers(triggers, 150)?.id).toBe('BUY_DIP');
    expect(evaluateTriggers(triggers, 149.99)?.id).toBe('BUY_DIP');
  });

  it('fires >= when price is at or above the threshold', () => {
    expect(evaluateTriggers(triggers, 200)?.id).toBe('BUY_BREAKOUT');
    expect(evaluateTriggers(triggers, 250)?.id).toBe('BUY_BREAKOUT');
  });

  it('returns null between thresholds', () => {
    expect(evaluateTriggers(triggers, 175)).toBeNull();
  });

  it('returns null with no triggers', () => {
    expect(evaluateTriggers([], 175)).toBeNull();
  });
});

describe('buildTriggers', () => {
  it('SNIPE: main is buy-the-dip (<=), stop is breakout (>=)', () => {
    expect(buildTriggers('SNIPE', '150', '200')).toEqual([
      { id: 'BUY_DIP', operator: '<=', price: 150 },
      { id: 'BUY_BREAKOUT', operator: '>=', price: 200 },
    ]);
  });

  it('EJECT: main is take-profit (>=), stop is stop-loss (<=)', () => {
    expect(buildTriggers('EJECT', '300', '120')).toEqual([
      { id: 'TAKE_PROFIT', operator: '>=', price: 300 },
      { id: 'STOP_LOSS', operator: '<=', price: 120 },
    ]);
  });

  it('omits unset or non-positive prices', () => {
    expect(buildTriggers('SNIPE', '150')).toHaveLength(1);
    expect(buildTriggers('SNIPE', '0', '0')).toHaveLength(0);
    expect(buildTriggers('EJECT', '', '')).toHaveLength(0);
  });
});

describe('getKrakenMonitoringPair', () => {
  it('maps stable->XMR snipes and XMR->stable ejects to XMR/USD', () => {
    expect(getKrakenMonitoringPair('SNIPE', 'USDT', 'XMR')).toBe('XMR/USD');
    expect(getKrakenMonitoringPair('SNIPE', 'USDC', 'XMR')).toBe('XMR/USD');
    expect(getKrakenMonitoringPair('EJECT', 'XMR', 'USDT')).toBe('XMR/USD');
    expect(getKrakenMonitoringPair('EJECT', 'XMR', 'DAI')).toBe('XMR/USD');
  });

  it('normalizes stagenet tickers', () => {
    expect(getKrakenMonitoringPair('EJECT', 'SXMR', 'USDT')).toBe('XMR/USD');
  });

  it('falls back to the non-USD leg when the subject is a fiat proxy', () => {
    expect(getKrakenMonitoringPair('SNIPE', 'ETH', 'USDT')).toBe('ETH/USD');
  });
});

describe('loadPersistedSession', () => {
  const valid: PersistedVigilSession = {
    version: VIGIL_SESSION_VERSION,
    identityId: 'vault_123',
    mode: 'SNIPE',
    phase: 'ARMED',
    triggers: [{ id: 'BUY_DIP', operator: '<=', price: 150 }],
    config: {
      triggerPrice: '150', amount: '100', targetAddress: '4abc',
      compliance: { kyc: 'ANY', log: 'ANY' } as never,
    },
    createdAt: 1,
  };

  it('accepts a valid v1 session for the matching identity', () => {
    expect(loadPersistedSession(valid, 'vault_123')).toEqual(valid);
  });

  it('rejects sessions from a different identity', () => {
    expect(loadPersistedSession(valid, 'vault_other')).toBeNull();
  });

  it('rejects newer schema versions instead of corrupting', () => {
    expect(loadPersistedSession({ ...valid, version: 2 }, 'vault_123')).toBeNull();
  });

  it('rejects malformed blobs', () => {
    expect(loadPersistedSession(null, 'vault_123')).toBeNull();
    expect(loadPersistedSession({ ...valid, mode: 'YOLO' }, 'vault_123')).toBeNull();
    expect(loadPersistedSession({ ...valid, phase: 'DONE' }, 'vault_123')).toBeNull();
    expect(loadPersistedSession({ ...valid, triggers: 'nope' }, 'vault_123')).toBeNull();
  });
});

import { pushTick, TICK_CAP, type TickPoint } from '../usePriceWatcher';

describe('pushTick (heartbeat chart buffer)', () => {
  it('collapses ticks in the same 2s window, latest wins', () => {
    const buf: TickPoint[] = [];
    pushTick(buf, 100, 10);
    pushTick(buf, 101, 11); // same window (100-101)
    expect(buf).toEqual([{ time: 100, value: 11 }]);
    pushTick(buf, 102, 12); // next window
    expect(buf).toEqual([{ time: 100, value: 11 }, { time: 102, value: 12 }]);
  });

  it('ignores out-of-order ticks', () => {
    const buf: TickPoint[] = [{ time: 200, value: 5 }];
    pushTick(buf, 150, 9);
    expect(buf).toEqual([{ time: 200, value: 5 }]);
  });

  it('caps the buffer at TICK_CAP points, dropping the oldest', () => {
    const buf: TickPoint[] = [];
    for (let i = 0; i <= TICK_CAP; i++) pushTick(buf, i * 2, i);
    expect(buf.length).toBe(TICK_CAP);
    expect(buf[0].time).toBe(2); // oldest (0) shifted out
    expect(buf[buf.length - 1].value).toBe(TICK_CAP);
  });
});
