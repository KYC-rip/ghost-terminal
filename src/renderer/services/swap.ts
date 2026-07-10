/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { apiClient, apiClient as client } from './client';
import {
  type BatchQuoteRequest,
  type BatchQuoteResult,
  type BatchOrderResult,
  type ExchangeStatus as TradeStatusCentral
} from "./types";

export type TradeStatus = TradeStatusCentral;
export type { BatchQuoteRequest, BatchQuoteResult, BatchOrderResult };

// --- Shared Interfaces ---
export type ComplianceLevel = 'ANY' | 'STANDARD' | 'STRICT';

export interface ComplianceState {
  kyc: ComplianceLevel;
  log: ComplianceLevel;
}

export interface TradeSupport {
  tx_url: string;
  support_url: string;
  type: string;
  tos: string;
}

export interface TradeDetails {
  provider_logo: string;
  original_eta: number;
  original_amount_to_USD?: number;
  expiresAt?: string;
}

export interface ExchangeRoute {
  provider: string;
  engine?: string;
  amount_to: number;
  amount_from: number;
  kyc: string;
  log_policy: string;
  insurance: number;
  spread: number;
  fixed: boolean;
  eta: number;
}

export interface ExchangeQuote {
  id: string;
  rate: number;
  amount_from: number;
  amount_to: number;
  min: number;
  max: number;
  provider: string;
  engine?: string;
  kyc_rating: string;
  eta: number;
  routes?: ExchangeRoute[];
}

// --- 1. Create Trade ---

export interface CreateTradeParams {
  id: string;
  amountFrom: number;
  amountTo: number;
  fromTicker: string;
  fromNetwork: string;
  toTicker: string;
  toNetwork: string;
  destinationAddress: string;
  provider: string;
  engine?: string;
  extra?: any;
  fixed?: boolean;
  isPayment?: boolean;
  memo?: string;
  source?: 'swap' | 'vigil-snipe' | 'vigil-eject' | 'dispenser' | 'ghost';
}

export interface ExchangeResponse {
  trade_id: string;
  status: string;
  amount_from: number;
  amount_to: number;
  deposit_amount: number;
  address_provider: string;
  address_user: string;
  ticker_from: string;
  ticker_to: string;
  network_from: string;
  network_to: string;
  provider: string;
  engine?: string;
  id?: string;
  deposit_address?: string;
  depositAddress?: string;
  fromTicker?: string;
  toTicker?: string;
  amountFrom?: number;
  amountTo?: number;
  depositAmount?: number;
  expiresAt?: string;
  eta?: number;
}

/** Normalize v2 response → ExchangeResponse */
function normalizeExchangeResponse(raw: any): ExchangeResponse {
  return {
    id: raw.id || raw.trade_id || '',
    trade_id: raw.trade_id || raw.id || '',
    status: (raw.status || '').toUpperCase(),
    amount_from: raw.amount_from ?? raw.fromAmount ?? raw.depositAmount ?? 0,
    amount_to: raw.amount_to ?? raw.toAmount ?? 0,
    deposit_amount: raw.deposit_amount ?? raw.depositAmount ?? raw.fromAmount ?? 0,
    address_provider: raw.address_provider ?? raw.depositAddress ?? raw.deposit_address ?? '',
    address_user: raw.address_user ?? '',
    ticker_from: raw.ticker_from ?? raw.fromTicker ?? '',
    ticker_to: raw.ticker_to ?? raw.toTicker ?? '',
    network_from: raw.network_from ?? raw.fromNetwork ?? '',
    network_to: raw.network_to ?? raw.toNetwork ?? '',
    provider: raw.provider || '',
    engine: raw.engine,
    depositAddress: raw.depositAddress ?? raw.address_provider ?? raw.deposit_address ?? '',
    deposit_address: raw.deposit_address ?? raw.depositAddress ?? raw.address_provider ?? '',
  };
}

/** Normalize v2 response → TradeStatus */
function normalizeTradeStatus(raw: any): TradeStatusCentral {
  return {
    ...raw,
    id: raw.id || raw.trade_id || '',
    trade_id: raw.trade_id || raw.id || '',
    status: (raw.status || 'WAITING').toUpperCase(),
    ticker_from: raw.ticker_from || raw.fromTicker || '',
    ticker_to: raw.ticker_to || raw.toTicker || '',
    amount_from: raw.amount_from ?? raw.fromAmount ?? raw.depositAmount ?? 0,
    amount_to: raw.amount_to ?? raw.toAmount ?? 0,
    address_provider: raw.address_provider || raw.depositAddress || raw.deposit_address || '',
    deposit_address: raw.deposit_address || raw.depositAddress || raw.address_provider || '',
    address_user: raw.address_user || '',
    tx_out: raw.tx_out || raw.txOut || undefined,
    provider: raw.provider || '',
    network_from: raw.network_from || raw.fromNetwork || '',
    network_to: raw.network_to || raw.toNetwork || '',
    confirmations: raw.confirmations || 0,
    fixed: raw.fixed ?? false,
  };
}


export interface BridgeEstimate {
  amount_to: string;
  eta: number;
  first_provider: string;
  first_kycrating: string;
  first_logpolicy: string;
  first_insurance: number;
  second_provider: string;
  second_kycrating: string;
  second_logpolicy: string;
  second_insurance: number;
  first_eta: number;
  second_eta: number;

  first_list: string[];
  second_list: string[];
}


export interface BridgeTrade {
  trade_id: string;
  status: string;
  ticker_from: string;
  ticker_to: string;

  network_from: string;
  network_to: string;

  amount_from: number;
  amount_to: number;
  provider: string;
  address_provider?: string;
  address_user?: string;
  address_provider_memo?: string;
  tx_out?: string;

  details?: {
    hashout?: string;
    support?: {
      tx_url?: string;
    };
    provider_logo?: string;
    original_eta?: number;
    second_trade_id?: string;
  };
  quotes?: {
    support?: {
      support_url?: string;
      tx_url?: string;
    }
  };
  confirmations?: number;
  refund_address?: string;
}

/**
 * 1. Create a Swap Trade
 */
export function createTrade(params: CreateTradeParams): Promise<ExchangeResponse> {
  // Mock for Testnets (seth, sxmr, tltc)
  const t = params.fromTicker.toLowerCase();
  if (t === 'seth' || t === 'sxmr' || t === 'tltc') {
    const tradeId = `testnet_real_${Math.random().toString(36).substring(7)}_${Date.now()}`;
    const mockAddrMap: Record<string, string> = {
      'sxmr': "55LTR8KniP4LQGJ9fsSKSvCoZKGvNDYbhY7AgWhNCasZ9nuL6S2ToRKmUnof69xs9snstivivsnNCofLoMBPfSaS7XBsEtC",
      'tltc': "tltc1qpfycydpyrtzkvpgxdzhszhyzpgxdzhszpgxdzhsz", // Mock Bech32
      'seth': "0x000000000000000000000000000000000000dEaD"
    };
    const mockAddr = mockAddrMap[t] || "55LTR8KniP4LQGJ9fsSKSvCoZKGvNDYbhY7AgWhNCasZ9nuL6S2ToRKmUnof69xs9snstivivsnNCofLoMBPfSaS7XBsEtC";

    return Promise.resolve({
      id: tradeId, trade_id: tradeId, status: "waiting",
      amount_from: params.amountFrom, amount_to: params.amountTo,
      deposit_amount: params.amountFrom, deposit_address: mockAddr,
      address_provider: mockAddr, address_user: params.destinationAddress,
      ticker_from: t, ticker_to: params.toTicker,
      network_from: t === 'sxmr' ? "Stagenet" : (t === 'tltc' ? "Testnet" : "Sepolia"),
      network_to: params.toNetwork, provider: "TestnetMock"
    });
  }

  return client<ExchangeResponse>('/v2/exchange/create', {
    body: {
      ...params.extra,
      trade_id: params.id, amount_from: params.amountFrom, amount_to: params.amountTo,
      from_currency: params.fromTicker, from_network: params.fromNetwork,
      to_currency: params.toTicker, to_network: params.toNetwork,
      address_to: params.destinationAddress, fixed_rate: params.fixed || false,
      address_memo: params.memo, to_currency_memo: !!params.memo,
      provider: params.provider, isPayment: params.isPayment || false,
      // Namespace the source with `rt:` (ripley-terminal) so wallet-originated
      // trades are distinguishable from the website, which uses the bare
      // 'swap'/'ghost'/'pay' values. The backend stores this verbatim; its
      // functional source-branches (ghost bridge legs, pay, telegram) strip the
      // prefix via baseSource(), so behavior is unchanged.
      source: `rt:${params.source || 'swap'}`,
      engine: params.engine,
    }
  }).then(normalizeExchangeResponse);
}

/**
 * 2. Get Swap Trade Status
 */
export function getTradeStatus(id: string) {
  // Mock for Testnets
  if (id.startsWith('testnet_real_')) {
    const parts = id.split('_');
    const timestamp = parseInt(parts[parts.length - 1]);
    const now = Date.now();
    const elapsed = (now - timestamp) / 1000;

    let status = 'waiting';

    // Simulate real time passage
    if (elapsed > 60) status = 'finished';      // Finish after 1 minute
    else if (elapsed > 30) status = 'sending';  // Send after 30 seconds
    else if (elapsed > 10) status = 'exchanging'; // Exchange after 10 seconds
    else if (elapsed > 0) status = 'confirming';  // Presence of ID implies confirming (Vigil mode implies transaction already broadcast)

    return Promise.resolve({
      trade_id: id,
      status: status,
      amount_from: 0.1, // Mock values for testnet
      amount_to: 0.05,
      ticker_from: 'SETH',
      ticker_to: 'SXMR',
      provider: 'Mock_Stagenet_Liquidity',
      tx_out: status === 'finished' ? '540c45...' : undefined,
      deposit_address: '...',
      // ...
    } as any);
  } else if (id.startsWith('test_')) {
    const parts = id.split('_');
    const timestamp = parseInt(parts[parts.length - 1]);
    const now = Date.now();
    const elapsed = now - timestamp;

    let status = 'waiting';
    if (elapsed > 60000) status = 'finished';
    else if (elapsed > 20000) status = 'exchanging';

    return Promise.resolve({
      trade_id: id,
      status: status,
      ticker_from: 'sxmr',
      ticker_to: 'seth',
      amount_from: 0.001,
      amount_to: 3,
      address_provider: 'mock_provider_address',
      address_user: 'mock_user_address',
      provider: 'TestnetMock',
      created_at: new Date(timestamp).toISOString()
    } as any);
  }

  return client<TradeStatus>(`/v2/exchange/status/${id}`).then(normalizeTradeStatus) as Promise<TradeStatus>;
}

/**
 * 3. Get Real-time Quote
 */
export async function fetchQuote(
  fromTicker: string,
  fromNetwork: string,
  toTicker: string,
  toNetwork: string,
  amountValue: number,
  isReverse: boolean = false,
  kyc: ComplianceLevel = 'ANY',
  log: ComplianceLevel = 'ANY',
): Promise<ExchangeQuote> {
  // Mock for Testnets (seth, sxmr, tltc)
  const t = fromTicker.toLowerCase();
  if (t === 'seth' || t === 'sxmr' || t === 'tltc') {
    const rateMap: Record<string, number> = { 'seth': 3000, 'sxmr': 20000, 'tltc': 70 };
    const rate = rateMap[t] || 100;
    const estimatedAmt = isReverse ? amountValue / rate : amountValue * rate;
    return Promise.resolve({
      id: `mock_quote_${t}_` + Date.now(), rate: rate,
      amount_from: isReverse ? estimatedAmt : amountValue,
      amount_to: isReverse ? amountValue : estimatedAmt,
      min: 0.001, max: 100, provider: "TestnetMock", kyc_rating: "A", eta: 2,
      routes: [{
        provider: "TestnetMock", amount_to: isReverse ? amountValue : estimatedAmt,
        amount_from: isReverse ? estimatedAmt : amountValue,
        kyc: "A", log_policy: "no_logs", insurance: 0, spread: 0.5, fixed: false, eta: 2
      }]
    });
  }

  const params = new URLSearchParams({
    from: fromTicker, from_net: fromNetwork, to: toTicker, to_net: toNetwork,
    amount: amountValue.toString(), type: isReverse ? 'to' : 'from',
    kyc: kycMap[kyc], log: logMap[log],
  });

  return client<ExchangeQuote>(`/v2/exchange/estimate?${params.toString()}`);
}

/**
 * A. Batch Quote Only
 */
export async function quoteBatchTrades(
  requests: BatchQuoteRequest[],
  strategy: 'best' | 'diversity' = 'best',
  kyc: ComplianceLevel = 'ANY',
  log: ComplianceLevel = 'ANY',
): Promise<BatchQuoteResult[]> {
  const rawResults = await Promise.all(requests.map(async (req) => {
    try {
      const quote = await fetchQuote(
        req.fromTicker,
        req.fromNetwork,
        req.toTicker,
        req.toNetwork,
        req.amountTo,
        true,
        kyc,
        log
      );

      const validRoutes = quote.routes || [];

      if (validRoutes.length === 0) throw new Error('No compatible providers found, try lower the barrier');
      return { req, quoteId: quote.id, validRoutes, success: true };
    } catch (err: any) {
      return { req, quoteId: '--', validRoutes: [], success: false, error: err.message || 'Quote failed' };
    }
  }));

  const providerUsage: Record<string, number> = {};
  const finalResults: BatchQuoteResult[] = [];

  for (const res of rawResults) {
    if (!res.success || res.validRoutes.length === 0) {
      finalResults.push({
        trade_id: "--", request_id: res.req.id, provider: '', amount_from_estimated: 0,
        amount_to: 0, success: false, error: res.error, original_request: res.req
      });
      continue;
    }

    let selectedRoute: any;
    const bestPrice = res.validRoutes[0].amount_from;

    if (strategy === 'best') {
      selectedRoute = res.validRoutes[0];
    } else {
      const TOLERANCE = 1.05;
      const candidates = res.validRoutes.filter((r: any) => r.amount_from <= bestPrice * TOLERANCE);
      candidates.sort((a: any, b: any) => {
        const usageA = providerUsage[a.provider] || 0;
        const usageB = providerUsage[b.provider] || 0;
        if (usageA !== usageB) return usageA - usageB;
        return a.amount_from - b.amount_from;
      });
      selectedRoute = candidates[0];
    }

    providerUsage[selectedRoute.provider] = (providerUsage[selectedRoute.provider] || 0) + 1;
    finalResults.push({
      request_id: res.req.id, trade_id: res.quoteId, provider: selectedRoute.provider,
      engine: selectedRoute.engine,
      amount_from_estimated: selectedRoute.amount_from, amount_to: res.req.amountTo,
      success: true, original_request: res.req
    });
  }
  return finalResults;
}

/**
 * B. Batch Order Execution
 */
export async function executeBatchTrades(quotes: BatchQuoteResult[], destinationMap: Record<string, string>): Promise<BatchOrderResult[]> {
  const createPromises = quotes.map(async (q) => {
    if (!q.success) {
      return { request_id: q.request_id, trade_id: '', address_provider: '', amount_from: 0, provider: '', status: 'failed' as const, error: q.error };
    }
    try {
      const destAddr = destinationMap[q.request_id];
      const trade = await createTrade({
        id: q.trade_id, amountFrom: q.amount_from_estimated, amountTo: q.amount_to,
        fromTicker: q.original_request.fromTicker, fromNetwork: q.original_request.fromNetwork,
        toTicker: q.original_request.toTicker, toNetwork: q.original_request.toNetwork,
        destinationAddress: destAddr, provider: q.provider, engine: q.engine, source: "dispenser"
      });
      return {
        request_id: q.request_id, trade_id: trade.trade_id || trade.id || '',
        address_provider: trade.address_provider || trade.deposit_address || '',
        amount_from: Number(trade.amount_from || trade.deposit_amount || 0),
        provider: q.provider, status: 'success' as const, expected_to: q.amount_to
      };
    } catch (err) {
      return { request_id: q.request_id, trade_id: '', address_provider: '', amount_from: 0, provider: q.provider, status: 'failed' as const, error: 'Creation failed' };
    }
  });
  return Promise.all(createPromises);
}


// --- API Service ---
const kycMap: Record<ComplianceLevel, string> = {
  'STRICT': 'A',   // No KYC
  'STANDARD': 'B', // Standard (Exclude C/D)
  'ANY': 'D'       // Allow All
};

const logMap: Record<ComplianceLevel, string> = {
  'STRICT': 'A',   // No Logs
  'STANDARD': 'B', // Short Term Logs (Exclude C/D)
  'ANY': 'C'       // Allow All
};

export const fetchBridgeEstimate = async (from: string, to: string, amount: number, network_from: string = "Mainnet", network_to: string = "Mainnet", kyc: ComplianceLevel, log: ComplianceLevel) => {
  const params = new URLSearchParams({ from, to, network_from, network_to, amount: amount.toString(), type: 'from', kyc: kycMap[kyc], log: logMap[log] });

  console.log(`requesting API: /v1/exchange/bridge/estimate?${params.toString()}`);

  const data = await apiClient<BridgeEstimate>(`/v2/exchange/bridge/estimate?${params.toString()}`, {}, async (res) => {
    if (!res.ok) {
      let errMsg = "Estimate Failed";
      try {
        const errData = await res.json();
        if (errData.error) errMsg = errData.error;
      } catch (e) {
        console.warn('[Swap] Error body parse failed:', e);
        errMsg = await res.text() || res.statusText;
      }
      throw new Error(errMsg.split('error":')?.[1]?.replaceAll(/["\\}]/g, '') || errMsg);
    }
    return await res.json() as BridgeEstimate;
  });

  return data;
};

export const createBridgeTrade = async (payload: {
  from_currency: string;
  from_network: string;
  to_currency: string;
  to_network: string;
  amount_from: number;
  address_to: string;
  refund_address: string;
}) => {
  try {
    const data = await apiClient<BridgeTrade[]>(`/v2/exchange/bridge/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    return data;
  } catch (e) {
    console.error("Failed to create bridge:", e);
    throw e;
  }
};

export const fetchBridgeStatus = async (id: string) => {
  try {
    const trade1 = await apiClient<BridgeTrade>(`/v2/exchange/status/${id}`);
    if (trade1.details && trade1.details.second_trade_id) {
      try {
        const trade2 = await apiClient<BridgeTrade>(`/v2/exchange/status/${trade1.details.second_trade_id}`)
        return [trade1, trade2] as BridgeTrade[];
      } catch (e) {
        console.warn("Failed to fetch second leg of bridge:", e);
      }
    }
    return [trade1] as BridgeTrade[];
  } catch (e) {
    console.error("Failed to fetch bridge status:", e);
    throw e;
  }
};

// ─── V2 BRIDGE API ───

export interface BridgeRoute {
  engine: string;
  provider: string;
  amount_to: number;
  amount_from?: number;
  eta: number;
  kyc: string;
  log_policy?: string;
  type?: string;
  bridgeLabel?: string;
  bridgeBadge?: string;
  bridgeHighlight?: string;
  ingressProvider?: string;
  egressProvider?: string;
  ingressKyc?: string;
  egressKyc?: string;
  requiresRefund?: boolean;
  hops?: Array<{ name: string; logo?: string }>;
  providerLogo?: string;
}

export interface BridgeEstimateV2 {
  amount_to: number;
  eta: number;
  routes: BridgeRoute[];
}

export interface BridgeTradeV2 {
  id: string;
  status: string;
  engine: string;
  provider?: string;
  fromTicker: string;
  fromNetwork?: string;
  toTicker: string;
  toNetwork?: string;
  fromAmount?: number;
  toAmount?: number;
  depositAddress?: string;
  depositAmount?: number;
  depositMemo?: string;
  address_user?: string;
  txIn?: string;
  txOut?: string;
  confirmations?: number;
  createdAt?: string;
  eta?: number;
  secondTradeId?: string;
  timing?: {
    detectedAt?: string;
    confirmedAt?: string;
    sendingAt?: string;
    finishedAt?: string;
  };
  details?: {
    hashout?: string;
    provider_logo?: string;
    original_eta?: number;
    second_trade_id?: string;
    support?: { tx_url?: string; support_url?: string };
  };
  hops?: Array<{ name: string; logo?: string }>;
}

export async function fetchBridgeEstimateV2(
  from: string,
  to: string,
  amount: number,
  network_from = 'Mainnet',
  network_to = 'Mainnet',
  kyc: ComplianceLevel = 'ANY',
  log: ComplianceLevel = 'ANY',
  noCache = false,
): Promise<BridgeEstimateV2> {
  const params = new URLSearchParams({
    from, to, network_from, network_to,
    amount: amount.toString(),
    kyc: kycMap[kyc], log: logMap[log],
  });
  if (noCache) params.set('no_cache', '1');

  return apiClient<BridgeEstimateV2>(`/v2/exchange/bridge/estimate?${params.toString()}`);
}

export async function createBridgeTradeV2(payload: {
  engine?: string;
  from_currency: string;
  from_network?: string;
  to_currency: string;
  to_network?: string;
  amount_from: number;
  address_to: string;
  refund_address?: string;
  address_memo?: string;
  refund_memo?: string;
}): Promise<BridgeTradeV2[]> {
  return apiClient<BridgeTradeV2[]>('/v2/exchange/bridge/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function fetchBridgeStatusV2(id: string, engine?: string): Promise<BridgeTradeV2[]> {
  const params = engine ? `?engine=${engine}` : '';
  const trade1 = await apiClient<BridgeTradeV2>(`/v2/exchange/status/${id}${params}`);
  const secondId = trade1.secondTradeId || trade1.details?.second_trade_id;
  if (secondId) {
    try {
      const trade2 = await apiClient<BridgeTradeV2>(`/v2/exchange/status/${secondId}${params}`);
      return [trade1, trade2];
    } catch (e) {
      console.warn('[Swap] Second leg status fetch failed:', e);
      return [trade1];
    }
  }
  return [trade1];
}