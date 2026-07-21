/* eslint-disable @typescript-eslint/no-explicit-any */

export interface Currency {
  id: string;
  ticker: string;
  name: string;
  network: string;
  image: string;
  minimum: number;
  maximum: number;
  balance?: string;
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
  original_amount_from_USD?: number;
  original_USD_total_cost_percentage?: number;
  expiresAt?: string;
  support?: TradeSupport;
  hashin?: string;
  hashout?: string;
  deposit_time_detected?: string;
  marketrate_deposit_time?: string;
  marketrate_sending_time?: string;
  marketrate_finished_time?: string;
  deposit_time_1stconfirmation?: string;
  marketrate_variation?: number;
  estimation_creation_diff?: number;
}

export interface ExchangeStatus {
  id: string;
  trade_id: string;
  status: string;
  
  // Amounts
  amount_from: number;
  amount_to: number;
  deposit_amount?: number;
  amount_deposit?: number | string;

  // Addresses
  address_provider: string;
  deposit_address?: string;
  address_deposit?: string;
  address_user: string;
  address_provider_memo?: string;
  
  // Coin Info
  ticker_from: string;
  ticker_to: string;
  network_from: string;
  network_to: string;
  coin_from?: string;
  coin_to?: string;
  
  // Metadata
  provider: string;
  fixed: boolean;
  confirmations: number;
  date?: string;
  type?: string;
  
  // Transaction
  tx_in?: string;
  tx_out?: string;
  
  // Rich Data
  details?: TradeDetails;
  quotes?: {
    quotes?: any[];
    max_withdrawal?: number;
    min_withdrawal?: number;
    expiresAt?: string;
    support?: TradeSupport;
    kyc_list?: string[];
    logpolicy_list?: string[];
    markup?: boolean;
    best_only?: boolean;
  };
  payment?: boolean;
  message?: string;
  trade_id_provider?: string;
}

export type TradeStatus = ExchangeStatus;

export interface BatchQuoteRequest {
  id: string;
  fromTicker: string;
  fromNetwork: string;
  toTicker: string;
  toNetwork: string;
  amountTo: number;
}

export interface BatchQuoteResult {
  trade_id: string;
  request_id: string;
  provider: string;
  engine?: string;
  amount_from_estimated: number;
  amount_to: number;
  success: boolean;
  error?: string;
  original_request: BatchQuoteRequest;
}

export interface BatchOrderResult {
  request_id: string;
  trade_id: string;
  address_provider: string; 
  amount_from: number;      
  provider: string;
  status: 'success' | 'failed' | 'finished' | 'expired';
  error?: string;
  expected_to?: number;
}