import { MoneroAccount } from '../contexts/VaultContext';
import { RpcClient } from './rpcClient';

export interface Transaction {
  id: string;
  amount: string;
  type: 'in' | 'out' | 'pending';
  timestamp: number;
  address: string;
  confirmations: number;
  subaddr_index?: { major: number; minor: number };
  accountIndex?: number;
  fee?: string;
  height?: number;
  paymentId?: string;
  note?: string;
  unlockTime?: number;
  doubleSpendSeen?: boolean;
  destinations?: Array<{ address: string; amount: string }>;
}

export const WalletService = {
  /**
   * Fetch all sub-accounts under current wallet (multi-account in GUI)
   */
  async getAccounts(): Promise<MoneroAccount[]> {
    // RPC Method: get_accounts
    const res = await RpcClient.call('get_accounts', {
      all_accounts: true,
      tag: "" // Empty string to fetch all
    });

    return (res.subaddress_accounts || []).map((acc: any) => ({
      index: acc.account_index,
      label: acc.label || `Account #${acc.account_index}`,
      balance: RpcClient.formatXmr(acc.balance),
      unlockedBalance: RpcClient.formatXmr(acc.unlocked_balance),
      baseAddress: acc.base_address
    }));
  },

  async createAccount(label: string = 'NEW_ACCOUNT') {
    const res = await RpcClient.call('create_account', {
      label: label
    });
    return {
      index: res.account_index,
      address: res.address
    };
  },

  async renameAccount(accountIndex: number, newLabel: string) {
    await RpcClient.call('label_account', {
      account_index: accountIndex,
      label: newLabel
    });
  },

  // --- Base State ---
  async getBalance(accountIndex: number) {
    // 🚀 Retrieve detailed list of all accounts
    const balance = await RpcClient.call('get_balance', { account_index: accountIndex });
    return {
      total: RpcClient.formatXmr(balance.total_balance.toString()),
      unlocked: RpcClient.formatXmr(balance.unlocked_balance.toString())
    };
  },

  async getHeight(accountIndex: number) {
    const res = await RpcClient.call('get_height', { account_index: accountIndex });
    return res.height;
  },

  async getAddress(accountIndex: number) {
    const res = await RpcClient.call('get_address', { account_index: accountIndex });
    return {
      primary: res.address,
      all: res.addresses || []
    };
  },

  // --- Transaction Operations ---
  async send(destination: string, amountXmr: number, accountIndex: number, priority: number = 0) {
    const rawAmount = RpcClient.toAtomic(amountXmr);

    await RpcClient.call('transfer', {
      destinations: [{ destination, amount: rawAmount }],
      account_index: accountIndex,
      priority
    });
  },

  /**
   * Multi-destination transfer with optional coin control
   */
  async sendMulti(
    destinations: { address: string; amount: number }[],
    accountIndex: number,
    subaddrIndices?: number[],
    priority?: number
  ) {
    const rpcDest = destinations.map(d => ({
      destination: d.address,
      amount: RpcClient.toAtomic(d.amount)
    }));

    const params: any = {
      destinations: rpcDest,
      account_index: accountIndex,
      priority: priority ?? 0
    };

    if (subaddrIndices && subaddrIndices.length > 0) {
      params.subaddr_indices = subaddrIndices;
    }

    return await RpcClient.call('transfer', params);
  },

  /**
   * Churn: Sweeps all available balance back to a fresh subaddress to refresh privacy and break heuristic links
   */
  async churn(accountIndex: number) {
    const newAddr = await this.createSubaddress('Churn_Target', accountIndex);
    const res = await RpcClient.call('sweep_all', {
      address: newAddr,
      account_index: accountIndex,
      ring_size: 16
    });
    return res.tx_hash_list?.[0] || res.tx_hash;
  },

  /**
   * Splinter: Shatters the unlocked balance into N smaller UTXOs distributed across new subaddresses.
   */
  async splinter(accountIndex: number, fragments: number) {
    if (fragments < 2 || fragments > 10) {
      throw new Error("Splinter fragments must be between 2 and 10.");
    }
    const balRes = await RpcClient.call('getbalance', { account_index: accountIndex });
    const availablePico = balRes.unlocked_balance || 0;

    // Fee-aware buffer: splinter spends ~all UTXOs and the tx fee grows with the
    // input count, so a FIXED buffer underestimated multi-input wallets (8 inputs →
    // fee ~0.00067 XMR, over the old 0.0005 → NotEnoughFunds). Scale by the unspent-
    // output count; any unused remainder simply returns as change.
    const utxoRes = await RpcClient.call('incoming_transfers', { account_index: accountIndex });
    const numInputs = Math.max(1, (utxoRes.transfers || []).length);
    const feeBuffer = 500000000 + numInputs * 150000000; // 0.0005 base + ~0.00015/input
    const splinterableAmount = availablePico - feeBuffer;

    if (splinterableAmount <= 0) {
      throw new Error("Balance too small after reserving fee buffer.");
    }

    const amountPerFragment = Math.floor(splinterableAmount / fragments);

    const destinations = [];
    for (let i = 0; i < fragments; i++) {
      const newAddr = await this.createSubaddress(`Fragment_${Math.random().toString(36).substring(2, 6)}`, accountIndex);
      destinations.push({
        address: newAddr,
        amount: amountPerFragment
      });
    }

    const res = await RpcClient.call('transfer', {
      destinations,
      account_index: accountIndex,
      ring_size: 16
    });

    return res.tx_hash_list?.[0] || res.tx_hash;
  },

  /**
   * Sweep All: Extinguish all wallet funds to a specific address
   */
  async sweepAll(destination: string, accountIndex: number, priority: number = 0) {
    const res = await RpcClient.call('sweep_all', {
      address: destination,
      account_index: accountIndex,
      priority,
      ring_size: 16
    });
    return res.tx_hash_list;
  },

  // --- Data Query ---
  async getTransactions(accountIndex: number): Promise<Transaction[]> {
    const res = await RpcClient.call('get_transfers', {
      in: true,
      out: true,
      pending: true,
      failed: true,
      pool: false, // pool:true forces daemon mempool query — fails over Tor
      account_index: accountIndex,
    });

    const mapTx = (tx: any, type: 'in' | 'out' | 'pending'): Transaction => ({
      id: tx.txid,
      amount: RpcClient.formatXmr(tx.amount),
      type,
      timestamp: tx.timestamp * 1000,
      address: tx.address || '',
      confirmations: tx.confirmations || 0,
      subaddr_index: tx.subaddr_index,
      fee: tx.fee ? RpcClient.formatXmr(tx.fee) : undefined,
      height: tx.height,
      paymentId: tx.payment_id !== '0000000000000000' ? tx.payment_id : undefined,
      note: tx.note,
      unlockTime: tx.unlock_time,
      doubleSpendSeen: tx.double_spend_seen,
      destinations: tx.destinations && tx.destinations.length > 0
        ? tx.destinations.map((d: any) => ({
          address: d.address,
          amount: RpcClient.formatXmr(d.amount)
        }))
        : undefined
    });

    return [
      ...(res.in || []).map((t: any) => mapTx(t, 'in')),
      ...(res.out || []).map((t: any) => mapTx(t, 'out')),
      ...(res.pending || []).map((t: any) => mapTx(t, 'pending')),
    ].map(tx => ({
      ...tx,
      accountIndex: tx.subaddr_index?.major ?? 0,
    })).sort((a, b) => b.timestamp - a.timestamp);
  },

  async createSubaddress(label: string, accountIndex: number) {
    const res = await RpcClient.call('create_address', {
      account_index: accountIndex,
      label
    });
    return res.address;
  },

  async rescan(height: number) {
    return await RpcClient.call('rescan_blockchain', { height }); // C++ RPC rescans from specified height
  },

  async getFeeEstimates() {
    const res = await RpcClient.call('get_fee_estimate');
    return {
      fees: (res.fees || []).map((f: any) => RpcClient.formatXmr(f)),
      quantization_mask: res.quantization_mask
    };
  },


  async getOutputs(accountIndex: number) {
    try {
      // 🚀 Use incoming_transfers to retrieve all available outputs
      const res = await RpcClient.call('incoming_transfers', {
        account_index: accountIndex,
        transfer_type: 'available',
        verbose: true
      });

      return (res.transfers || []).map((o: any) => ({
        amount: RpcClient.formatXmr(o.amount),
        keyImage: o.key_image,
        isUnlocked: o.unlocked,
        frozen: o.frozen || false,
        spent: false, // If type is "available", it hasn't been spent
        subaddressIndex: o.subaddr_index.minor,
        timestamp: o.timestamp ? o.timestamp * 1000 : Date.now(),
        txid: o.txid
      })).sort((a: any, b: any) => b.timestamp - a.timestamp);

    } catch (e: any) {
      console.error("RPC_METHOD_ERROR: incoming_transfers failed.", e.message);
      return [];
    }
  },

  /**
   * Set subaddress label
   */
  async setSubaddressLabel(index: number, label: string, accountIndex: number) {
    // RPC Method: label_address
    return await RpcClient.call('label_address', {
      account_index: accountIndex,
      index: { major: 0, minor: index },
      label: label
    });
  },

  /**
   * Helper method: fetch full list of subaddresses with real balances
   */
  async getSubaddresses(accountIndex: number) {
    // 1. Get address list (labels, addresses, used status)
    const addrRes = await RpcClient.call('get_address', { account_index: accountIndex });

    // 2. Get per-subaddress balances from getbalance
    const balRes = await RpcClient.call('getbalance', { account_index: accountIndex });

    // Build a lookup map: subaddress_index → { balance, unlocked_balance }
    const balMap = new Map<number, { balance: number; unlocked: number }>();
    if (balRes.per_subaddress) {
      for (const sub of balRes.per_subaddress) {
        balMap.set(sub.address_index, {
          balance: sub.balance || 0,
          unlocked: sub.unlocked_balance || 0
        });
      }
    }

    return (addrRes.addresses || []).map((addr: any) => {
      const bal = balMap.get(addr.address_index);
      return {
        index: addr.address_index,
        address: addr.address,
        label: addr.label || 'UNTITLED_RECIPIENT',
        balance: RpcClient.formatXmr(bal?.balance || 0),
        unlockedBalance: RpcClient.formatXmr(bal?.unlocked || 0),
        isUsed: addr.used || false
      };
    });
  },

  async createSubaddressWithLabel(label: string, accountIndex: number) {
    const address = await this.createSubaddress(label, accountIndex);
    await this.setSubaddressLabel(address.index, label, accountIndex);
    return address;
  },

  async sendTransaction(destination: string, amount: number, accountIndex: number, priority: number = 0) {
    const tx = await RpcClient.call('transfer', {
      destinations: [{ address: destination, amount: RpcClient.toAtomic(amount) }],
      account_index: accountIndex,
      priority,
      ring_size: 16
    });

    return tx.tx_hash;
  },

  /**
   * Vanish Coin: Sweeps a single output (identified by its key_image) back to the main account address.
   */
  async vanishCoin(keyImage: string, accountIndex: number = 0) {
    // 1. Get the primary address for this account to sweep back to
    const addressRes = await RpcClient.call('get_address', { account_index: accountIndex, address_index: [0] });
    const primaryAddress = addressRes.address;

    // 2. Perform the single sweep
    const tx = await RpcClient.call('sweep_single', {
      address: primaryAddress,
      key_image: keyImage,
      ring_size: 16
    });

    return tx.tx_hash_list?.[0] || tx.tx_hash;
  },

  /**
   * Vanish Subaddress: Sweeps ALL outputs from a specific subaddress to a fresh new subaddress.
   */
  async vanishSubaddress(subaddressIndex: number, accountIndex: number = 0) {
    // 1. Create a fresh destination subaddress
    const newAddr = await this.createSubaddress('Vanish_Destination', accountIndex);

    // 2. Sweep all outputs from the target subaddress to the new one
    const tx = await RpcClient.call('sweep_all', {
      address: newAddr,
      account_index: accountIndex,
      subaddr_indices: [subaddressIndex],
      ring_size: 16
    });

    return { txHash: tx.tx_hash_list?.[0] || tx.tx_hash, destination: newAddr };
  },

  async getTxKey(txid: string) {
    const res = await RpcClient.call('get_tx_key', { txid });
    return res.tx_key;
  },

  async getTxProof(txid: string, address: string, message: string = "") {
    const res = await RpcClient.call('get_tx_proof', { txid, address, message });
    return res.signature;
  },

  async checkTxKey(txid: string, txKey: string, address: string) {
    const res = await RpcClient.call('check_tx_key', { txid, tx_key: txKey, address });
    return {
      confirmations: res.confirmations,
      inPool: res.in_pool,
      received: RpcClient.formatXmr(res.received)
    };
  },

  async checkTxProof(txid: string, address: string, message: string, signature: string) {
    const res = await RpcClient.call('check_tx_proof', { txid, address, message, signature });
    return {
      confirmations: res.confirmations,
      good: res.good,
      inPool: res.in_pool,
      received: RpcClient.formatXmr(res.received)
    };
  }
};
