//! Transaction construction, signing, and broadcasting.
//!
//! Uses monero-wallet's SignableTransaction for construction + signing,
//! and MoneroDaemon's publish_transaction for broadcasting.

use rand_core::OsRng;
use zeroize::Zeroizing;

use monero_address::MoneroAddress;
use monero_daemon_rpc::prelude::*;
use monero_oxide::ed25519::{Point, Scalar};
use monero_oxide::ringct::RctType;
use monero_oxide::transaction::Transaction;
use monero_wallet::send::{Change, SignableTransaction, TransactionKeys};
use monero_wallet::{OutputWithDecoys, ViewPair, WalletOutput};

/// Prepared transaction ready for signing.
pub struct PreparedTransaction {
    pub signable: SignableTransaction,
    pub fee: u64,
    pub amount: u64,
    pub destinations: Vec<(String, u64)>,
    /// Output ids (txid:index) consumed as real inputs — recorded as spent once
    /// the tx is successfully broadcast.
    pub spent_ids: Vec<String>,
    /// The transaction's main secret key (hex), re-derived deterministically for
    /// proof-of-payment export. Empty if it couldn't be derived.
    pub tx_key_hex: String,
}

/// Re-derive a transaction's main secret key from the same inputs the signer
/// uses. monero-oxide derives tx keys deterministically from the outgoing view
/// key + the (key, commitment) of each real input, in the order provided to
/// SignableTransaction::new (which preserves input order). This is the SAME
/// generator the library uses internally — not novel crypto. Returns the main
/// key only (correct for single standard-address sends and sweeps; multi-output
/// / subaddress sends also use per-output additional keys, which we omit).
fn derive_tx_key_hex(
    outgoing_view_key: &Zeroizing<[u8; 32]>,
    inputs: &[OutputWithDecoys],
) -> String {
    let iks: Vec<(Point, Point)> = inputs
        .iter()
        .map(|o| (o.key(), o.commitment().commit()))
        .collect();
    let mut keys = TransactionKeys::new(outgoing_view_key, iks);
    match keys.next() {
        Some(tx_key) => hex::encode(<[u8; 32]>::from(*tx_key)),
        None => String::new(),
    }
}

/// Concurrency for ring-decoy selection. Each decoy fetch is a small, latency-bound
/// RPC, so selecting them in parallel turns a fragmented wallet's serial decoy loop
/// (one round-trip per input — minutes, and >90s-timeout-prone, for a many-input
/// sweep/send) into a few concurrent rounds. Kept modest so it doesn't overwhelm a
/// Tor circuit.
const DECOY_CONCURRENCY: usize = 8;

/// Select ring decoys for every input concurrently, preserving input order. Each
/// task uses its own OsRng (a shared `&mut rng` can't cross concurrent futures).
async fn fetch_decoys_parallel(
    daemon: &(impl ProvidesDecoys + Sync),
    inputs: Vec<WalletOutput>,
    ring_len: u8,
    block_number: usize,
) -> Result<Vec<OutputWithDecoys>, String> {
    use futures::stream::StreamExt;
    futures::stream::iter(inputs.into_iter())
        .map(|input| async move {
            let mut rng = OsRng;
            OutputWithDecoys::new(&mut rng, daemon, ring_len, block_number, input).await
        })
        .buffered(DECOY_CONCURRENCY)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Decoy selection failed: {:?}", e))
}

/// Construct a transaction (select decoys, compute fee), but don't sign yet.
/// Returns a PreparedTransaction that can be reviewed before signing.
pub async fn prepare_transaction(
    daemon: &(impl ProvidesDecoys + ProvidesBlockchainMeta + ProvidesFeeRates + Sync),
    view_pair: &ViewPair,
    inputs: Vec<WalletOutput>,
    payments: Vec<(MoneroAddress, u64)>,
    priority: FeePriority,
) -> Result<PreparedTransaction, String> {
    // Record which owned outputs are being spent (every provided input is a real
    // spend; decoys are ring members, not inputs) before they're consumed.
    let spent_ids: Vec<String> = inputs.iter().map(crate::wallet::state::output_id).collect();

    // Get current block number for decoy selection
    let block_number = daemon
        .latest_block_number()
        .await
        .map_err(|e| format!("Failed to get block number: {:?}", e))?;

    // Select decoys for each input (concurrently — see fetch_decoys_parallel).
    let ring_len = 16u8; // Monero's current ring size
    let inputs_with_decoys = fetch_decoys_parallel(daemon, inputs, ring_len, block_number).await?;

    // Get fee rate from daemon
    // max_per_weight: safety cap to prevent absurd fees from a malicious node
    // 500_000 pico per weight unit is generous (~0.05 XMR for a typical tx)
    let fee_rate = daemon
        .fee_rate(priority, 500_000)
        .await
        .map_err(|e| format!("Failed to get fee rate: {:?}", e))?;

    // Outgoing view key — used to seed deterministic RNGs for transaction construction.
    // We use a hash of the spend point as a deterministic but unique value.
    let spend_compressed = view_pair.spend().compress();
    let outgoing_view_key = Zeroizing::new(spend_compressed.to_bytes());

    // Derive the tx secret key now (same generator the signer uses), for
    // proof-of-payment export via get_tx_key.
    let tx_key_hex = derive_tx_key_hex(&outgoing_view_key, &inputs_with_decoys);

    // Set change to go back to our primary address
    let change = Change::new(view_pair.clone(), None);

    // Destination info for display
    let destinations: Vec<(String, u64)> = payments
        .iter()
        .map(|(addr, amt)| (addr.to_string(), *amt))
        .collect();

    let total_amount: u64 = payments.iter().map(|(_, a)| a).sum();

    // Construct signable transaction
    let signable = SignableTransaction::new(
        RctType::ClsagBulletproofPlus,
        outgoing_view_key,
        inputs_with_decoys,
        payments,
        change,
        vec![], // no extra data
        fee_rate,
    )
    .map_err(|e| format!("Transaction construction failed: {:?}", e))?;

    let fee = signable.necessary_fee();

    Ok(PreparedTransaction {
        signable,
        fee,
        amount: total_amount,
        destinations,
        spent_ids,
        tx_key_hex,
    })
}

/// Prepare a sweep: send ALL provided outputs to one address with no change
/// output (residual goes to fee via `Change::fingerprintable(None)`). The amount
/// is `total - necessary_fee`; we probe once to learn the fee for the
/// (N inputs, 1 output) structure, then rebuild at the exact amount.
pub async fn prepare_sweep(
    daemon: &(impl ProvidesDecoys + ProvidesBlockchainMeta + ProvidesFeeRates + Sync),
    view_pair: &ViewPair,
    inputs: Vec<WalletOutput>,
    destination: MoneroAddress,
    priority: FeePriority,
) -> Result<PreparedTransaction, String> {
    if inputs.is_empty() {
        return Err("No spendable outputs to sweep".into());
    }
    let spent_ids: Vec<String> = inputs.iter().map(crate::wallet::state::output_id).collect();
    let total: u64 = inputs.iter().map(|o| o.commitment().amount).sum();

    let block_number = daemon
        .latest_block_number()
        .await
        .map_err(|e| format!("Failed to get block number: {:?}", e))?;
    let ring_len = 16u8;
    let owds = fetch_decoys_parallel(daemon, inputs, ring_len, block_number).await?;
    let fee_rate = daemon
        .fee_rate(priority, 500_000)
        .await
        .map_err(|e| format!("Failed to get fee rate: {:?}", e))?;
    let outgoing_view_key = Zeroizing::new(view_pair.spend().compress().to_bytes());

    let build = |amount: u64, owds: Vec<OutputWithDecoys>| {
        // Monero requires >= 2 outputs (SendError::NoChange otherwise). A sweep has
        // no change, so split the swept amount across TWO outputs to the destination
        // — the canonical sweep shape (matches monero-wallet-rpc sweep_all). One
        // payment + no change = a single output and is rejected.
        let half = amount / 2;
        SignableTransaction::new(
            RctType::ClsagBulletproofPlus,
            outgoing_view_key.clone(),
            owds,
            vec![(destination, half), (destination, amount - half)],
            Change::fingerprintable(None), // no change output — sweep everything
            vec![],
            fee_rate,
        )
    };

    // Probe with a safe sub-total amount to read the necessary fee for this
    // (N inputs, 1 output, no change) shape, then rebuild at total - fee.
    let probe =
        build(total / 2, owds.clone()).map_err(|e| format!("Sweep probe failed: {:?}", e))?;
    let fee = probe.necessary_fee();
    if total <= fee {
        return Err(format!(
            "Balance ({}) is too small to cover the sweep fee ({})",
            format_atomic(total),
            format_atomic(fee)
        ));
    }
    let amount = total - fee;
    let tx_key_hex = derive_tx_key_hex(&outgoing_view_key, &owds);
    let signable =
        build(amount, owds).map_err(|e| format!("Sweep construction failed: {:?}", e))?;

    Ok(PreparedTransaction {
        signable,
        fee,
        amount,
        destinations: vec![(destination.to_string(), amount)],
        spent_ids,
        tx_key_hex,
    })
}

/// Format atomic units to an XMR string (local helper to avoid a state dep).
fn format_atomic(atomic: u64) -> String {
    format!(
        "{}.{:012}",
        atomic / 1_000_000_000_000,
        atomic % 1_000_000_000_000
    )
}

/// Sign a prepared transaction with the spend key.
pub fn sign_transaction(
    prepared: PreparedTransaction,
    spend_key: &Zeroizing<Scalar>,
) -> Result<Transaction, String> {
    let mut rng = OsRng;
    prepared
        .signable
        .sign(&mut rng, spend_key)
        .map_err(|e| format!("Transaction signing failed: {:?}", e))
}

/// Broadcast a signed transaction to the daemon.
pub async fn broadcast_transaction(
    daemon: &impl PublishTransaction,
    tx: &Transaction,
) -> Result<(), String> {
    daemon
        .publish_transaction(tx)
        .await
        .map_err(|e| format!("Broadcast failed: {:?}", e))
}
