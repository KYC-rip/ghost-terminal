use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoneroAccount {
    pub index: u32,
    pub label: String,
    pub balance: String,
    #[serde(rename = "unlockedBalance")]
    pub unlocked_balance: String,
    #[serde(rename = "baseAddress")]
    pub base_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubaddressInfo {
    pub index: u32,
    pub address: String,
    pub label: String,
    pub balance: String,
    #[serde(rename = "unlockedBalance")]
    pub unlocked_balance: String,
    #[serde(rename = "isUsed")]
    pub is_used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub amount: String,
    #[serde(rename = "type")]
    pub tx_type: String, // "in" | "out" | "pending"
    pub timestamp: u64,
    pub address: String,
    pub confirmations: u64,
    pub fee: Option<String>,
    pub height: Option<u64>,
    #[serde(rename = "accountIndex")]
    pub account_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletOutput {
    pub amount: String,
    #[serde(rename = "keyImage")]
    pub key_image: String,
    #[serde(rename = "isUnlocked")]
    pub is_unlocked: bool,
    pub frozen: bool,
    #[serde(rename = "subaddressIndex")]
    pub subaddress_index: u32,
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedTx {
    pub fee: String,
    pub amount: String,
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    /// Opaque blob to pass to relay_transfer
    #[serde(rename = "txMetadata")]
    pub tx_metadata: Vec<u8>,
    pub destinations: Vec<TxDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxDestination {
    pub address: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub status: String, // "SYNCED" | "SYNCING" | "OFFLINE"
    pub height: u64,
    #[serde(rename = "daemonHeight")]
    pub daemon_height: u64,
    #[serde(rename = "syncPercent")]
    pub sync_percent: f64,
    /// The daemon node provider name (e.g. "monero.one", "cakewallet")
    #[serde(rename = "nodeLabel", default)]
    pub node_label: String,
    /// The daemon node URL
    #[serde(rename = "nodeUrl", default)]
    pub node_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(rename = "routingMode")]
    pub routing_mode: String, // "tor" | "clearnet"
    pub network: String, // "mainnet" | "stagenet"
    #[serde(rename = "customNodeAddress")]
    pub custom_node_address: Option<String>,
    #[serde(rename = "autoLockMinutes")]
    pub auto_lock_minutes: u32,
    // Extensible with serde flatten
    #[serde(flatten)]
    pub extra: serde_json::Value,
}
