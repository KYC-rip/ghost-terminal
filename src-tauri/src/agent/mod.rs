//! Agent gateway — a loopback (127.0.0.1) HTTP server that lets an autonomous AI
//! agent query the wallet and make payments. Spending authority is NEVER held by
//! the gateway: every `/transfer` is delegated to `relay_transfer_grant`, so the
//! agent can only spend within a user-armed transfer grant (per-tx / budget / fills
//! / expiry caps enforced by the ledger, spend key retained under its lock). With no
//! grant bound, the gateway is read-only (sync / balance / invoice subaddress).
pub mod gateway;

pub use gateway::AgentGatewayState;
