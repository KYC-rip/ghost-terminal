use core::future::Future;

use crate::InterfaceError;

/// Provides metadata from the blockchain.
pub trait ProvidesBlockchainMeta: Sync {
  /// Get the number of the latest block.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  fn latest_block_number(&self) -> impl Send + Future<Output = Result<usize, InterfaceError>>;
}
