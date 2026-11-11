use aztec::macros::aztec;

mod log;
pub use log::{apply_event, Block, count_event, EthereumLog, freshness_deadline, ProofNode, Terms, verify_log};

/// WARNING: example only. Unaudited; not for deployment as-is.
///
/// Applies a fixed effect once per Ethereum log of one kind, proven in a transaction receipt under the receipts root of
/// a block that the deployer pins. `ethereum_proofs::events::verify_event` proves the receipt at `transaction_index`
/// and the exact log at the receipt-local `log_index`: its emitter, topics and data. The contract also requires a
/// successful post-Byzantium receipt.
///
/// - The pinned block is not checked against Ethereum consensus or finality: the deployer is trusted for it, as for any
///   pinned root, so the contract accepts logs of that one block.
/// - The event id is (chain id, block number, transaction index, log index), never the receipts root alone, and one
///   nullifier per event id makes the effect happen at most once.
/// - The contract stores only a hash of its terms (a transaction has a small public-write limit); every call passes
///   them.
/// - Anyone who has the log can submit it; the effect (a public counter here) does not depend on the caller.
/// - Capacities: trie depth 4, 532-byte nodes, a 1024-byte receipt, 3 logs per receipt and 256 data bytes. Depth 4 does
///   not reach every transaction index of a large block.
#[aztec]
pub contract EventProof {
    use crate::{apply_event, count_event, EthereumLog, Terms};
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        state_vars::{PublicImmutable, PublicMutable},
    };

    #[storage]
    struct Storage<Context> {
        terms_hash: PublicImmutable<Field, Context>,
        events: PublicMutable<Field, Context>,
    }

    #[initializer]
    #[external("public")]
    fn constructor(terms: Terms) {
        self.storage.terms_hash.initialize(terms.hash());
    }

    /// Applies the effect once for a proven log of the pinned kind in the pinned block.
    #[external("private")]
    fn on_event(terms: Terms, log: EthereumLog) {
        apply_event(self.context, self.storage.terms_hash.read(), terms, log);
        self.enqueue_self.record_event();
    }

    #[only_self]
    #[external("public")]
    fn record_event() {
        count_event(self.storage.events);
    }

    #[view]
    #[external("public")]
    fn count() -> Field {
        self.storage.events.read()
    }
}
