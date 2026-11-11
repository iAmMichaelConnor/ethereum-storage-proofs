//! The log evidence that EventProof accepts and its verification.
use aztec::{
    context::{PrivateContext, PublicContext},
    protocol::{hash::{poseidon2_hash, poseidon2_hash_bytes}, traits::{Deserialize, Serialize}},
    state_vars::PublicMutable,
};
use ethereum_proofs::{events::{Event, verify_event}, proof::EncodedNode};

global DEPTH: u32 = 4;
global NODE_BYTES: u32 = 532;
global LEAF_BYTES: u32 = 1024;
global MAX_LOGS: u32 = 3;
global DATA_BYTES: u32 = 256;

global DOMAIN_EVENT: Field = comptime { poseidon2_hash_bytes("ETHEREUM_EVENT_PROOF_V1".as_bytes()) };

/// The block the deployer pins: its chain, number, time (Unix seconds) and receipts root.
#[derive(Deserialize, Eq, Serialize)]
pub struct Block {
    pub chain_id: u64,
    pub number: u64,
    pub timestamp: u64,
    pub receipts_root: [u8; 32],
}

/// The deployment terms: the pinned block, the log kind (emitter and first topic) and a freshness ceiling in
/// seconds; `0xffffffffffffffff` accepts any age.
#[derive(Deserialize, Serialize)]
pub struct Terms {
    pub block: Block,
    pub emitter: [u8; 20],
    pub topic0: [u8; 32],
    pub max_age: u64,
}

impl Terms {
    /// The commitment that the contract stores; callers pass the terms with each call.
    pub fn hash(self) -> Field {
        poseidon2_hash(self.serialize())
    }
}

/// One receipt-trie node (`ethereum_proofs::proof::EncodedNode`, which has no serialisation for a function ABI).
#[derive(Deserialize, Serialize)]
pub struct ProofNode {
    pub bytes: [u8; NODE_BYTES],
    pub length: u32,
    pub is_extension: bool,
}

/// A log and its receipt proof. `log_index` is receipt-local; the JSON-RPC block-wide `logIndex` is not this value.
/// Topics past `topic_count` and data bytes past `data_length` must be zero.
#[derive(Deserialize, Serialize)]
pub struct EthereumLog {
    pub block: Block,
    pub transaction_index: u64,
    pub log_index: u32,
    pub nodes: [ProofNode; DEPTH],
    pub count: u32,
    pub leaf: [u8; LEAF_BYTES],
    pub leaf_length: u32,
    pub emitter: [u8; 20],
    pub topics: [[u8; 32]; 4],
    pub topic_count: u32,
    pub data: [u8; DATA_BYTES],
    pub data_length: u32,
}

/// Verifies the log under its block's receipts root and returns its event id.
pub fn verify_log(log: EthereumLog) -> Field {
    let view = verify_event::<DEPTH, NODE_BYTES, LEAF_BYTES, MAX_LOGS, DATA_BYTES>(
        lanes(log.block.receipts_root),
        log.transaction_index,
        log.nodes.map(|n: ProofNode| EncodedNode { bytes: n.bytes, length: n.length, is_extension: n.is_extension }),
        log.count,
        log.leaf,
        log.leaf_length,
        log.log_index,
        Event {
            emitter: log.emitter,
            topics: log.topics,
            topic_count: log.topic_count,
            data: log.data,
            data_length: log.data_length,
        },
    );
    assert(!view.has_post_state & view.status, "Transaction did not succeed");
    poseidon2_hash([
        DOMAIN_EVENT,
        log.block.chain_id as Field,
        log.block.number as Field,
        log.transaction_index as Field,
        log.log_index as Field,
    ])
}

/// The receipts root as `ethereum_proofs` takes it: four lanes of little-endian bytes.
fn lanes(root: [u8; 32]) -> [u64; 4] {
    let mut result = [0; 4];
    for i in 0..4 {
        let mut value: u64 = 0;
        for j in 0..8 {
            value += (root[8 * i + j] as u64) << (8 * j) as u64;
        }
        result[i] = value;
    }
    result
}

/// The last timestamp at which a transaction may use a log of a block at `block_time`. Rejects a block after the
/// anchor block and a log already too old there. The addition saturates.
pub fn freshness_deadline(block_time: u64, anchor_time: u64, max_age: u64) -> u64 {
    assert(block_time <= anchor_time, "Block after the anchor block");
    let remaining = 0xffffffffffffffff - block_time;
    let deadline = block_time
        + if max_age > remaining {
            remaining
        } else {
            max_age
        };
    assert(anchor_time <= deadline, "Event too old");
    deadline
}

/// The private part of `EventProof::on_event`, given the stored terms hash: checks the log against the terms and its
/// receipt proof, limits the transaction to the freshness deadline and pushes the event id as a nullifier.
pub fn apply_event(context: &mut PrivateContext, terms_hash: Field, terms: Terms, log: EthereumLog) {
    assert_eq(terms_hash, terms.hash(), "Wrong terms");
    assert(log.block == terms.block, "Not the pinned block");
    assert(log.emitter == terms.emitter, "Wrong emitter");
    assert((log.topic_count > 0) & (log.topics[0] == terms.topic0), "Wrong event signature");
    let event_id = verify_log(log);
    let anchor_time = context.get_anchor_block_header().timestamp();
    let deadline = freshness_deadline(log.block.timestamp, anchor_time, terms.max_age);
    context.set_expiration_timestamp(deadline);
    // The domain-separated event id cannot equal another nullifier of this contract; Aztec silos it by address.
    context.push_nullifier_unsafe(event_id);
}

/// The public effect of an accepted event: one more on the counter.
pub fn count_event(events: PublicMutable<Field, PublicContext>) {
    events.write(events.read() + 1);
}
