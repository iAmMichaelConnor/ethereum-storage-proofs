//! Merkle-Patricia account and storage verification for unconstrained code: Aztec
//! public functions (the AVM) and other Brillig. Every entry point is an
//! `unconstrained fn`, so a constrained caller (an Aztec private function or any
//! circuit) must wrap it in `unsafe` and gains no guarantee from it. Use
//! `ethereum_proofs` in circuits.
//!
//! The verifier walks the same tries as `ethereum_proofs`, but takes its inputs
//! in a packed form that is cheap to pass as public-function arguments and to
//! hash with the AVM's Keccak-f[1600] opcode: each node is its RLP bytes as
//! 64-bit Keccak lanes, three per field, so a node is hashed block by block
//! with no byte array built. Hashes, roots and hashed keys are four
//! little-endian lanes, as in `ethereum_proofs`.
//!
//! The roots, the address and the slot are the caller's to authenticate and bind,
//! exactly as for `ethereum_proofs`. Public-function arguments are public, so
//! everything passed here (the root, the account, the slot and its value) is
//! visible on Aztec.

mod sink;
mod node;
mod leaf;
pub mod pack;
mod fixtures_tests;

pub use leaf::PublicAccount;

/// keccak(slot key) as four lanes: the key a storage path walks.
pub unconstrained fn slot_key_hash(slot_key: [u8; 32]) -> [u64; 4] {
    sink::hash_word(slot_key)
}

/// Fields per packed node. The layout is described in `node.nr` and produced
/// by `pack::pack_node` and the TypeScript SDK's `packPublicNode`.
pub global NODE_FIELDS: u32 = 23;
/// Fields per packed account (`PublicAccount::from_fields`).
pub global ACCOUNT_FIELDS: u32 = 8;

/// The end of a walked path: the reference the leaf must match, how many key
/// nibbles the path consumed, and the hashed key it walked. The fields are
/// private so that a leaf check can only bind to a path this crate walked.
pub struct PathEnd {
    reference: sink::Reference,
    nibble: u32,
    key: [u64; 4],
}

/// Walk the first `count` packed nodes from `root` along `key_hash`
/// (keccak(address) for accounts, keccak(slot key) for storage, as lanes). Nodes past
/// `count` are ignored. The result is only meaningful as input to a leaf check.
pub unconstrained fn verify_path<let D: u32>(
    root: [u64; 4],
    key_hash: [u64; 4],
    nodes: [[Field; NODE_FIELDS]; D],
    count: u32,
) -> PathEnd {
    let (reference, nibble) = node::walk(root, key_hash, nodes, count);
    PathEnd { reference, nibble, key: key_hash }
}

/// Finish an account proof. The address is the account's; the path must have
/// walked keccak(address).
pub unconstrained fn verify_account_leaf(end: PathEnd, account: PublicAccount) {
    assert_eq(end.key, account.key_hash(), "Path walked a different key");
    leaf::check_account(end.reference, end.nibble, end.key, account);
}

/// Finish a storage proof for a nonzero value (`value_high * 2^128 + value_low`).
/// The path must have walked `key_hash`.
pub unconstrained fn verify_storage_leaf(
    end: PathEnd,
    key_hash: [u64; 4],
    value_high: u128,
    value_low: u128,
) {
    assert_eq(end.key, key_hash, "Path walked a different key");
    leaf::check_storage(end.reference, end.nibble, end.key, value_high, value_low);
}

/// Prove an account under an authenticated state root.
pub unconstrained fn verify_account<let D: u32>(
    state_root: [u64; 4],
    account: PublicAccount,
    nodes: [[Field; NODE_FIELDS]; D],
    count: u32,
) {
    let end = verify_path(state_root, account.key_hash(), nodes, count);
    verify_account_leaf(end, account);
}

/// Prove that `slot_key` holds a nonzero value under an authenticated storage root.
pub unconstrained fn verify_storage<let D: u32>(
    storage_root: [u64; 4],
    slot_key: [u8; 32],
    value_high: u128,
    value_low: u128,
    nodes: [[Field; NODE_FIELDS]; D],
    count: u32,
) {
    let key_hash = sink::hash_word(slot_key);
    let end = verify_path(storage_root, key_hash, nodes, count);
    verify_storage_leaf(end, key_hash, value_high, value_low);
}

/// Prove an account under an authenticated state root and a nonzero slot value
/// under that account's storage root.
pub unconstrained fn verify_account_and_storage<let AD: u32, let SD: u32>(
    state_root: [u64; 4],
    account: PublicAccount,
    account_nodes: [[Field; NODE_FIELDS]; AD],
    account_count: u32,
    slot_key: [u8; 32],
    value_high: u128,
    value_low: u128,
    storage_nodes: [[Field; NODE_FIELDS]; SD],
    storage_count: u32,
) {
    verify_account(state_root, account, account_nodes, account_count);
    verify_storage(
        account.storage_hash,
        slot_key,
        value_high,
        value_low,
        storage_nodes,
        storage_count,
    );
}
