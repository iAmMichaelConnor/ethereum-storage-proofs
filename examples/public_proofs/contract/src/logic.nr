//! The logic of PublicProofs' functions, callable from TXE test contexts.
use aztec::{
    context::PublicContext,
    protocol::{traits::{Deserialize, Packable, Serialize}, utils::reader::Reader},
    state_vars::{Map, PublicMutable},
};
use ethereum_proofs::{proof::EncodedNode, types::StorageSlot, verify_storage_proof};
use ethereum_public_proofs::{NODE_FIELDS, PublicAccount, verify_account, verify_account_and_storage};

pub global ACCOUNT_DEPTH: u32 = 10;
pub global STORAGE_DEPTH: u32 = 8;
/// Storage path capacity of the private proof: the private function's circuit grows with it.
pub global PRIVATE_STORAGE_DEPTH: u32 = 7;
pub global NODE_BYTES: u32 = 532;

/// An Ethereum state root as four little-endian lanes.
#[derive(Deserialize, Packable, Serialize)]
pub struct StateRoot {
    pub lanes: [u64; 4],
}

/// One packed trie node as a public-function argument: its `NODE_FIELDS` fields (`ethereum_public_proofs` layout).
/// aztec-nr decodes a `[Field; N]` argument in a loop that costs about 700 L2 gas per field; this type reads its
/// fields straight into an array literal, for less than half of that.
#[derive(Serialize)]
pub struct PackedNode {
    pub fields: [Field; NODE_FIELDS],
}

impl Deserialize for PackedNode {
    let N: u32 = NODE_FIELDS;

    fn deserialize(fields: [Field; Self::N]) -> Self {
        PackedNode { fields }
    }

    #[inline_always]
    fn stream_deserialize<let K: u32>(reader: &mut Reader<K>) -> Self {
        PackedNode { fields: read_node_fields!() }
    }
}

/// `[reader.read(), reader.read(), ...]`, one read per node field, in order.
comptime fn read_node_fields() -> Quoted {
    let mut reads: [Quoted] = @[];
    for _ in 0..NODE_FIELDS {
        reads = reads.push_back(quote { reader.read() });
    }
    let reads = reads.join(quote { , });
    quote { [$reads] }
}

/// The fields of packed node arguments.
pub fn node_fields<let D: u32>(nodes: [PackedNode; D]) -> [[Field; NODE_FIELDS]; D] {
    nodes.map(|node: PackedNode| node.fields)
}

/// One raw trie node for the private storage proof (`ethereum_proofs::proof::EncodedNode`, which has no
/// serialisation for a function ABI).
#[derive(Deserialize, Serialize)]
pub struct ProofNode {
    pub bytes: [u8; NODE_BYTES],
    pub length: u32,
    pub is_extension: bool,
}

/// The state root recorded for `block_number`. Fails if none is.
pub unconstrained fn trusted_root(
    roots: Map<Field, PublicMutable<StateRoot, PublicContext>, PublicContext>,
    block_number: Field,
) -> [u64; 4] {
    let root = roots.at(block_number).read().lanes;
    assert(root != [0; 4], "No state root for this block");
    root
}

/// The body of `prove_slot`: the account and the slot value, both proven in public.
pub unconstrained fn prove_slot_in_public(
    root: [u64; 4],
    account: [Field; 8],
    account_nodes: [[Field; NODE_FIELDS]; ACCOUNT_DEPTH],
    account_count: u32,
    slot_key: [u8; 32],
    value_high: u128,
    value_low: u128,
    storage_nodes: [[Field; NODE_FIELDS]; STORAGE_DEPTH],
    storage_count: u32,
) {
    verify_account_and_storage(
        root,
        PublicAccount::from_fields(account),
        account_nodes,
        account_count,
        slot_key,
        value_high,
        value_low,
        storage_nodes,
        storage_count,
    );
}

/// The private part of `prove_slot_privately`: the slot holds `value` under `storage_root`.
pub fn prove_storage_in_private(
    storage_root: [u64; 4],
    slot_key: [u8; 32],
    value: [u8; 32],
    value_length: u8,
    storage_nodes: [ProofNode; PRIVATE_STORAGE_DEPTH],
    storage_count: u32,
) {
    let nodes = storage_nodes.map(|n: ProofNode| {
        EncodedNode { bytes: n.bytes, length: n.length, is_extension: n.is_extension }
    });
    verify_storage_proof(
        storage_root,
        slot_key,
        StorageSlot { value, value_length },
        nodes,
        storage_count,
    );
}

/// The body of `check_account`: the account, with `storage_root`, is under `root`.
pub unconstrained fn prove_account_in_public(
    root: [u64; 4],
    account: [Field; 8],
    account_nodes: [[Field; NODE_FIELDS]; ACCOUNT_DEPTH],
    account_count: u32,
    storage_root: [u64; 4],
) {
    let account = PublicAccount::from_fields(account);
    assert_eq(account.storage_hash, storage_root, "Account has a different storage root");
    verify_account(root, account, account_nodes, account_count);
}

/// The public effect of an accepted proof: one more on the counter.
pub fn count_acceptance(accepted: PublicMutable<Field, PublicContext>) {
    accepted.write(accepted.read() + 1);
}
