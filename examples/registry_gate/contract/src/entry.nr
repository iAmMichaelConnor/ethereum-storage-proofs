//! The registry entry evidence that RegistryGate accepts and its verification.
use aztec::{
    context::{PrivateContext, PublicContext},
    protocol::{
        address::AztecAddress,
        hash::{poseidon2_hash, poseidon2_hash_bytes},
        traits::{Deserialize, Serialize, ToField},
    },
    state_vars::{Map, PublicMutable},
};
use ethereum_proofs::{keccak::keccak256, proof::{EncodedNode, verify_l1_storage}, types::{Account, StorageSlot}};

global ACCOUNT_DEPTH: u32 = 8;
global STORAGE_DEPTH: u32 = 6;
global NODE_BYTES: u32 = 532;

pub global DOMAIN_ENTRY: Field = comptime { poseidon2_hash_bytes("ETHEREUM_REGISTRY_ENTRY_V1".as_bytes()) };

/// The deployment terms: the pinned state root of a chain, the trusted registry and its mapping slot, and the
/// least value that admits a beneficiary.
#[derive(Deserialize, Serialize)]
pub struct Terms {
    pub chain: Field,
    pub state_root: [u8; 32],
    pub registry: [u8; 20],
    pub mapping_slot: [u8; 32],
    pub min_value: Field,
}

impl Terms {
    /// The commitment that the contract stores; callers pass the terms with each call.
    pub fn hash(self) -> Field {
        poseidon2_hash(self.serialize())
    }
}

/// One trie node (`ethereum_proofs::proof::EncodedNode`, which has no serialisation for a function ABI).
#[derive(Deserialize, Serialize)]
pub struct ProofNode {
    pub bytes: [u8; NODE_BYTES],
    pub length: u32,
    pub is_extension: bool,
}

/// The registry account's state (`ethereum_types::Account` without the address, which the entry gives).
#[derive(Deserialize, Serialize)]
pub struct RegistryAccount {
    pub nonce: [u8; 8],
    pub balance: [u8; 32],
    pub nonce_length: u8,
    pub balance_length: u8,
    pub storage_hash: [u64; 4],
    pub code_hash: [u64; 4],
}

/// A registry entry for `beneficiary`, proven under `state_root`. The value holds minimal big-endian bytes,
/// left-aligned, as RLP stores it.
#[derive(Deserialize, Serialize)]
pub struct RegistryEntry {
    pub chain: Field,
    pub state_root: [u8; 32],
    pub registry: [u8; 20],
    pub mapping_slot: [u8; 32],
    pub beneficiary: AztecAddress,
    pub account: RegistryAccount,
    pub account_nodes: [ProofNode; ACCOUNT_DEPTH],
    pub account_count: u32,
    pub storage_nodes: [ProofNode; STORAGE_DEPTH],
    pub storage_count: u32,
    pub value: [u8; 32],
    pub value_length: u8,
}

/// `keccak256(key ++ mapping_slot)`: the storage key of `mapping(bytes32 => ...)` at `mapping_slot`.
pub fn mapping_key(key: [u8; 32], mapping_slot: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0; 64];
    for i in 0..32 {
        preimage[i] = key[i];
        preimage[32 + i] = mapping_slot[i];
    }
    keccak256(preimage, 64)
}

/// Verifies the entry under its state root and returns its value as a field.
pub fn verify_entry(entry: RegistryEntry) -> Field {
    assert(entry.value_length <= 31, "Registry value exceeds 248 bits");
    let key = mapping_key(
        entry.beneficiary.to_field().to_be_bytes::<32>(),
        entry.mapping_slot,
    );
    let node = |n: ProofNode| EncodedNode { bytes: n.bytes, length: n.length, is_extension: n.is_extension };
    verify_l1_storage::<ACCOUNT_DEPTH, NODE_BYTES, STORAGE_DEPTH, NODE_BYTES>(
        lanes(entry.state_root),
        Account {
            nonce: entry.account.nonce,
            balance: entry.account.balance,
            address: entry.registry,
            nonce_length: entry.account.nonce_length,
            balance_length: entry.account.balance_length,
            storage_hash: entry.account.storage_hash,
            code_hash: entry.account.code_hash,
        },
        entry.account_nodes.map(node),
        entry.account_count,
        key,
        StorageSlot { value: entry.value, value_length: entry.value_length },
        entry.storage_nodes.map(node),
        entry.storage_count,
    );
    let mut value: Field = 0;
    for i in 0..31 {
        if i < entry.value_length as u32 {
            value = value * 256 + entry.value[i] as Field;
        }
    }
    value
}

/// The state root as `ethereum_proofs` takes it: four lanes of little-endian bytes.
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

/// The private part of `RegistryGate::claim`, given the stored terms hash: checks the entry against the terms and its
/// proof and pushes one nullifier per beneficiary. Returns the beneficiary and the value to admit.
pub fn apply_claim(
    context: &mut PrivateContext,
    terms_hash: Field,
    terms: Terms,
    entry: RegistryEntry,
) -> (AztecAddress, Field) {
    assert_eq(terms_hash, terms.hash(), "Wrong terms");
    assert((entry.chain == terms.chain) & (entry.state_root == terms.state_root), "Not the pinned state root");
    assert((entry.registry == terms.registry) & (entry.mapping_slot == terms.mapping_slot), "Not the trusted registry");
    let value = verify_entry(entry);
    assert(!value.lt(terms.min_value), "Registry value below the minimum");
    // One admission per beneficiary of this registry and slot; Aztec silos the nullifier by address.
    context.push_nullifier_unsafe(poseidon2_hash([DOMAIN_ENTRY, entry.beneficiary.to_field()]));
    (entry.beneficiary, value)
}

/// The public effect of an admitted entry: the beneficiary's membership value.
pub fn admit_member(
    members: Map<AztecAddress, PublicMutable<Field, PublicContext>, PublicContext>,
    beneficiary: AztecAddress,
    value: Field,
) {
    members.at(beneficiary).write(value);
}
