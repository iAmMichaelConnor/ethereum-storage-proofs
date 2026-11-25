use aztec::{
    context::PublicContext,
    protocol::{hash::poseidon2_hash, traits::{Deserialize, Packable, Serialize}},
    state_vars::{Map, PublicMutable},
};
use ethereum_public_proofs::{NODE_FIELDS, PublicAccount, StorageProof, verify_account, verify_storage};
use public_proofs_contract::{ACCOUNT_DEPTH, STORAGE_DEPTH};

pub global SLOT_CAPACITY: u32 = 2;
// Two paths of eight nodes share at least their root whenever both have internal nodes.
pub global SHARED_NODE_CAPACITY: u32 = 15;
global TWO_160: Field = 0x10000000000000000000000000000000000000000;
global TWO_128: Field = 0x100000000000000000000000000000000;

/// The contract ABI for one claim. Indices refer to the shared storage node table.
#[derive(Deserialize, Serialize)]
pub struct BatchSlot {
    pub slot_key: [u8; 32],
    pub value_high: u128,
    pub value_low: u128,
    pub node_indices: [u32; STORAGE_DEPTH],
    pub count: u32,
}

impl BatchSlot {
    pub fn proof(self) -> StorageProof<STORAGE_DEPTH> {
        StorageProof {
            slot_key: self.slot_key,
            value_high: self.value_high,
            value_low: self.value_low,
            node_indices: self.node_indices,
            count: self.count,
        }
    }
}

#[derive(Packable)]
pub struct VerifiedStorageRoot {
    first: u128,
    last_with_presence: Field,
}

impl VerifiedStorageRoot {
    fn from_lanes(lanes: [u64; 4]) -> Self {
        let first = lanes[0] as u128 | ((lanes[1] as u128) << 64);
        let last = lanes[2] as u128 | ((lanes[3] as u128) << 64);
        // The marker fits above both lanes. An unwritten entry has a zero field.
        Self { first, last_with_presence: last as Field + TWO_128 }
    }

    fn read_lanes(self) -> [u64; 4] {
        assert(self.last_with_presence != 0, "Account was not verified for this state root");
        let last = self.last_with_presence as u128;
        [self.first as u64, (self.first >> 64) as u64, last as u64, (last >> 64) as u64]
    }
}

pub type AccountRoots<Context> = Map<Field, PublicMutable<VerifiedStorageRoot, Context>, Context>;

/// The address and all four lanes refer to one snapshot on the contract's configured Ethereum chain.
unconstrained fn snapshot_key(root: [u64; 4], address: Field) -> Field {
    assert(address.lt(TWO_160), "Address exceeds 160 bits");
    poseidon2_hash(
        [root[0] as Field, root[1] as Field, root[2] as Field, root[3] as Field, address],
    )
}

pub unconstrained fn record_verified_account(
    cache: AccountRoots<PublicContext>,
    root: [u64; 4],
    account_fields: [Field; 8],
    account_nodes: [[Field; NODE_FIELDS]; ACCOUNT_DEPTH],
    account_count: u32,
) {
    let account = PublicAccount::from_fields(account_fields);
    verify_account(root, account, account_nodes, account_count);
    cache.at(snapshot_key(root, account.address)).write(VerifiedStorageRoot::from_lanes(account.storage_hash));
}

pub unconstrained fn prove_cached_slot(
    cache: AccountRoots<PublicContext>,
    root: [u64; 4],
    address: Field,
    slot_key: [u8; 32],
    value_high: u128,
    value_low: u128,
    nodes: [[Field; NODE_FIELDS]; STORAGE_DEPTH],
    count: u32,
) {
    let storage_root = cache.at(snapshot_key(root, address)).read().read_lanes();
    verify_storage(storage_root, slot_key, value_high, value_low, nodes, count);
}
