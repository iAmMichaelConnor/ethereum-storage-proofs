//! Explicit absence domains; these claims cannot be confused with nonzero inclusion claims.
use super::{halves, pack, RecursiveProof, verify_claim};
use poseidon::poseidon2::Poseidon2;
pub struct StorageZeroClaim {
    pub storage_root: [u64; 4],
    pub slot_key: [u8; 32],
}
pub struct AccountAbsentClaim {
    pub state_root: [u64; 4],
    pub address: [u8; 20],
}
pub struct L1ZeroClaim {
    pub state_root: [u64; 4],
    pub address: [u8; 20],
    pub slot_key: [u8; 32],
}
pub fn storage_zero_statement(c: StorageZeroClaim) -> Field {
    let k = halves(c.slot_key);
    Poseidon2::hash(
        [
            0x53544f524147455f5a45524f5f5631,
            c.storage_root[0] as Field,
            c.storage_root[1] as Field,
            c.storage_root[2] as Field,
            c.storage_root[3] as Field,
            k[0],
            k[1],
        ],
        7,
    )
}
pub fn account_absent_statement(c: AccountAbsentClaim) -> Field {
    Poseidon2::hash(
        [
            0x4143434f554e545f414253454e545f5631,
            c.state_root[0] as Field,
            c.state_root[1] as Field,
            c.state_root[2] as Field,
            c.state_root[3] as Field,
            pack(c.address),
        ],
        6,
    )
}
pub fn l1_zero_statement(c: L1ZeroClaim) -> Field {
    let k = halves(c.slot_key);
    Poseidon2::hash(
        [
            0x4c315f5a45524f5f5631,
            c.state_root[0] as Field,
            c.state_root[1] as Field,
            c.state_root[2] as Field,
            c.state_root[3] as Field,
            pack(c.address),
            k[0],
            k[1],
        ],
        8,
    )
}
pub fn verify_storage_zero_recursive_proof(
    c: RecursiveProof,
    authorized_vk_hash: Field,
    expected: StorageZeroClaim,
) {
    verify_claim(c, authorized_vk_hash, expected, storage_zero_statement);
}
pub fn verify_account_absent_recursive_proof(
    c: RecursiveProof,
    authorized_vk_hash: Field,
    expected: AccountAbsentClaim,
) {
    verify_claim(c, authorized_vk_hash, expected, account_absent_statement);
}
pub fn verify_l1_zero_recursive_proof(
    c: RecursiveProof,
    authorized_vk_hash: Field,
    expected: L1ZeroClaim,
) {
    verify_claim(c, authorized_vk_hash, expected, l1_zero_statement);
}
/// Bind independently produced included-account and zero-storage proofs to the same storage root.
pub fn verify_linked_zero_recursive_proofs(
    account: RecursiveProof,
    account_vk_hash: Field,
    account_claim: super::AccountClaim,
    storage: RecursiveProof,
    storage_vk_hash: Field,
    storage_claim: StorageZeroClaim,
) {
    assert_eq(account_claim.storage_root, storage_claim.storage_root);
    super::verify_account_recursive_proof(account, account_vk_hash, account_claim);
    verify_storage_zero_recursive_proof(storage, storage_vk_hash, storage_claim);
}

#[test]
fn test_storage_zero_statement_binds_every_leaf() {
    let claim = StorageZeroClaim {
        storage_root: super::sample_lanes(21),
        slot_key: super::sample_bytes(22),
    };
    let digest = storage_zero_statement(claim);
    super::assert_u64s_bound(
        digest,
        claim.storage_root,
        |storage_root| {
            let mut changed = claim;
            changed.storage_root = storage_root;
            storage_zero_statement(changed)
        },
    );
    super::assert_u8s_bound(
        digest,
        claim.slot_key,
        |slot_key| {
            let mut changed = claim;
            changed.slot_key = slot_key;
            storage_zero_statement(changed)
        },
    );
}

#[test]
fn test_account_absent_statement_binds_every_leaf() {
    let claim = AccountAbsentClaim {
        state_root: super::sample_lanes(23),
        address: super::sample_bytes(24),
    };
    let digest = account_absent_statement(claim);
    super::assert_u64s_bound(
        digest,
        claim.state_root,
        |state_root| {
            let mut changed = claim;
            changed.state_root = state_root;
            account_absent_statement(changed)
        },
    );
    super::assert_u8s_bound(
        digest,
        claim.address,
        |address| {
            let mut changed = claim;
            changed.address = address;
            account_absent_statement(changed)
        },
    );
}

#[test]
fn test_l1_zero_statement_binds_every_leaf() {
    let claim = L1ZeroClaim {
        state_root: super::sample_lanes(25),
        address: super::sample_bytes(26),
        slot_key: super::sample_bytes(27),
    };
    let digest = l1_zero_statement(claim);
    super::assert_u64s_bound(
        digest,
        claim.state_root,
        |state_root| {
            let mut changed = claim;
            changed.state_root = state_root;
            l1_zero_statement(changed)
        },
    );
    super::assert_u8s_bound(
        digest,
        claim.address,
        |address| {
            let mut changed = claim;
            changed.address = address;
            l1_zero_statement(changed)
        },
    );
    super::assert_u8s_bound(
        digest,
        claim.slot_key,
        |slot_key| {
            let mut changed = claim;
            changed.slot_key = slot_key;
            l1_zero_statement(changed)
        },
    );
}
