//! Poseidon2 UltraHonk recursive proofs for Aztec v6 private callers.
//! The caller must authorize the producer verification-key hash and authenticate
//! the root. A witness-supplied key hash alone is not an authorization policy.
use ethereum_types::StorageSlot;
use poseidon::poseidon2::Poseidon2;

pub struct L1Claim {
    pub state_root: [u64; 4],
    pub address: [u8; 20],
    pub slot_key: [u8; 32],
    /// Full uint256, big endian. Unlike StorageSlot, this is left-zero-padded.
    pub value: [u8; 32],
}

pub struct StorageClaim {
    pub storage_root: [u64; 4],
    pub slot_key: [u8; 32],
    pub value: [u8; 32],
}

pub struct RecursiveProof {
    pub verification_key: [Field; 115],
    /// Includes the eight pairing-accumulator fields. Do not strip them.
    pub proof: [Field; 458],
}

fn pack<let N: u32>(bytes: [u8; N]) -> Field {
    std::static_assert(N <= 31, "Packing must be injective");
    let mut result = 0;
    for byte in bytes {
        result = result * 256 + byte as Field;
    }
    result
}

fn halves(word: [u8; 32]) -> [Field; 2] {
    let mut hi = [0; 16];
    let mut lo = [0; 16];
    for i in 0..16 {
        hi[i] = word[i];
        lo[i] = word[i + 16];
    }
    [pack(hi), pack(lo)]
}

/// Convert the canonical minimal integer used by Ethereum RLP to a uint256.
pub fn value_word(slot: StorageSlot) -> [u8; 32] {
    assert(slot.value_length > 0);
    assert(slot.value_length <= 32);
    assert(slot.value[0] != 0);
    let mut word = [0; 32];
    for i in 0..32 {
        if i < slot.value_length as u32 {
            word[32 - slot.value_length as u32 + i] = slot.value[i];
        } else {
            assert_eq(slot.value[i], 0, "Nonzero value padding");
        }
    }
    word
}

/// Versioned, domain-separated commitment. Every 256-bit word uses two fields;
/// conversion to a single BN254 field would lose information.
pub fn l1_statement(claim: L1Claim) -> Field {
    let key = halves(claim.slot_key);
    let value = halves(claim.value);
    Poseidon2::hash(
        [
            0x4c3153544f524147455f5631, // L1STORAGE_V1
            claim.state_root[0] as Field,
            claim.state_root[1] as Field,
            claim.state_root[2] as Field,
            claim.state_root[3] as Field,
            pack(claim.address),
            key[0],
            key[1],
            value[0],
            value[1],
        ],
        10,
    )
}

pub fn storage_statement(claim: StorageClaim) -> Field {
    let key = halves(claim.slot_key);
    let value = halves(claim.value);
    Poseidon2::hash(
        [
            0x53544f524147455f5631, // STORAGE_V1; deliberately distinct from L1
            claim.storage_root[0] as Field,
            claim.storage_root[1] as Field,
            claim.storage_root[2] as Field,
            claim.storage_root[3] as Field,
            key[0],
            key[1],
            value[0],
            value[1],
        ],
        9,
    )
}

// All typed claims use the same pinned v6 recursive_proof format and one statement.
// Keep policy and recursive verification in one place; typed wrappers bind domains.
fn verify_claim<T>(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: T,
    statement: fn(T) -> Field,
) {
    assert(authorized_vk_hash != 0);
    std::verify_proof_with_type(
        recursive_proof.verification_key,
        recursive_proof.proof,
        [statement(expected)],
        authorized_vk_hash,
        6,
    );
}

/// Use an authorized key for the full account-plus-storage producer.
/// The expected claim can remain private inside the calling Aztec function.
pub fn verify_l1_recursive_proof(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: L1Claim,
) {
    verify_claim(recursive_proof, authorized_vk_hash, expected, l1_statement);
}

/// Use an authorized key for the storage-only producer, and an authenticated
/// storage root. This does not prove the root belongs to a particular account.
pub fn verify_storage_recursive_proof(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: StorageClaim,
) {
    verify_claim(
        recursive_proof,
        authorized_vk_hash,
        expected,
        storage_statement,
    );
}

// Test helpers for the statement-binding tests here and in absence.nr and receipts.nr.
// Each `statement` closure rebuilds the claim with the given leaves and hashes it.

/// Varied bytes: bit 0 and bit 7 each occur both set and clear.
fn sample_bytes<let N: u32>(seed: u32) -> [u8; N] {
    let mut bytes = [0; N];
    for i in 0..N {
        bytes[i] = ((seed + 73 * i) % 256) as u8;
    }
    bytes
}

/// Varied 64-bit lanes: bit 0 and bit 63 each occur both set and clear.
fn sample_lanes(seed: u64) -> [u64; 4] {
    [0x0123456789abcdef ^ seed, 0xfedcba9876543210 ^ seed, 0x8000000000000001 ^ seed, seed]
}

/// Flip the low bit and, separately, the high bit of every leaf; each must change the digest.
fn assert_leaves_bound<T, let N: u32, Env>(
    digest: Field,
    leaves: [T; N],
    low_and_high_bits: [T; 2],
    statement: fn[Env]([T; N]) -> Field,
)
where
    T: std::ops::BitXor,
{
    for i in 0..N {
        for bit in low_and_high_bits {
            let mut changed = leaves;
            changed[i] = changed[i] ^ bit;
            assert(digest != statement(changed));
        }
    }
}

fn assert_u8s_bound<let N: u32, Env>(
    digest: Field,
    leaves: [u8; N],
    statement: fn[Env]([u8; N]) -> Field,
) {
    assert_leaves_bound(digest, leaves, [0x01, 0x80], statement);
}

fn assert_u32s_bound<let N: u32, Env>(
    digest: Field,
    leaves: [u32; N],
    statement: fn[Env]([u32; N]) -> Field,
) {
    assert_leaves_bound(digest, leaves, [0x01, 0x80000000], statement);
}

fn assert_u64s_bound<let N: u32, Env>(
    digest: Field,
    leaves: [u64; N],
    statement: fn[Env]([u64; N]) -> Field,
) {
    assert_leaves_bound(digest, leaves, [0x01, 0x8000000000000000], statement);
}

#[test]
fn test_l1_and_storage_statements_are_domain_separated() {
    let claim =
        L1Claim { state_root: [1, 2, 3, 4], address: [0; 20], slot_key: [6; 32], value: [7; 32] };
    let storage_claim = StorageClaim {
        storage_root: claim.state_root,
        slot_key: claim.slot_key,
        value: claim.value,
    };
    assert(l1_statement(claim) != storage_statement(storage_claim));
}

#[test]
fn test_l1_statement_binds_every_leaf() {
    let claim = L1Claim {
        state_root: sample_lanes(1),
        address: sample_bytes(2),
        slot_key: sample_bytes(3),
        value: sample_bytes(4),
    };
    let digest = l1_statement(claim);
    assert_u64s_bound(
        digest,
        claim.state_root,
        |state_root| {
            let mut changed = claim;
            changed.state_root = state_root;
            l1_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.address,
        |address| {
            let mut changed = claim;
            changed.address = address;
            l1_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.slot_key,
        |slot_key| {
            let mut changed = claim;
            changed.slot_key = slot_key;
            l1_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.value,
        |value| {
            let mut changed = claim;
            changed.value = value;
            l1_statement(changed)
        },
    );
}

#[test]
fn test_storage_statement_binds_every_leaf() {
    let claim = StorageClaim {
        storage_root: sample_lanes(5),
        slot_key: sample_bytes(6),
        value: sample_bytes(7),
    };
    let digest = storage_statement(claim);
    assert_u64s_bound(
        digest,
        claim.storage_root,
        |storage_root| {
            let mut changed = claim;
            changed.storage_root = storage_root;
            storage_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.slot_key,
        |slot_key| {
            let mut changed = claim;
            changed.slot_key = slot_key;
            storage_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.value,
        |value| {
            let mut changed = claim;
            changed.value = value;
            storage_statement(changed)
        },
    );
}

#[test]
fn test_value_word() {
    let mut value = [0; 32];
    value[0] = 0x80;
    let word = value_word(StorageSlot { value, value_length: 1 });
    assert_eq(word[31], 0x80);
    for i in 0..31 {
        assert_eq(word[i], 0);
    }
    assert_eq(value_word(StorageSlot { value: [255; 32], value_length: 32 }), [255; 32]);
}

#[test(should_fail_with = "Nonzero value padding")]
fn test_noncanonical_value() {
    let _word = value_word(StorageSlot { value: [1; 32], value_length: 1 });
}

/// App-owned recursive_proof: this account's storage root occurs under this state root.
pub struct AccountClaim {
    pub state_root: [u64; 4],
    pub address: [u8; 20],
    pub storage_root: [u64; 4],
}

/// User-owned predicate recursive_proof. The actual slot value stays in its witness.
pub struct ThresholdClaim {
    pub storage_root: [u64; 4],
    pub slot_key: [u8; 32],
    pub minimum: [u8; 32],
}

pub fn account_statement(claim: AccountClaim) -> Field {
    Poseidon2::hash(
        [
            0x4143434f554e545f5631, // ACCOUNT_V1
            claim.state_root[0] as Field,
            claim.state_root[1] as Field,
            claim.state_root[2] as Field,
            claim.state_root[3] as Field,
            pack(claim.address),
            claim.storage_root[0] as Field,
            claim.storage_root[1] as Field,
            claim.storage_root[2] as Field,
            claim.storage_root[3] as Field,
        ],
        10,
    )
}

pub fn threshold_statement(claim: ThresholdClaim) -> Field {
    let key = halves(claim.slot_key);
    let minimum = halves(claim.minimum);
    Poseidon2::hash(
        [
            0x53544f524147455f47455f5631, // STORAGE_GE_V1
            claim.storage_root[0] as Field,
            claim.storage_root[1] as Field,
            claim.storage_root[2] as Field,
            claim.storage_root[3] as Field,
            key[0],
            key[1],
            minimum[0],
            minimum[1],
        ],
        9,
    )
}

/// Compare complete big-endian uint256 words, without reduction modulo a field.
pub fn assert_value_at_least(value: [u8; 32], minimum: [u8; 32]) {
    let mut equal = true;
    let mut greater = false;
    for i in 0..32 {
        greater = greater | (equal & (value[i] > minimum[i]));
        equal = equal & (value[i] == minimum[i]);
    }
    assert(greater | equal, "Storage value is below the minimum");
}

pub fn verify_account_recursive_proof(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: AccountClaim,
) {
    verify_claim(
        recursive_proof,
        authorized_vk_hash,
        expected,
        account_statement,
    );
}

pub fn verify_threshold_recursive_proof(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: ThresholdClaim,
) {
    verify_claim(
        recursive_proof,
        authorized_vk_hash,
        expected,
        threshold_statement,
    );
}

/// Verify both parties' recursive proofs in the SAME constrained private function.
/// The app recursive_proof can be reused for this account/root across users/slots.
/// Authenticate expected_account.state_root and constrain its intended address.
pub fn verify_linked_storage(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: Field,
    user_vk_hash: Field,
    expected_account: AccountClaim,
    slot_key: [u8; 32],
    value: [u8; 32],
) {
    verify_account_recursive_proof(app_recursive_proof, app_vk_hash, expected_account);
    verify_storage_recursive_proof(
        user_recursive_proof,
        user_vk_hash,
        StorageClaim { storage_root: expected_account.storage_root, slot_key, value },
    );
}

/// As above, but the user proves a lower bound without revealing the slot value
/// to the consumer. Bind slot_key to the intended Solidity mapping/storage slot.
pub fn verify_linked_threshold(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: Field,
    user_vk_hash: Field,
    expected_account: AccountClaim,
    slot_key: [u8; 32],
    minimum: [u8; 32],
) {
    verify_account_recursive_proof(app_recursive_proof, app_vk_hash, expected_account);
    verify_threshold_recursive_proof(
        user_recursive_proof,
        user_vk_hash,
        ThresholdClaim { storage_root: expected_account.storage_root, slot_key, minimum },
    );
}

#[test]
fn test_uint256_threshold() {
    assert_value_at_least([255; 32], [255; 32]);
    assert_value_at_least([255; 32], [0; 32]);
    let mut a = [0; 32];
    let mut b = [255; 32];
    a[0] = 128;
    b[0] = 127;
    assert_value_at_least(a, b);
}

#[test(should_fail_with = "Storage value is below the minimum")]
fn test_uint256_threshold_rejects_less() {
    let mut value = [255; 32];
    value[0] = 127;
    let mut minimum = [0; 32];
    minimum[0] = 128;
    assert_value_at_least(value, minimum);
}

#[test]
fn test_account_statement_binds_every_leaf() {
    let claim = AccountClaim {
        state_root: sample_lanes(8),
        address: sample_bytes(9),
        storage_root: sample_lanes(10),
    };
    let digest = account_statement(claim);
    assert_u64s_bound(
        digest,
        claim.state_root,
        |state_root| {
            let mut changed = claim;
            changed.state_root = state_root;
            account_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.address,
        |address| {
            let mut changed = claim;
            changed.address = address;
            account_statement(changed)
        },
    );
    assert_u64s_bound(
        digest,
        claim.storage_root,
        |storage_root| {
            let mut changed = claim;
            changed.storage_root = storage_root;
            account_statement(changed)
        },
    );
}

#[test]
fn test_threshold_statement_binds_every_leaf() {
    let claim = ThresholdClaim {
        storage_root: sample_lanes(11),
        slot_key: sample_bytes(12),
        minimum: sample_bytes(13),
    };
    let digest = threshold_statement(claim);
    assert_u64s_bound(
        digest,
        claim.storage_root,
        |storage_root| {
            let mut changed = claim;
            changed.storage_root = storage_root;
            threshold_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.slot_key,
        |slot_key| {
            let mut changed = claim;
            changed.slot_key = slot_key;
            threshold_statement(changed)
        },
    );
    assert_u8s_bound(
        digest,
        claim.minimum,
        |minimum| {
            let mut changed = claim;
            changed.minimum = minimum;
            threshold_statement(changed)
        },
    );
}

/// Ordered batch claim. Every uint256 remains two injectively packed field limbs.
pub struct BatchStorageClaim<let K: u32> {
    pub storage_root: [u64; 4],
    pub slot_keys: [[u8; 32]; K],
    pub values: [[u8; 32]; K],
}

pub fn batch_storage_statement<let K: u32>(claim: BatchStorageClaim<K>) -> Field {
    std::static_assert(K > 0, "A batch must contain at least one claim");
    let mut fields = [0; 6 + 4 * K];
    fields[0] = 0x53544f524147455f42415443485f5631; // STORAGE_BATCH_V1
    fields[1] = K as Field;
    for i in 0..4 {
        fields[2 + i] = claim.storage_root[i] as Field;
    }
    for i in 0..K {
        let key = halves(claim.slot_keys[i]);
        let value = halves(claim.values[i]);
        fields[6 + 4 * i] = key[0];
        fields[7 + 4 * i] = key[1];
        fields[8 + 4 * i] = value[0];
        fields[9 + 4 * i] = value[1];
    }
    Poseidon2::hash(fields, 6 + 4 * K)
}

pub fn verify_batch_storage_recursive_proof<let K: u32>(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: BatchStorageClaim<K>,
) {
    verify_claim(
        recursive_proof,
        authorized_vk_hash,
        expected,
        batch_storage_statement,
    );
}

/// One app account recursive_proof and one user batch recursive_proof share exactly one
/// storage root. Bind expected_account, ordered keys/values, and both keys in policy.
pub fn verify_linked_batch<let K: u32>(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: Field,
    user_vk_hash: Field,
    expected_account: AccountClaim,
    slot_keys: [[u8; 32]; K],
    values: [[u8; 32]; K],
) {
    verify_account_recursive_proof(app_recursive_proof, app_vk_hash, expected_account);
    verify_batch_storage_recursive_proof(
        user_recursive_proof,
        user_vk_hash,
        BatchStorageClaim { storage_root: expected_account.storage_root, slot_keys, values },
    );
}

#[test]
fn test_batch_storage_statement_binds_every_leaf() {
    let mut slot_keys = [[0; 32]; 4];
    let mut values = [[0; 32]; 4];
    for k in 0..4 {
        slot_keys[k] = sample_bytes(20 + k);
        values[k] = sample_bytes(40 + k);
    }
    let claim = BatchStorageClaim { storage_root: sample_lanes(14), slot_keys, values };
    let digest = batch_storage_statement(claim);
    assert_u64s_bound(
        digest,
        claim.storage_root,
        |storage_root| {
            let mut changed = claim;
            changed.storage_root = storage_root;
            batch_storage_statement(changed)
        },
    );
    for k in 0..4 {
        assert_u8s_bound(
            digest,
            claim.slot_keys[k],
            |slot_key| {
                let mut changed = claim;
                changed.slot_keys[k] = slot_key;
                batch_storage_statement(changed)
            },
        );
        assert_u8s_bound(
            digest,
            claim.values[k],
            |value| {
                let mut changed = claim;
                changed.values[k] = value;
                batch_storage_statement(changed)
            },
        );
    }
}

pub mod receipts;

pub mod absence;
mod benchmarks;
