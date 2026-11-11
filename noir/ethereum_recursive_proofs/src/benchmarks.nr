// Benchmark entry points: recursive consumers, each verifying UltraHonk producer proofs
// against authorized verification-key hashes and binding the expected claim.
// `nargo export` compiles each to its own program for the gates report.
use crate::absence::{storage_zero_statement, StorageZeroClaim, verify_linked_zero_recursive_proofs};
use crate::{
    account_statement, AccountClaim, batch_storage_statement, BatchStorageClaim, RecursiveProof,
    storage_statement, StorageClaim, threshold_statement, ThresholdClaim, verify_linked_batch,
    verify_linked_storage, verify_linked_threshold, verify_storage_recursive_proof,
};

// One storage producer proof.
#[export]
fn consume_storage(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: StorageClaim,
) -> Field {
    verify_storage_recursive_proof(recursive_proof, authorized_vk_hash, expected);
    storage_statement(expected)
}

// An app account proof and a user proof made independently, linked by the storage root.
#[export]
fn linked_storage(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: Field,
    user_vk_hash: Field,
    expected_account: AccountClaim,
    slot_key: [u8; 32],
    value: [u8; 32],
) -> [Field; 2] {
    verify_linked_storage(
        app_recursive_proof,
        user_recursive_proof,
        app_vk_hash,
        user_vk_hash,
        expected_account,
        slot_key,
        value,
    );
    [
        account_statement(expected_account),
        storage_statement(
            StorageClaim { storage_root: expected_account.storage_root, slot_key, value },
        ),
    ]
}

#[export]
fn linked_batch4(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: Field,
    user_vk_hash: Field,
    expected_account: AccountClaim,
    slot_keys: [[u8; 32]; 4],
    values: [[u8; 32]; 4],
) -> [Field; 2] {
    verify_linked_batch(
        app_recursive_proof,
        user_recursive_proof,
        app_vk_hash,
        user_vk_hash,
        expected_account,
        slot_keys,
        values,
    );
    [
        account_statement(expected_account),
        batch_storage_statement(
            BatchStorageClaim { storage_root: expected_account.storage_root, slot_keys, values },
        ),
    ]
}

#[export]
fn linked_threshold(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: Field,
    user_vk_hash: Field,
    expected_account: AccountClaim,
    slot_key: [u8; 32],
    minimum: [u8; 32],
) -> [Field; 2] {
    verify_linked_threshold(
        app_recursive_proof,
        user_recursive_proof,
        app_vk_hash,
        user_vk_hash,
        expected_account,
        slot_key,
        minimum,
    );
    [
        account_statement(expected_account),
        threshold_statement(
            ThresholdClaim { storage_root: expected_account.storage_root, slot_key, minimum },
        ),
    ]
}

#[export]
fn linked_zero(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: Field,
    user_vk_hash: Field,
    expected_account: AccountClaim,
    slot_key: [u8; 32],
) -> Field {
    let expected = StorageZeroClaim { storage_root: expected_account.storage_root, slot_key };
    verify_linked_zero_recursive_proofs(
        app_recursive_proof,
        app_vk_hash,
        expected_account,
        user_recursive_proof,
        user_vk_hash,
        expected,
    );
    storage_zero_statement(expected)
}
