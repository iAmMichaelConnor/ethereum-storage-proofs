// Link account and zero-storage recursive proofs to authenticate an absent or zero-valued slot.
use ethereum_recursive_proofs::{
    absence::{storage_zero_statement, StorageZeroClaim, verify_linked_zero_recursive_proofs},
    AccountClaim,
    RecursiveProof,
};
fn main(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: pub Field,
    user_vk_hash: pub Field,
    expected_account: pub AccountClaim,
    slot_key: [u8; 32],
) -> pub Field {
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
