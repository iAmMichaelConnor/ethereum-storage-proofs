// Link account and threshold recursive proofs to authenticate a minimum storage value.
use ethereum_recursive_proofs::{
    account_statement, AccountClaim, RecursiveProof, threshold_statement, ThresholdClaim,
    verify_linked_threshold,
};
fn main(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: pub Field,
    user_vk_hash: pub Field,
    expected_account: AccountClaim,
    slot_key: [u8; 32],
    minimum: [u8; 32],
) -> pub [Field; 2] {
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
