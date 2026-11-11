// Link account and storage recursive proofs to authenticate a slot under the claimed state root.
use ethereum_recursive_proofs::{
    account_statement, AccountClaim, RecursiveProof, storage_statement, StorageClaim,
    verify_linked_storage,
};
fn main(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: pub Field,
    user_vk_hash: pub Field,
    expected_account: AccountClaim,
    slot_key: [u8; 32],
    value: [u8; 32],
) -> pub [Field; 2] {
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
