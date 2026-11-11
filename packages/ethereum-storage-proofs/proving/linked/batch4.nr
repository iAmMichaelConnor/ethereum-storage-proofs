// Link an account recursive_proof to four ordered storage claims through recursive verification.
use ethereum_recursive_proofs::{
    account_statement, AccountClaim, batch_storage_statement, BatchStorageClaim, RecursiveProof,
    verify_linked_batch,
};
global BATCH_SIZE: u32 = 4;
// Bind roots, ordered claims and authorized producer keys in the calling app.
fn main(
    app_recursive_proof: RecursiveProof,
    user_recursive_proof: RecursiveProof,
    app_vk_hash: pub Field,
    user_vk_hash: pub Field,
    expected_account: AccountClaim,
    slot_keys: [[u8; 32]; BATCH_SIZE],
    values: [[u8; 32]; BATCH_SIZE],
) -> pub [Field; 2] {
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
