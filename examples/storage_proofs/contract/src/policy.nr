//! The deployment policy that StorageProofs pins and the logic of its functions.
use aztec::{context::PublicContext, protocol::traits::{Deserialize, Packable, Serialize}, state_vars::PublicMutable};
use ethereum_recursive_proofs::{AccountClaim, RecursiveProof, verify_linked_batch};

// Adjust this one compile-time constant for another ordered batch shape.
pub global SLOTS: u32 = 4;

#[derive(Deserialize, Packable, Serialize)]
pub struct Policy {
    state_root: [u64; 4],
    address: [u8; 20],
    app_vk_hash: Field,
    user_vk_hash: Field,
}

/// The constructor's check of the policy: both producer verification-key hashes are set.
pub fn check_policy(policy: Policy) {
    assert((policy.app_vk_hash != 0) & (policy.user_vk_hash != 0), "Zero producer key hash");
}

/// The private part of `StorageProofs::accept`: verifies the linked app and user proofs of `SLOTS` slots of the
/// pinned account under the policy.
pub fn verify_submission(
    policy: Policy,
    app_key: [Field; 115],
    app_proof: [Field; 458],
    user_key: [Field; 115],
    user_proof: [Field; 458],
    storage_root: [u64; 4],
    slot_keys: [[u8; 32]; SLOTS],
    values: [[u8; 32]; SLOTS],
) {
    verify_linked_batch(
        RecursiveProof { verification_key: app_key, proof: app_proof },
        RecursiveProof { verification_key: user_key, proof: user_proof },
        policy.app_vk_hash,
        policy.user_vk_hash,
        AccountClaim { state_root: policy.state_root, address: policy.address, storage_root },
        slot_keys,
        values,
    );
}

/// The public effect of an accepted submission: one more on the counter.
pub fn count_acceptance(accepted: PublicMutable<Field, PublicContext>) {
    accepted.write(accepted.read() + 1);
}
