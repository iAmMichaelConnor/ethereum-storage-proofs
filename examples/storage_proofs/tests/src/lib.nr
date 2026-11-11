//! Tests of StorageProofs' logic, run without deploying the contract: `check_policy` is the constructor's check,
//! `verify_submission` the body of `accept` and `count_acceptance` the body of `record_acceptance`. Executing a circuit
//! does not verify its recursive proofs (the backend does, when proving), so `verify_submission` runs on placeholder
//! proofs: these tests pin the policy, the wiring and the counter, never proof soundness.
use aztec::{protocol::traits::Deserialize, state_vars::{PublicMutable, StateVariable}};
use aztec::test::helpers::test_environment::TestEnvironment;
use storage_proofs_contract::{check_policy, count_acceptance, Policy, StorageProofs, verify_submission};

// Serialised Policy: state_root[4], address[20], app_vk_hash, user_vk_hash.
fn policy(app_vk_hash: Field, user_vk_hash: Field) -> Policy {
    let mut fields = [5; 26];
    fields[0] = 1;
    fields[1] = 2;
    fields[2] = 3;
    fields[3] = 4;
    fields[24] = app_vk_hash;
    fields[25] = user_vk_hash;
    Policy::deserialize(fields)
}

fn submit() {
    verify_submission(
        policy(7, 11),
        [0; 115],
        [0; 458],
        [0; 115],
        [0; 458],
        [0; 4],
        [[0; 32]; 4],
        [[0; 32]; 4],
    );
}

// A policy with both key hashes passes the constructor's check, and `accept`'s private part executes on a submission
// under it. Recursive proof verification has no unconstrained form, so this test runs constrained.
#[test]
fn valid_policy_and_submission_execute() {
    check_policy(policy(7, 11));
    submit();
}

#[test]
unconstrained fn accepted_submissions_are_counted() {
    TestEnvironment::new().public_context(|context| {
        let accepted = PublicMutable::new(context, StorageProofs::storage_layout().accepted.slot);
        assert_eq(accepted.read(), 0);
        count_acceptance(accepted);
        assert_eq(accepted.read(), 1);
        count_acceptance(accepted);
        assert_eq(accepted.read(), 2);
    });
}

#[test(should_fail_with = "Zero producer key hash")]
unconstrained fn zero_app_key_hash_rejected_at_deployment() {
    check_policy(policy(0, 11));
}

#[test(should_fail_with = "Zero producer key hash")]
unconstrained fn zero_user_key_hash_rejected_at_deployment() {
    check_policy(policy(7, 0));
}
