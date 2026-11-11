use aztec::macros::aztec;

mod policy;
pub use policy::{check_policy, count_acceptance, Policy, SLOTS, verify_submission};

#[aztec]
pub contract StorageProofs {
    use crate::{check_policy, count_acceptance, Policy, SLOTS, verify_submission};
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        state_vars::{PublicImmutable, PublicMutable},
    };

    #[storage]
    struct Storage<Context> {
        policy: PublicImmutable<Policy, Context>,
        accepted: PublicMutable<Field, Context>,
    }

    // The deployer pins the state root, the account address and both producer
    // verification-key hashes. A production app must obtain the root from its
    // authenticated Ethereum block/finality policy instead of a fixed value.
    #[initializer]
    #[external("public")]
    fn constructor(policy: Policy) {
        check_policy(policy);
        self.storage.policy.initialize(policy);
        self.storage.accepted.write(0);
    }

    #[external("private")]
    fn accept(
        app_key: [Field; 115],
        app_proof: [Field; 458],
        user_key: [Field; 115],
        user_proof: [Field; 458],
        storage_root: [u64; 4],
        slot_keys: [[u8; 32]; SLOTS],
        values: [[u8; 32]; SLOTS],
    ) {
        verify_submission(
            self.storage.policy.read(),
            app_key,
            app_proof,
            user_key,
            user_proof,
            storage_root,
            slot_keys,
            values,
        );
        // Application predicates can constrain these exact private slots/values.
        // This example applies none and emits no nullifier: the same pair of
        // proofs is accepted again in a later transaction, and any slot of the
        // pinned account qualifies. An application that accepts a fact once
        // must push a domain-separated nullifier derived from the claim
        // (address, slot key and, if the value may change, the state root).
        self.enqueue_self.record_acceptance();
    }

    #[only_self]
    #[external("public")]
    fn record_acceptance() {
        count_acceptance(self.storage.accepted);
    }

    #[view]
    #[external("public")]
    fn count() -> Field {
        self.storage.accepted.read()
    }
}
