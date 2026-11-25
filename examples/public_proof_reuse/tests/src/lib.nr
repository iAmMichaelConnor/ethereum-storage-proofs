use aztec::{context::PublicContext, state_vars::{Map, StateVariable}, test::helpers::test_environment::TestEnvironment};
use public_proof_reuse_contract::{AccountRoots, prove_cached_slot, PublicProofReuse, record_verified_account};
use public_proofs_test::fixture::{
    ACCOUNT, ACCOUNT_COUNT, account_nodes, SLOT_KEY, STATE_ROOT, STORAGE_COUNT, storage_nodes, VALUE_HIGH, VALUE_LOW,
};

unconstrained fn reuse_with(root: [u64; 4], address: Field, value_low: u128) {
    let env = TestEnvironment::new();
    env.public_context(|context| {
        let cache: AccountRoots<PublicContext> = Map::new(
            context,
            PublicProofReuse::storage_layout().verified_accounts.slot,
        );
        record_verified_account(cache, STATE_ROOT, ACCOUNT, account_nodes(), ACCOUNT_COUNT);
        prove_cached_slot(
            cache,
            root,
            address,
            SLOT_KEY,
            VALUE_HIGH,
            value_low,
            storage_nodes(),
            STORAGE_COUNT,
        );
    });
}

#[test]
unconstrained fn reuses_verified_storage_root() {
    reuse_with(STATE_ROOT, ACCOUNT[0], VALUE_LOW);
}

#[test(should_fail_with = "Account was not verified for this state root")]
unconstrained fn rejects_other_snapshot() {
    let mut root = STATE_ROOT;
    root[3] = root[3] ^ 1;
    reuse_with(root, ACCOUNT[0], VALUE_LOW);
}

#[test(should_fail_with = "Account was not verified for this state root")]
unconstrained fn rejects_other_account() {
    reuse_with(STATE_ROOT, ACCOUNT[0] + 1, VALUE_LOW);
}

#[test(should_fail_with = "Storage leaf differs from its parent reference")]
unconstrained fn cached_slot_value_still_needs_a_proof() {
    reuse_with(STATE_ROOT, ACCOUNT[0], VALUE_LOW + 1);
}

#[test(should_fail_with = "Account leaf differs from its parent reference")]
unconstrained fn refuses_to_cache_an_unverified_storage_root() {
    let env = TestEnvironment::new();
    env.public_context(|context| {
        let cache: AccountRoots<PublicContext> = Map::new(
            context,
            PublicProofReuse::storage_layout().verified_accounts.slot,
        );
        let mut account = ACCOUNT;
        account[4] += 1;
        record_verified_account(cache, STATE_ROOT, account, account_nodes(), ACCOUNT_COUNT);
    });
}
