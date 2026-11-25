//! Tests of PublicProofs' logic, run in TXE test contexts without deploying the contract: `trusted_root` and
//! `prove_slot_in_public` are the body of `prove_slot`, `prove_storage_in_private` the private part of
//! `prove_slot_privately` and `prove_account_in_public` the body of `check_account`. The proof is a saved mainnet
//! USDT balance slot from `fixture.nr`.
pub mod fixture;

use aztec::{
    context::PublicContext,
    state_vars::{Map, PublicMutable, StateVariable},
    test::helpers::test_environment::TestEnvironment,
};
use fixture::{
    ACCOUNT, ACCOUNT_COUNT, account_nodes, BLOCK_NUMBER, raw_storage_nodes, SLOT_KEY, STATE_ROOT, STORAGE_COUNT,
    storage_nodes, STORAGE_ROOT, VALUE, VALUE_HIGH, VALUE_LENGTH, VALUE_LOW,
};
use public_proofs_contract::{
    prove_account_in_public, prove_slot_in_public, prove_storage_in_private, PublicProofs, StateRoot, trusted_root,
};

/// The root recorded for `block_number` after recording `root` for the fixture block.
unconstrained fn recorded_root(root: [u64; 4], block_number: Field) -> [u64; 4] {
    let env = TestEnvironment::new();
    env.public_context(|context| {
        let roots: Map<Field, PublicMutable<StateRoot, PublicContext>, PublicContext> =
            Map::new(context, PublicProofs::storage_layout().roots.slot);
        roots.at(BLOCK_NUMBER).write(StateRoot { lanes: root });
        trusted_root(roots, block_number)
    })
}

#[test]
unconstrained fn slot_proven_in_public() {
    let root = recorded_root(STATE_ROOT, BLOCK_NUMBER);
    prove_slot_in_public(
        root,
        ACCOUNT,
        account_nodes(),
        ACCOUNT_COUNT,
        SLOT_KEY,
        VALUE_HIGH,
        VALUE_LOW,
        storage_nodes(),
        STORAGE_COUNT,
    );
}

#[test(should_fail_with = "No state root for this block")]
unconstrained fn unrecorded_block_rejected() {
    let _ = recorded_root(STATE_ROOT, BLOCK_NUMBER + 1);
}

#[test(should_fail_with = "Storage leaf differs from its parent reference")]
unconstrained fn wrong_value_rejected_in_public() {
    prove_slot_in_public(
        STATE_ROOT,
        ACCOUNT,
        account_nodes(),
        ACCOUNT_COUNT,
        SLOT_KEY,
        VALUE_HIGH,
        VALUE_LOW + 1,
        storage_nodes(),
        STORAGE_COUNT,
    );
}

// The private storage proof and the public account proof of `prove_slot_privately`, each run as the contract runs
// them. The private part runs unconstrained here; its constraints are those of `ethereum_proofs`.
#[test]
unconstrained fn slot_proven_privately_and_account_in_public() {
    prove_storage_in_private(
        STORAGE_ROOT,
        SLOT_KEY,
        VALUE,
        VALUE_LENGTH,
        raw_storage_nodes(),
        STORAGE_COUNT,
    );
    prove_account_in_public(
        STATE_ROOT,
        ACCOUNT,
        account_nodes(),
        ACCOUNT_COUNT,
        STORAGE_ROOT,
    );
}

#[test(should_fail_with = "Account has a different storage root")]
unconstrained fn private_root_must_be_the_accounts() {
    let mut other = STORAGE_ROOT;
    other[0] = other[0] ^ 1;
    prove_account_in_public(STATE_ROOT, ACCOUNT, account_nodes(), ACCOUNT_COUNT, other);
}
