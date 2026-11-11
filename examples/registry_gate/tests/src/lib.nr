//! Tests of RegistryGate's logic, run in TXE test contexts without deploying the contract: `apply_claim` is the body
//! of `claim` and `admit_member` the body of `admit`. Entries come from `fixture.nr`;
//! `ethereum_proofs::proof::verify_l1_storage` proves the registry account and the mapping entry under the pinned
//! root. Negative cases use other entries or mutate a valid one.
mod fixture;

use aztec::{
    context::PublicContext,
    protocol::{address::AztecAddress, traits::FromField},
    state_vars::{Map, PublicMutable, StateVariable},
    test::helpers::test_environment::TestEnvironment,
};
use fixture::{
    BENEFICIARY_A, BENEFICIARY_B, CHAIN_ID, entry_a, entry_a_later, entry_a_other_registry, entry_a_slot_1, entry_b,
    LATER_STATE_ROOT, MAPPING_SLOT, REGISTRY, STATE_ROOT, VALUE_A, VALUE_A_LATER, VALUE_B,
};
use registry_gate_contract::{admit_member, apply_claim, RegistryEntry, RegistryGate, Terms};

/// Terms that pin the fixture state root and registry, and admit values of at least 1.
fn terms() -> Terms {
    Terms { chain: CHAIN_ID, state_root: STATE_ROOT, registry: REGISTRY, mapping_slot: MAPPING_SLOT, min_value: 1 }
}

/// Runs `claim`'s private part for a contract deployed with `deployed`, called with `t` and `entry`; returns the
/// beneficiary and value it admits.
unconstrained fn claim(env: TestEnvironment, deployed: Terms, t: Terms, entry: RegistryEntry) -> (AztecAddress, Field) {
    env.private_context(|context| apply_claim(context, deployed.hash(), t, entry))
}

#[test]
unconstrained fn listed_beneficiary_admitted() {
    let env = TestEnvironment::new();
    let (beneficiary, value) = claim(env, terms(), terms(), entry_a());
    assert_eq(beneficiary, AztecAddress::from_field(BENEFICIARY_A));
    assert_eq(value, VALUE_A);
    env.public_context(|context| {
        let members: Map<AztecAddress, PublicMutable<Field, PublicContext>, PublicContext> =
            Map::new(context, RegistryGate::storage_layout().members.slot);
        assert_eq(members.at(beneficiary).read(), 0);
        admit_member(members, beneficiary, value);
        assert_eq(members.at(beneficiary).read(), VALUE_A);
        assert_eq(members.at(AztecAddress::from_field(BENEFICIARY_B)).read(), 0);
    });
}

#[test]
unconstrained fn other_beneficiary_admitted() {
    let env = TestEnvironment::new();
    let _ = claim(env, terms(), terms(), entry_a());
    let (beneficiary, value) = claim(env, terms(), terms(), entry_b());
    assert_eq(beneficiary, AztecAddress::from_field(BENEFICIARY_B));
    assert_eq(value, VALUE_B);
}

#[test]
unconstrained fn later_root_admitted_by_its_own_terms() {
    let mut t = terms();
    t.state_root = LATER_STATE_ROOT;
    let (beneficiary, value) = claim(TestEnvironment::new(), t, t, entry_a_later());
    assert_eq(beneficiary, AztecAddress::from_field(BENEFICIARY_A));
    assert_eq(value, VALUE_A_LATER);
}

#[test(should_fail_with = "already present")]
unconstrained fn second_admission_rejected() {
    let env = TestEnvironment::new();
    let _ = claim(env, terms(), terms(), entry_a());
    let _ = claim(env, terms(), terms(), entry_a());
}

#[test(should_fail_with = "Not the pinned state root")]
unconstrained fn later_root_rejected_by_earlier_terms() {
    let env = TestEnvironment::new();
    let _ = claim(env, terms(), terms(), entry_a_later());
}

#[test(should_fail_with = "Not the trusted registry")]
unconstrained fn other_registry_rejected() {
    let env = TestEnvironment::new();
    let _ = claim(env, terms(), terms(), entry_a_other_registry());
}

#[test(should_fail_with = "Not the trusted registry")]
unconstrained fn other_mapping_slot_rejected() {
    let env = TestEnvironment::new();
    let _ = claim(env, terms(), terms(), entry_a_slot_1());
}

#[test(should_fail_with = "Not the pinned state root")]
unconstrained fn other_chain_rejected() {
    let env = TestEnvironment::new();
    let mut entry = entry_a();
    entry.chain = 10;
    let _ = claim(env, terms(), terms(), entry);
}

#[test(should_fail_with = "Registry value below the minimum")]
unconstrained fn value_below_the_minimum_rejected() {
    let mut t = terms();
    t.min_value = 3;
    let env = TestEnvironment::new();
    let _ = claim(env, t, t, entry_a());
}

#[test(should_fail_with = "Registry value exceeds 248 bits")]
unconstrained fn value_above_248_bits_rejected() {
    let env = TestEnvironment::new();
    let mut entry = entry_a();
    entry.value_length = 32;
    let _ = claim(env, terms(), terms(), entry);
}

#[test(should_fail_with = "Node hash differs from its parent reference")]
unconstrained fn other_beneficiary_entry_rejected() {
    // B's proof does not open A's mapping entry.
    let env = TestEnvironment::new();
    let mut entry = entry_b();
    entry.beneficiary = AztecAddress::from_field(BENEFICIARY_A);
    let _ = claim(env, terms(), terms(), entry);
}

#[test(should_fail_with = "Node hash differs from its parent reference")]
unconstrained fn tampered_value_rejected() {
    let env = TestEnvironment::new();
    let mut entry = entry_a();
    entry.value[0] = 7;
    let _ = claim(env, terms(), terms(), entry);
}

#[test(should_fail_with = "Account leaf hash differs from its parent reference")]
unconstrained fn tampered_storage_root_rejected() {
    let env = TestEnvironment::new();
    let mut entry = entry_a();
    entry.account.storage_hash[0] += 1;
    let _ = claim(env, terms(), terms(), entry);
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn other_terms_rejected() {
    // A caller cannot loosen the deployed terms, here the minimum value.
    let mut t = terms();
    t.min_value = 3;
    let _ = claim(TestEnvironment::new(), t, terms(), entry_a());
}
