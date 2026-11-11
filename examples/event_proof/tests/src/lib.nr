//! Tests of EventProof's logic, run in TXE test contexts without deploying the contract: `apply_event` is the body of
//! `on_event` and `count_event` the body of `record_event`. Logs come from `fixture.nr`;
//! `ethereum_proofs::events::verify_event` proves the receipt and the log under the pinned receipts root. Negative
//! cases mutate the valid log.
mod fixture;

use aztec::{
    protocol::constants::MAX_TX_LIFETIME,
    state_vars::{PublicMutable, StateVariable},
    test::helpers::test_environment::TestEnvironment,
};
use event_proof_contract::{apply_event, count_event, EthereumLog, EventProof, freshness_deadline, Terms, verify_log};
use fixture::{anonymous_log, BLOCK_TIME, historical_log, NOW, transfer_log};

/// Terms that pin the fixture block, accept logs of the transfer log's emitter and first topic, and allow an hour.
fn terms() -> Terms {
    let log = transfer_log();
    Terms { block: log.block, emitter: log.emitter, topic0: log.topics[0], max_age: 3600 }
}

/// A test environment whose next context is anchored at a block mined at `timestamp`.
unconstrained fn setup(timestamp: u64) -> TestEnvironment {
    let env = TestEnvironment::new();
    env.mine_block_at(timestamp);
    env
}

/// Runs `on_event`'s private part for a contract deployed with `deployed`, called with `t` and `log`.
unconstrained fn submit(env: TestEnvironment, deployed: Terms, t: Terms, log: EthereumLog) {
    env.private_context(|context| apply_event(context, deployed.hash(), t, log));
}

/// Runs `on_event`'s private part for a contract deployed with `t` and returns the expiration timestamp that the
/// transaction's public inputs carry.
unconstrained fn expiration(env: TestEnvironment, t: Terms, log: EthereumLog) -> u64 {
    env.private_context(|context| {
        apply_event(context, t.hash(), t, log);
        (*context).finish().expiration_timestamp
    })
}

#[test]
unconstrained fn valid_log_applied() {
    submit(setup(NOW), terms(), terms(), transfer_log());
}

#[test]
unconstrained fn accepted_events_are_counted() {
    TestEnvironment::new().public_context(|context| {
        let events = PublicMutable::new(context, EventProof::storage_layout().events.slot);
        assert_eq(events.read(), 0);
        count_event(events);
        assert_eq(events.read(), 1);
        count_event(events);
        assert_eq(events.read(), 2);
    });
}

#[test]
unconstrained fn fresh_at_the_maximum_age() {
    let mut t = terms();
    t.max_age = 60;
    submit(setup(BLOCK_TIME + 60), t, t, transfer_log());
}

#[test]
unconstrained fn inclusion_limited_by_freshness() {
    // Built two minutes after the block, the transaction expires when the log is an hour old, before the protocol's
    // lifetime from its anchor block ends.
    assert(BLOCK_TIME + 3600 < NOW + MAX_TX_LIFETIME);
    assert_eq(expiration(setup(NOW), terms(), transfer_log()), BLOCK_TIME + 3600);
}

#[test]
unconstrained fn inclusion_ends_at_the_anchor_time_at_the_maximum_age() {
    let mut t = terms();
    t.max_age = 60;
    assert_eq(expiration(setup(BLOCK_TIME + 60), t, transfer_log()), BLOCK_TIME + 60);
}

#[test]
unconstrained fn any_age_leaves_the_protocol_lifetime() {
    // The deadline saturates at the largest timestamp, so the protocol's lifetime is the tighter limit.
    let mut t = terms();
    t.max_age = 0xffffffffffffffff;
    assert_eq(freshness_deadline(BLOCK_TIME, NOW, t.max_age), 0xffffffffffffffff);
    assert_eq(expiration(setup(NOW), t, transfer_log()), NOW + MAX_TX_LIFETIME);
}

#[test]
unconstrained fn next_log_is_another_event() {
    // Log 0 of the same transaction has its own event id (log index), so it does not collide with log 1.
    assert(verify_log(transfer_log()) != verify_log(anonymous_log()));
}

#[test(should_fail_with = "Not the pinned block")]
unconstrained fn other_chain_rejected() {
    // A prover cannot relabel the log as another chain's.
    let env = setup(NOW);
    let mut log = transfer_log();
    log.block.chain_id = 10;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Not the pinned block")]
unconstrained fn other_block_number_rejected() {
    // Another block record with the same root would change the event id.
    let env = setup(NOW);
    let mut log = transfer_log();
    log.block.number += 1;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Not the pinned block")]
unconstrained fn changed_block_time_rejected() {
    let env = setup(NOW);
    let mut log = transfer_log();
    log.block.timestamp += 1000;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Wrong emitter")]
unconstrained fn other_emitter_terms_rejected() {
    let mut t = terms();
    t.emitter[19] ^= 1;
    let env = setup(NOW);
    submit(env, t, t, transfer_log());
}

#[test(should_fail_with = "Wrong event signature")]
unconstrained fn other_signature_terms_rejected() {
    let mut t = terms();
    t.topic0[0] ^= 1;
    let env = setup(NOW);
    submit(env, t, t, transfer_log());
}

#[test(should_fail_with = "Log emitter differs")]
unconstrained fn changed_emitter_rejected() {
    // The terms accept the changed emitter, so the proof itself must reject it.
    let mut log = transfer_log();
    log.emitter[0] ^= 1;
    let mut t = terms();
    t.emitter = log.emitter;
    let env = setup(NOW);
    submit(env, t, t, log);
}

#[test(should_fail_with = "Log topic differs")]
unconstrained fn changed_topic_rejected() {
    let env = setup(NOW);
    let mut log = transfer_log();
    log.topics[2][0] ^= 1;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Log data differs")]
unconstrained fn changed_data_rejected() {
    let env = setup(NOW);
    let mut log = transfer_log();
    log.data[0] ^= 1;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Log emitter differs")]
unconstrained fn wrong_log_index_rejected() {
    // Log 0 has another emitter and no topics.
    let env = setup(NOW);
    let mut log = transfer_log();
    log.log_index = 0;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Receipt leaf hash differs from its parent reference")]
unconstrained fn wrong_transaction_index_rejected() {
    // The proof path is for transaction 1.
    let env = setup(NOW);
    let mut log = transfer_log();
    log.transaction_index = 2;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Receipt leaf hash differs from its parent reference")]
unconstrained fn changed_receipt_rejected() {
    let env = setup(NOW);
    let mut log = transfer_log();
    log.leaf[300] ^= 1;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Nonzero unused topic")]
unconstrained fn unused_topic_slot_rejected() {
    // Claiming three topics leaves the fourth, which is not zero, unused.
    let env = setup(NOW);
    let mut log = transfer_log();
    log.topic_count = 3;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Nonzero data padding")]
unconstrained fn data_past_length_rejected() {
    let env = setup(NOW);
    let mut log = transfer_log();
    log.data[100] = 1;
    submit(env, terms(), terms(), log);
}

#[test(should_fail_with = "Transaction did not succeed")]
unconstrained fn historical_receipt_rejected() {
    // A pre-Byzantium receipt has a post-state root and no status.
    let _ = verify_log(historical_log());
}

#[test(should_fail_with = "Event too old")]
unconstrained fn stale_rejected() {
    let mut t = terms();
    t.max_age = 60;
    let env = setup(BLOCK_TIME + 61);
    submit(env, t, t, transfer_log());
}

#[test(should_fail_with = "Block after the anchor block")]
unconstrained fn future_block_rejected() {
    let env = setup(BLOCK_TIME - 1);
    submit(env, terms(), terms(), transfer_log());
}

#[test(should_fail_with = "already present")]
unconstrained fn second_submission_rejected() {
    let env = setup(NOW);
    submit(env, terms(), terms(), transfer_log());
    submit(env, terms(), terms(), transfer_log());
}

#[test(should_fail_with = "Wrong terms")]
unconstrained fn other_terms_rejected() {
    // A caller cannot loosen the deployed terms, here the freshness ceiling.
    let env = setup(NOW);
    let mut t = terms();
    t.max_age = 0xffffffffffffffff;
    submit(env, terms(), t, transfer_log());
}
