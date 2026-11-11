//! Receipt-summary and exact-event recursive proofs. Roots and keys are caller policy.
use super::{halves, pack, RecursiveProof, verify_claim};
use poseidon::poseidon2::Poseidon2;

pub struct ReceiptClaim {
    pub receipts_root: [u64; 4],
    pub transaction_index: u64,
    pub receipt_type: u8,
    /// True for a pre-Byzantium receipt (32-byte post-state root, no status code).
    pub has_post_state: bool,
    /// Meaningful only when has_post_state is false. It is also false for every
    /// pre-Byzantium receipt, so a consumer that acts on success or failure must
    /// pin has_post_state = false as well.
    pub status: bool,
    pub post_state: [u8; 32],
    pub cumulative_gas_used: u64,
}

pub struct EventClaim {
    pub receipts_root: [u64; 4],
    pub transaction_index: u64,
    pub log_index: u32,
    pub emitter: [u8; 20],
    /// Topics at index topic_count and above must be zero; event_statement rejects
    /// any other value. A consumer that relies on topic j must pin topic_count > j.
    pub topics: [[u8; 32]; 4],
    pub topic_count: u32,
    /// Keccak256 of the exact data bytes, in four little-endian lanes.
    pub data_hash: [u64; 4],
    pub data_length: u32,
}

pub fn receipt_statement(claim: ReceiptClaim) -> Field {
    let state = halves(claim.post_state);
    Poseidon2::hash(
        [
            0x524543454950545f5631, // RECEIPT_V1
            claim.receipts_root[0] as Field,
            claim.receipts_root[1] as Field,
            claim.receipts_root[2] as Field,
            claim.receipts_root[3] as Field,
            claim.transaction_index as Field,
            claim.receipt_type as Field,
            claim.has_post_state as Field,
            claim.status as Field,
            state[0],
            state[1],
            claim.cumulative_gas_used as Field,
        ],
        12,
    )
}

pub fn event_statement(claim: EventClaim) -> Field {
    assert(claim.topic_count <= 4, "More than four topics");
    let mut topics = [0; 8];
    for i in 0..4 {
        if i < claim.topic_count {
            let pair = halves(claim.topics[i]);
            topics[2 * i] = pair[0];
            topics[2 * i + 1] = pair[1];
        } else {
            // One statement per claim: reject, rather than ignore, unused topic values.
            for k in 0..32 {
                assert_eq(claim.topics[i][k], 0, "Nonzero unused topic");
            }
        }
    }
    Poseidon2::hash(
        [
            0x4556454e545f5631, // EVENT_V1; distinct from receipt/storage claims
            claim.receipts_root[0] as Field,
            claim.receipts_root[1] as Field,
            claim.receipts_root[2] as Field,
            claim.receipts_root[3] as Field,
            claim.transaction_index as Field,
            claim.log_index as Field,
            pack(claim.emitter),
            claim.topic_count as Field,
            topics[0],
            topics[1],
            topics[2],
            topics[3],
            topics[4],
            topics[5],
            topics[6],
            topics[7],
            claim.data_hash[0] as Field,
            claim.data_hash[1] as Field,
            claim.data_hash[2] as Field,
            claim.data_hash[3] as Field,
            claim.data_length as Field,
        ],
        22,
    )
}

pub fn verify_receipt_recursive_proof(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: ReceiptClaim,
) {
    verify_claim(
        recursive_proof,
        authorized_vk_hash,
        expected,
        receipt_statement,
    );
}

pub fn verify_event_recursive_proof(
    recursive_proof: RecursiveProof,
    authorized_vk_hash: Field,
    expected: EventClaim,
) {
    verify_claim(
        recursive_proof,
        authorized_vk_hash,
        expected,
        event_statement,
    );
}

#[test]
fn test_receipt_statement_binds_every_leaf() {
    let claim = ReceiptClaim {
        receipts_root: super::sample_lanes(15),
        transaction_index: 0x0102030405060708,
        receipt_type: 0x02,
        has_post_state: true,
        status: false,
        post_state: super::sample_bytes(16),
        cumulative_gas_used: 0x0000000001c9c380,
    };
    let digest = receipt_statement(claim);
    super::assert_u64s_bound(
        digest,
        claim.receipts_root,
        |receipts_root| {
            let mut changed = claim;
            changed.receipts_root = receipts_root;
            receipt_statement(changed)
        },
    );
    super::assert_u64s_bound(
        digest,
        [claim.transaction_index],
        |transaction_index| {
            let mut changed = claim;
            changed.transaction_index = transaction_index[0];
            receipt_statement(changed)
        },
    );
    super::assert_u8s_bound(
        digest,
        [claim.receipt_type],
        |receipt_type| {
            let mut changed = claim;
            changed.receipt_type = receipt_type[0];
            receipt_statement(changed)
        },
    );
    let mut changed = claim;
    changed.has_post_state = !claim.has_post_state;
    assert(digest != receipt_statement(changed));
    changed = claim;
    changed.status = !claim.status;
    assert(digest != receipt_statement(changed));
    super::assert_u8s_bound(
        digest,
        claim.post_state,
        |post_state| {
            let mut changed = claim;
            changed.post_state = post_state;
            receipt_statement(changed)
        },
    );
    super::assert_u64s_bound(
        digest,
        [claim.cumulative_gas_used],
        |cumulative_gas_used| {
            let mut changed = claim;
            changed.cumulative_gas_used = cumulative_gas_used[0];
            receipt_statement(changed)
        },
    );
    // post_state stays bound when has_post_state is false; the statement does not gate it.
    let mut status_only = claim;
    status_only.has_post_state = false;
    let status_digest = receipt_statement(status_only);
    super::assert_u8s_bound(
        status_digest,
        status_only.post_state,
        |post_state| {
            let mut changed = status_only;
            changed.post_state = post_state;
            receipt_statement(changed)
        },
    );
}

unconstrained fn witness<T>(x: T) -> T {
    x
}

fn sample_event_claim(topic_count: u32) -> EventClaim {
    // Canonical claims: topics at index topic_count and above are zero.
    let mut topics = [[0; 32]; 4];
    for t in 0..4 {
        if t < topic_count {
            topics[t] = super::sample_bytes(60 + t);
        }
    }
    EventClaim {
        receipts_root: super::sample_lanes(17),
        transaction_index: 0x8000000000000003,
        log_index: 0x00000105,
        emitter: super::sample_bytes(18),
        topics,
        topic_count,
        data_hash: super::sample_lanes(19),
        data_length: 0x80000044,
    }
}

#[test]
fn test_event_statement_binds_every_leaf() {
    // All four topics are in use, so every topic byte is bound.
    let claim = sample_event_claim(4);
    let digest = event_statement(claim);
    super::assert_u64s_bound(
        digest,
        claim.receipts_root,
        |receipts_root| {
            let mut changed = claim;
            changed.receipts_root = receipts_root;
            event_statement(changed)
        },
    );
    super::assert_u64s_bound(
        digest,
        [claim.transaction_index],
        |transaction_index| {
            let mut changed = claim;
            changed.transaction_index = transaction_index[0];
            event_statement(changed)
        },
    );
    super::assert_u32s_bound(
        digest,
        [claim.log_index],
        |log_index| {
            let mut changed = claim;
            changed.log_index = log_index[0];
            event_statement(changed)
        },
    );
    super::assert_u8s_bound(
        digest,
        claim.emitter,
        |emitter| {
            let mut changed = claim;
            changed.emitter = emitter;
            event_statement(changed)
        },
    );
    for t in 0..4 {
        super::assert_u8s_bound(
            digest,
            claim.topics[t],
            |topic| {
                let mut changed = claim;
                changed.topics[t] = topic;
                event_statement(changed)
            },
        );
    }
    super::assert_u64s_bound(
        digest,
        claim.data_hash,
        |data_hash| {
            let mut changed = claim;
            changed.data_hash = data_hash;
            event_statement(changed)
        },
    );
    super::assert_u32s_bound(
        digest,
        [claim.data_length],
        |data_length| {
            let mut changed = claim;
            changed.data_length = data_length[0];
            event_statement(changed)
        },
    );
    // topic_count accepts only 0..=4 (`assert(claim.topic_count <= 4)`), so its bit flips
    // from 4 are rejected (tests below); every accepted count gives a distinct digest.
    let mut by_count = [0; 5];
    for count in 0..5 {
        by_count[count] = event_statement(sample_event_claim(count));
    }
    assert_eq(by_count[4], digest);
    for a in 0..5 {
        for b in 0..5 {
            if a != b {
                assert(by_count[a] != by_count[b]);
            }
        }
    }
}

#[test(should_fail_with = "More than four topics")]
fn test_event_statement_rejects_topic_count_low_bit_flip() {
    let _digest = event_statement(sample_event_claim(4 ^ 0x01));
}

#[test(should_fail_with = "More than four topics")]
fn test_event_statement_rejects_topic_count_high_bit_flip() {
    let _digest = event_statement(sample_event_claim(4 ^ 0x80000000));
}

#[test]
fn test_event_statement_binds_active_topics_with_zero_padding() {
    // Topics below topic_count are bound byte for byte; the zero padding is accepted.
    let claim = sample_event_claim(2);
    let digest = event_statement(claim);
    for t in 0..2 {
        super::assert_u8s_bound(
            digest,
            claim.topics[t],
            |topic| {
                let mut changed = claim;
                changed.topics[t] = topic;
                event_statement(changed)
            },
        );
    }
    assert_eq(claim.topics[2], [0; 32]);
    assert_eq(claim.topics[3], [0; 32]);
}

// If event_statement ignored topics beyond topic_count, a claim with topic_count = 3
// and any topics[3] would have the statement of the real log.
#[test(should_fail_with = "Nonzero unused topic")]
fn test_event_statement_rejects_nonzero_unused_topic() {
    let mut claim = sample_event_claim(3);
    claim.topics[3] = [0x77; 32];
    // Safety: the test witness is checked by the constrained statement below.
    let claim = unsafe { witness(claim) };
    let _ = event_statement(claim);
}

#[test(should_fail_with = "Nonzero unused topic")]
fn test_event_statement_rejects_one_bit_in_unused_topic() {
    let mut claim = sample_event_claim(2);
    claim.topics[2][31] = 1;
    // Safety: the test witness is checked by the constrained statement below.
    let claim = unsafe { witness(claim) };
    let _ = event_statement(claim);
}
