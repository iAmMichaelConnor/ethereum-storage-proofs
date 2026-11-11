//! Exact event/log inclusion inside an authenticated Ethereum receipt.
//! log_index is receipt-local; JSON-RPC block-global logIndex is not this value.
use crate::receipts::{EncodedNode, parse_log, ReceiptView, rlp::read_item, verify_receipt};

/// The expected log. Canonical form, enforced by verify_event: topics at index
/// topic_count and above are zero, and data bytes at data_length and above are zero.
/// A consumer that relies on topic j must also pin topic_count > j.
pub struct Event<let DATA: u32> {
    pub emitter: [u8; 20],
    pub topics: [[u8; 32]; 4],
    pub topic_count: u32,
    pub data: [u8; DATA],
    pub data_length: u32,
}

pub fn verify_event<let D: u32, let B: u32, let N: u32, let MAX_LOGS: u32, let DATA: u32>(
    receipts_root: [u64; 4],
    transaction_index: u64,
    nodes: [EncodedNode<B>; D],
    count: u32,
    leaf: [u8; N],
    leaf_length: u32,
    log_index: u32,
    expected: Event<DATA>,
) -> ReceiptView {
    assert(expected.topic_count <= 4, "More than four topics");
    assert(expected.data_length <= DATA, "Event data length exceeds capacity");
    // Reject, rather than ignore, values in unused slots: a consumer that pins
    // such a value must not see it accepted for a log that does not contain it.
    for j in 0..4 {
        if j >= expected.topic_count {
            for k in 0..32 {
                assert_eq(expected.topics[j][k], 0, "Nonzero unused topic");
            }
        }
    }
    for j in 0..DATA {
        if j >= expected.data_length {
            assert_eq(expected.data[j], 0, "Nonzero data padding");
        }
    }
    let view = verify_receipt::<D, B, N, MAX_LOGS>(
        receipts_root,
        transaction_index,
        nodes,
        count,
        leaf,
        leaf_length,
    );
    assert(log_index < view.log_count, "Log index exceeds the receipt's log count");
    let mut pos = view.logs_start;
    for i in 0..MAX_LOGS {
        if i < view.log_count {
            let log = read_item(leaf, pos, view.logs_end);
            if i == log_index {
                let (address, topics, data) = parse_log(leaf, log);
                for j in 0..20 {
                    assert_eq(
                        leaf[address.payload + j],
                        expected.emitter[j],
                        "Log emitter differs",
                    );
                }
                let mut topic_pos = topics.payload;
                for j in 0..4 {
                    if j < expected.topic_count {
                        let topic = read_item(leaf, topic_pos, topics.end);
                        assert(!topic.is_list, "Malformed log");
                        assert_eq(topic.length, 32, "Malformed log");
                        for k in 0..32 {
                            assert_eq(
                                leaf[topic.payload + k],
                                expected.topics[j][k],
                                "Log topic differs",
                            );
                        }
                        topic_pos = topic.end;
                    }
                }
                assert_eq(topic_pos, topics.end, "Log topic count differs");
                assert_eq(data.length, expected.data_length, "Log data length differs");
                for j in 0..DATA {
                    if j < expected.data_length {
                        assert_eq(leaf[data.payload + j], expected.data[j], "Log data differs");
                    }
                }
            }
            pos = log.end;
        }
    }
    view
}
