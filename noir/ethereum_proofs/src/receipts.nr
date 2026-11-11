//! Receipt inclusion under a caller-authenticated receiptsRoot.
//! Keys are RLP(u64 transaction index), NOT keccak(index).
//! Legacy receipts (including pre-Byzantium roots) and typed receipts 1..4.
pub use crate::proof::EncodedNode;
pub use crate::rlp;
use crate::{keccak::keccak256_limbs, proof::{new_cursor, verify_hashed_path_section}};
use crate::rlp::{Item, read_item, read_uint64};

/// All offsets refer to the supplied authenticated leaf buffer. This is a view,
/// not an independently authenticated witness. Obtain it from verify_receipt.
pub struct ReceiptView {
    pub receipt_type: u8,
    /// True for a pre-Byzantium receipt, whose first field is a 32-byte post-state
    /// root instead of a status code. Such a receipt records no success or failure.
    pub has_post_state: bool,
    /// The EIP-658 status code. Meaningful only when has_post_state is false:
    /// it is also false for every pre-Byzantium receipt, successful or not.
    /// Use succeeded() or failed() instead of reading it alone.
    pub status: bool,
    /// Zero unless has_post_state.
    pub post_state: [u8; 32],
    pub cumulative_gas_used: u64,
    pub logs_start: u32,
    pub logs_end: u32,
    pub log_count: u32,
}

impl ReceiptView {
    /// A post-Byzantium receipt with status 1.
    pub fn succeeded(self) -> bool {
        !self.has_post_state & self.status
    }

    /// A post-Byzantium receipt with status 0. A pre-Byzantium receipt is neither.
    pub fn failed(self) -> bool {
        !self.has_post_state & !self.status
    }
}

/// Canonical index encoding padded only for reuse of the bounded MPT traversal.
pub fn transaction_key(index: u64) -> ([u8; 32], u32) {
    let mut key = [0; 32];
    let mut width: u32 = 0;
    for i in 0..8 {
        if (index >> (8 * i) as u64) != 0 {
            width = i + 1;
        }
    }
    let length = if index < 128 { 1 } else { width + 1 };
    if index == 0 {
        key[0] = 0x80;
    } else if index < 128 {
        key[0] = index as u8;
    } else {
        key[0] = 0x80 + width as u8;
        for i in 0..8 {
            if i < width {
                key[i + 1] = (index >> (8 * (width - 1 - i)) as u64) as u8;
            }
        }
    }
    (key, length)
}

fn nibble(key: [u8; 32], index: u32) -> u8 {
    let byte = key[index / 2];
    if index % 2 == 0 {
        byte >> 4
    } else {
        byte & 15
    }
}

/// Check the schema of one log item (address, at most four 32-byte topics, data)
/// and return its address, topics-list and data items. Schema only: this proves
/// no inclusion. Pass only an item of a leaf authenticated by verify_receipt.
pub fn parse_log<let N: u32>(bytes: [u8; N], log: Item) -> (Item, Item, Item) {
    assert(log.is_list, "Malformed log");
    let address = read_item(bytes, log.payload, log.end);
    assert(!address.is_list, "Malformed log");
    assert_eq(address.length, 20, "Malformed log");
    let topics = read_item(bytes, address.end, log.end);
    assert(topics.is_list, "Malformed log");
    let mut pos = topics.payload;
    for _ in 0..4 {
        if pos < topics.end {
            let topic = read_item(bytes, pos, topics.end);
            assert(!topic.is_list, "Malformed log");
            assert_eq(topic.length, 32, "Malformed log");
            pos = topic.end;
        }
    }
    assert_eq(pos, topics.end, "More than four topics");
    let data = read_item(bytes, topics.end, log.end);
    assert(!data.is_list, "Malformed log");
    assert_eq(data.end, log.end, "Malformed log");
    (address, topics, data)
}

/// Parse an already authenticated receipt value. No inclusion is implied by this
/// helper on its own. MAX_LOGS is an explicit capacity, not an Ethereum limit.
pub fn parse_receipt<let N: u32, let MAX_LOGS: u32>(
    bytes: [u8; N],
    offset: u32,
    end: u32,
) -> ReceiptView {
    assert(end <= N, "Malformed receipt");
    assert(offset < end, "Malformed receipt");
    let first = bytes[offset];
    let mut receipt_type: u8 = 0;
    let mut start = offset;
    if first < 0x80 {
        assert((first >= 1) & (first <= 4), "Unsupported typed receipt schema");
        receipt_type = first;
        start += 1;
    }
    let receipt = read_item(bytes, start, end);
    assert(receipt.is_list, "Malformed receipt");
    assert_eq(receipt.end, end, "Malformed receipt");
    let outcome = read_item(bytes, receipt.payload, receipt.end);
    assert(!outcome.is_list, "Malformed receipt");
    let has_post_state = outcome.length == 32;
    let mut post_state = [0; 32];
    let mut status = false;
    if has_post_state {
        assert_eq(receipt_type, 0, "Typed receipts require status");
        for i in 0..32 {
            post_state[i] = bytes[outcome.payload + i];
        }
    } else {
        let code = read_uint64(bytes, outcome);
        assert(code <= 1, "Malformed receipt");
        status = code == 1;
    }
    let gas = read_item(bytes, outcome.end, receipt.end);
    let cumulative_gas_used = read_uint64(bytes, gas);
    let bloom = read_item(bytes, gas.end, receipt.end);
    assert(!bloom.is_list, "Malformed receipt");
    assert_eq(bloom.length, 256, "Malformed receipt");
    let logs = read_item(bytes, bloom.end, receipt.end);
    assert(logs.is_list, "Malformed receipt");
    assert_eq(logs.end, receipt.end, "Malformed receipt");
    let mut pos = logs.payload;
    let mut log_count = 0;
    for _ in 0..MAX_LOGS {
        if pos < logs.end {
            let log = read_item(bytes, pos, logs.end);
            let _ = parse_log(bytes, log);
            pos = log.end;
            log_count += 1;
        }
    }
    assert_eq(pos, logs.end, "Log capacity exceeded");
    ReceiptView {
        receipt_type,
        has_post_state,
        status,
        post_state,
        cumulative_gas_used,
        logs_start: logs.payload,
        logs_end: logs.end,
        log_count,
    }
}

/// Authenticate the exact receipt at transaction_index, then validate its schema.
/// D/B bound internal nodes; N bounds the full final leaf including receipt bytes.
/// Receipt values always exceed 32 bytes (bloom alone is 256), so every child
/// reference in a canonical receipt trie is hashed. RLP integer keys are prefix-free.
pub fn verify_receipt<let D: u32, let B: u32, let N: u32, let MAX_LOGS: u32>(
    receipts_root: [u64; 4],
    transaction_index: u64,
    nodes: [EncodedNode<B>; D],
    count: u32,
    leaf: [u8; N],
    leaf_length: u32,
) -> ReceiptView {
    let (key, key_length) = transaction_key(transaction_index);
    let cursor = verify_hashed_path_section(nodes, count, new_cursor(receipts_root), key);
    assert_eq(cursor.reference_length, 32, "Expected child hash");
    assert(cursor.nibble <= key_length * 2, "Receipt path is longer than its key");
    assert(leaf_length <= N, "Receipt leaf length exceeds capacity");
    // Keccak has no_predicates internals: normalize ignored lengths even when
    // this entire verifier is called under a disabled caller condition.
    let hash_length = if leaf_length <= N { leaf_length } else { 0 };
    assert_eq(
        keccak256_limbs(leaf, hash_length),
        cursor.hash,
        "Receipt leaf hash differs from its parent reference",
    );
    let outer = read_item(leaf, 0, leaf_length);
    assert(outer.is_list, "Receipt leaf does not match the transaction index");
    assert_eq(outer.end, leaf_length, "Receipt leaf does not match the transaction index");
    let path = read_item(leaf, outer.payload, outer.end);
    assert(!path.is_list, "Receipt leaf does not match the transaction index");
    let remaining = key_length * 2 - cursor.nibble;
    let odd = remaining % 2;
    assert_eq(path.length, 1 + remaining / 2, "Receipt leaf does not match the transaction index");
    let flag = 0x20 + 0x10 * odd as u8;
    assert_eq(
        leaf[path.payload],
        flag
            + if odd == 1 {
                nibble(key, cursor.nibble)
            } else {
                0
            },
        "Receipt leaf does not match the transaction index",
    );
    for i in 0..18 {
        if i < remaining {
            let encoded = i + 2 - odd;
            let byte = leaf[path.payload + encoded / 2];
            let actual = if encoded % 2 == 0 {
                byte >> 4
            } else {
                byte & 15
            };
            assert_eq(
                actual,
                nibble(key, cursor.nibble + i),
                "Receipt leaf does not match the transaction index",
            );
        }
    }
    let value = read_item(leaf, path.end, outer.end);
    assert(!value.is_list, "Receipt leaf does not match the transaction index");
    assert_eq(value.end, outer.end, "Receipt leaf does not match the transaction index");
    parse_receipt::<N, MAX_LOGS>(leaf, value.payload, value.end)
}

mod tests {
    use super::transaction_key;

    // Known answers from the RLP specification: the trie key is RLP(index).
    #[test]
    fn transaction_key_is_the_rlp_of_the_index() {
        let (key, length) = transaction_key(0);
        assert_eq((key[0], key[1], length), (0x80, 0, 1));
        let (key, length) = transaction_key(127);
        assert_eq((key[0], key[1], length), (0x7f, 0, 1));
        let (key, length) = transaction_key(128);
        assert_eq((key[0], key[1], key[2], length), (0x81, 0x80, 0, 2));
        let (key, length) = transaction_key(256);
        assert_eq((key[0], key[1], key[2], key[3], length), (0x82, 0x01, 0x00, 0, 3));
        let (key, length) = transaction_key(0xffffffffffffffff);
        assert_eq((key[0], length), (0x88, 9));
        for i in 0..8 {
            assert_eq(key[1 + i], 0xff);
        }
        assert_eq(key[9], 0);
    }
}
