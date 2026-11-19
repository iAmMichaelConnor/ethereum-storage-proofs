//! Packed trie nodes and the path walk.
//!
//! A packed node is a node's RLP bytes, as `eth_getProof` returns them,
//! zero-padded and read as little-endian 64-bit lanes, three per field: field
//! `k` is `lane[3k] + lane[3k + 1] * 2^64 + lane[3k + 2] * 2^128`. 23 fields
//! hold 69 lanes (552 bytes). Keccak absorbs 17 lanes per block, so each block
//! starts at one of three positions within a field; absorbing a block is a
//! fixed sequence of 17 lane XORs for each.
//!
//! The node's length comes from its own RLP list header, so it is covered by
//! the hash. The walk hashes the node, compares the digest with the parent's
//! reference, and only then parses the child it descends into. Whether a node
//! is a branch or an extension follows from its item count (17 or 2), so the
//! prover supplies no node kind.
use crate::NODE_FIELDS;
use crate::sink::Reference;
use std::hash::keccakf1600;

/// 2^-128 in the BN254 scalar field.
global INV_2_128: Field = 0x133100d71fdf35792b16366f4f7684df54ad7e14a329e70f18ee753c76f9dc6f;
/// Keccak-256 rate in bytes: one block, 17 lanes.
global RATE: u32 = 136;
/// Byte capacity of a packed node: four Keccak blocks.
pub(crate) global NODE_CAPACITY: u32 = 544;

/// Split a field into three lanes. Bits at and above 2^192 are dropped.
#[inline_always]
pub(crate) unconstrained fn split3(x: Field) -> (u64, u64, u64) {
    let low = x as u128;
    let high = (x - low as Field) * INV_2_128;
    (low as u64, (low >> 64) as u64, high as u64)
}

/// Lane `index` (0 to 68) of a packed node.
#[inline_always]
unconstrained fn lane(node: [Field; NODE_FIELDS], index: u32) -> u64 {
    let field = node[index / 3];
    let position = index % 3;
    if position == 0 {
        field as u64
    } else if position == 1 {
        ((field as u128) >> 64) as u64
    } else {
        ((field - (field as u128) as Field) * INV_2_128) as u64
    }
}

/// Byte `offset` of a packed node.
#[inline_always]
unconstrained fn byte(node: [Field; NODE_FIELDS], offset: u32) -> u8 {
    (lane(node, offset / 8) >> ((offset % 8) * 8) as u64) as u8
}

/// Lane `index` of a packed node, or zero past its 69 lanes.
#[inline_always]
unconstrained fn lane_or_zero(node: [Field; NODE_FIELDS], index: u32) -> u64 {
    if index < 69 {
        lane(node, index)
    } else {
        0
    }
}

/// The 32 bytes from `offset` as four lanes; bytes past the capacity read as zero.
unconstrained fn lanes_at(node: [Field; NODE_FIELDS], offset: u32) -> [u64; 4] {
    let first = offset / 8;
    let shift = ((offset % 8) * 8) as u64;
    let lane0 = lane(node, first);
    let lane1 = lane_or_zero(node, first + 1);
    let lane2 = lane_or_zero(node, first + 2);
    let lane3 = lane_or_zero(node, first + 3);
    if shift == 0 {
        [lane0, lane1, lane2, lane3]
    } else {
        let lane4 = lane_or_zero(node, first + 4);
        let back = 64 - shift;
        [
            (lane0 >> shift) | (lane1 << back),
            (lane1 >> shift) | (lane2 << back),
            (lane2 >> shift) | (lane3 << back),
            (lane3 >> shift) | (lane4 << back),
        ]
    }
}

/// The 17 lanes of block `block` (0 to 3), which starts at lane 17 * block:
/// field 0 position 0, field 5 position 2, field 11 position 1 or field 17
/// position 0.
#[inline_always]
unconstrained fn block_lanes(
    node: [Field; NODE_FIELDS],
    block: u32,
) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    if block == 0 {
        let (l0, l1, l2) = split3(node[0]);
        let (l3, l4, l5) = split3(node[1]);
        let (l6, l7, l8) = split3(node[2]);
        let (l9, l10, l11) = split3(node[3]);
        let (l12, l13, l14) = split3(node[4]);
        let (l15, l16, _) = split3(node[5]);
        (l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16)
    } else if block == 1 {
        let (_, _, l0) = split3(node[5]);
        let (l1, l2, l3) = split3(node[6]);
        let (l4, l5, l6) = split3(node[7]);
        let (l7, l8, l9) = split3(node[8]);
        let (l10, l11, l12) = split3(node[9]);
        let (l13, l14, l15) = split3(node[10]);
        let (l16, _, _) = split3(node[11]);
        (l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16)
    } else if block == 2 {
        let (_, l0, l1) = split3(node[11]);
        let (l2, l3, l4) = split3(node[12]);
        let (l5, l6, l7) = split3(node[13]);
        let (l8, l9, l10) = split3(node[14]);
        let (l11, l12, l13) = split3(node[15]);
        let (l14, l15, l16) = split3(node[16]);
        (l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16)
    } else {
        let (l0, l1, l2) = split3(node[17]);
        let (l3, l4, l5) = split3(node[18]);
        let (l6, l7, l8) = split3(node[19]);
        let (l9, l10, l11) = split3(node[20]);
        let (l12, l13, l14) = split3(node[21]);
        let (l15, l16, _) = split3(node[22]);
        (l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16)
    }
}

/// XOR block `block` of a packed node into the sponge state.
#[inline_always]
unconstrained fn absorb(state: [u64; 25], node: [Field; NODE_FIELDS], block: u32) -> [u64; 25] {
    let l = block_lanes(node, block);
    [
        state[0] ^ l.0,
        state[1] ^ l.1,
        state[2] ^ l.2,
        state[3] ^ l.3,
        state[4] ^ l.4,
        state[5] ^ l.5,
        state[6] ^ l.6,
        state[7] ^ l.7,
        state[8] ^ l.8,
        state[9] ^ l.9,
        state[10] ^ l.10,
        state[11] ^ l.11,
        state[12] ^ l.12,
        state[13] ^ l.13,
        state[14] ^ l.14,
        state[15] ^ l.15,
        state[16] ^ l.16,
        state[17],
        state[18],
        state[19],
        state[20],
        state[21],
        state[22],
        state[23],
        state[24],
    ]
}

/// The first block into an empty sponge.
#[inline_always]
unconstrained fn first_block(node: [Field; NODE_FIELDS]) -> [u64; 25] {
    let l = block_lanes(node, 0);
    [
        l.0, l.1, l.2, l.3, l.4, l.5, l.6, l.7, l.8, l.9, l.10, l.11, l.12, l.13, l.14, l.15, l.16,
        0, 0, 0, 0, 0, 0, 0, 0,
    ]
}

/// Keccak-256 of the first `length` bytes of a packed node. Bytes from
/// `length` to the end of its last block must be zero (any other value changes
/// the digest, so a nonzero tail only makes the node fail to match).
unconstrained fn hash_node(node: [Field; NODE_FIELDS], length: u32) -> [u64; 4] {
    let full = length / RATE;
    let rest = length % RATE;
    // Every node is at least two bytes, so block 0 always holds data.
    let mut state = first_block(node);
    for block in 1..full + 1 {
        state = keccakf1600(state);
        if (block < full) | (rest != 0) {
            state = absorb(state, node, block);
        }
    }
    state[rest / 8] ^= 1 << ((rest % 8) * 8) as u64;
    state[16] ^= 0x80 << 56;
    state = keccakf1600(state);
    [state[0], state[1], state[2], state[3]]
}

/// Total length (header included) of the short RLP item with this prefix.
#[inline_always]
unconstrained fn item_length(prefix: u8) -> u32 {
    if prefix < 0x80 {
        1
    } else if prefix <= 0xb7 {
        (prefix - 0x80) as u32 + 1
    } else {
        assert((prefix >= 0xc0) & (prefix <= 0xf7), "Unsupported RLP item in node");
        (prefix - 0xc0) as u32 + 1
    }
}

/// Nibble `index` of a key held as four little-endian lanes, high nibble of
/// each byte first.
#[inline_always]
pub(crate) unconstrained fn nibble_at(key: [u64; 4], index: u32) -> u8 {
    let byte = (key[index / 16] >> (((index / 2) % 8) * 8) as u64) as u8;
    if index % 2 == 0 {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

/// Check one node against `parent` and return the reference it holds for the
/// key from `nibble`, and the next nibble.
unconstrained fn step(
    node: [Field; NODE_FIELDS],
    parent: [u64; 4],
    key: [u64; 4],
    nibble: u32,
) -> (Reference, u32) {
    // The list header gives the node's length.
    let first = byte(node, 0);
    let (start, length) = if first <= 0xf7 {
        assert(first >= 0xc0, "Node is not an RLP list");
        (1, (first - 0xc0) as u32 + 1)
    } else if first == 0xf8 {
        (2, byte(node, 1) as u32 + 2)
    } else {
        assert_eq(first, 0xf9, "Node is not an RLP list");
        (3, byte(node, 1) as u32 * 256 + byte(node, 2) as u32 + 3)
    };
    assert(length < NODE_CAPACITY, "Node exceeds capacity");
    assert_eq(hash_node(node, length), parent, "Node hash differs from its parent reference");

    let selected = nibble_at(key, nibble) as u32;
    if length > 68 {
        // An extension is at most 68 bytes (a 33-byte path item and a 33-byte
        // child), so this is a branch. The bytes are the hashed node's, so only
        // the items up to the selected child need reading.
        let mut offset = start;
        for _ in 0..selected {
            offset += item_length(byte(node, offset));
        }
        assert(offset < length, "Node items do not end at its length");
        assert_eq(byte(node, length - 1), 0x80, "Branch value is not empty");
        (branch_child(node, offset), nibble + 1)
    } else {
        short_node(node, start, length, key, nibble, selected)
    }
}

/// The reference held by the branch child whose item starts at `offset`.
unconstrained fn branch_child(node: [Field; NODE_FIELDS], offset: u32) -> Reference {
    let prefix = byte(node, offset);
    // The fix for the descent bug in the code this is adapted from: an empty
    // child has no hash to follow, so the walk must stop.
    assert(prefix != 0x80, "Missing child");
    if prefix == 0xa0 {
        Reference { lanes: lanes_at(node, offset + 1), length: 32 }
    } else {
        assert((prefix >= 0xc0) & (prefix <= 0xde), "Expected child hash");
        Reference { lanes: lanes_at(node, offset), length: (prefix - 0xc0) as u32 + 1 }
    }
}

/// A node of at most 68 bytes: an extension, or a branch with embedded children.
/// Its items are all scanned to tell the two apart.
unconstrained fn short_node(
    node: [Field; NODE_FIELDS],
    start: u32,
    length: u32,
    key: [u64; 4],
    mut nibble: u32,
    selected: u32,
) -> (Reference, u32) {
    let mut offset = start;
    let mut count = 0;
    let mut item0 = 0;
    let mut item1 = 0;
    let mut chosen = 0;
    let mut value = 0;
    for i in 0..17 {
        if offset < length {
            if i == 0 {
                item0 = offset;
            }
            if i == 1 {
                item1 = offset;
            }
            if i == selected {
                chosen = offset;
            }
            value = offset;
            offset += item_length(byte(node, offset));
            count += 1;
        }
    }
    assert_eq(offset, length, "Node items do not end at its length");

    if count == 17 {
        // Secure-trie keys are all 32 bytes, so no branch carries a value.
        assert_eq(byte(node, value), 0x80, "Branch value is not empty");
        (branch_child(node, chosen), nibble + 1)
    } else {
        assert_eq(count, 2, "Node is neither a branch nor an extension");
        // Compact path: a lone flag byte below 0x80, or a string of up to 32 bytes.
        let path_prefix = byte(node, item0);
        let (path, path_length) = if path_prefix < 0x80 {
            (item0, 1)
        } else {
            (item0 + 1, (path_prefix - 0x80) as u32)
        };
        assert(path_length > 0, "Empty extension");
        let flag = byte(node, path);
        assert(flag >> 4 <= 1, "Expected extension, not leaf");
        if flag >> 4 == 1 {
            assert_eq(flag & 0x0f, nibble_at(key, nibble), "Extension path differs from the key");
            nibble += 1;
        } else {
            assert_eq(flag & 0x0f, 0, "Nonzero extension path padding");
            assert(path_length > 1, "Empty extension");
        }
        // An extension must leave at least one nibble for its child.
        assert(nibble + 2 * (path_length - 1) < 64, "Extension path is longer than the key");
        for j in 1..path_length {
            let b = byte(node, path + j);
            assert_eq(b >> 4, nibble_at(key, nibble), "Extension path differs from the key");
            assert_eq(b & 0x0f, nibble_at(key, nibble + 1), "Extension path differs from the key");
            nibble += 2;
        }
        assert_eq(byte(node, item1), 0xa0, "Expected child hash");
        (Reference { lanes: lanes_at(node, item1 + 1), length: 32 }, nibble)
    }
}

/// Walk `count` nodes from `root` along `key`. Returns the leaf's reference and
/// the number of key nibbles consumed.
pub(crate) unconstrained fn walk<let D: u32>(
    root: [u64; 4],
    key: [u64; 4],
    nodes: [[Field; NODE_FIELDS]; D],
    count: u32,
) -> (Reference, u32) {
    assert(count <= D, "Node count exceeds capacity");
    let mut reference = Reference { lanes: root, length: 32 };
    let mut nibble = 0;
    for i in 0..count {
        // With hashed 32-byte keys, an embedded branch or extension needs two
        // keys sharing about 56 nibbles of their Keccak hash; only leaves embed.
        assert_eq(reference.length, 32, "Embedded internal nodes are not supported");
        assert(nibble < 64, "Path is longer than the key");
        let (child, next) = step(nodes[i], reference.lanes, key, nibble);
        reference = child;
        nibble = next;
    }
    (reference, nibble)
}
