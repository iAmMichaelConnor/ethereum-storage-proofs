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
//! is a branch, an extension or a leaf follows from its item count (17 or 2)
//! and its path flag, so the prover supplies no node kind. A leaf can be longer
//! than an extension, so a long node is checked to have more than two items
//! before it is read as a branch.
use crate::NODE_FIELDS;
use crate::sink::Reference;
use std::hash::keccakf1600;

/// 2^-128 in the BN254 scalar field.
global INV_2_128: Field = 0x133100d71fdf35792b16366f4f7684df54ad7e14a329e70f18ee753c76f9dc6f;
/// 2^64. Dividing a u128 by it, rather than shifting, lets the compiler see that
/// the quotient fits a u64, so the cast to u64 needs no truncation.
global TWO_64: u128 = 0x10000000000000000;
/// Keccak-256 rate in bytes: one block, 17 lanes.
global RATE: u32 = 136;
/// Byte capacity of a packed node: four Keccak blocks.
pub(crate) global NODE_CAPACITY: u32 = 544;

/// Split a field into three lanes. Bits at and above 2^192 are dropped.
#[inline_always]
pub(crate) unconstrained fn split3(x: Field) -> (u64, u64, u64) {
    let low = x as u128;
    let high = (x - low as Field) * INV_2_128;
    (low as u64, (low / TWO_64) as u64, high as u64)
}

/// Byte `offset` of a packed node: byte `offset % 24` of field `offset / 24`,
/// counted from its least significant end. One radix decomposition is cheaper
/// than extracting the lane and shifting. A field of 2^192 or more does not
/// decompose into 24 bytes and fails here, so a byte read never disagrees with
/// the hashed lanes (which drop those bits).
#[inline_always]
unconstrained fn byte(node: [Field; NODE_FIELDS], offset: u32) -> u8 {
    let bytes: [u8; 24] = node[offset / 24].to_be_bytes();
    bytes[23 - offset % 24]
}

/// Field `index` of a packed node, or zero past its last field.
#[inline_always]
unconstrained fn field_or_zero(node: [Field; NODE_FIELDS], index: u32) -> Field {
    if index < NODE_FIELDS {
        node[index]
    } else {
        0
    }
}

/// The 32 bytes from `offset` as four lanes; bytes past the capacity read as zero.
unconstrained fn lanes_at(node: [Field; NODE_FIELDS], offset: u32) -> [u64; 4] {
    // The five lanes from lane `offset / 8` lie in two or three consecutive fields.
    let first = offset / 8;
    let field = first / 3;
    let (a0, a1, a2) = split3(node[field]);
    let (b0, b1, b2) = split3(field_or_zero(node, field + 1));
    let position = first % 3;
    let (lane0, lane1, lane2, lane3, lane4) = if position == 0 {
        (a0, a1, a2, b0, b1)
    } else if position == 1 {
        (a1, a2, b0, b1, b2)
    } else {
        (a2, b0, b1, b2, field_or_zero(node, field + 2) as u64)
    };
    let shift = ((offset % 8) * 8) as u64;
    if shift == 0 {
        [lane0, lane1, lane2, lane3]
    } else {
        let back = 64 - shift;
        [
            (lane0 >> shift) | (lane1 << back),
            (lane1 >> shift) | (lane2 << back),
            (lane2 >> shift) | (lane3 << back),
            (lane3 >> shift) | (lane4 << back),
        ]
    }
}

/// The 17 lanes of one Keccak block.
type Lanes17 = (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64);

/// The 17 lanes of block `block` (0 to 3), which starts at lane 17 * block:
/// field 0 position 0, field 5 position 2, field 11 position 1 or field 17
/// position 0.
#[inline_always]
unconstrained fn block_lanes(node: [Field; NODE_FIELDS], block: u32) -> Lanes17 {
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

/// XOR a block's lanes into the sponge state.
#[inline_always]
unconstrained fn absorb(state: [u64; 25], l: Lanes17) -> [u64; 25] {
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
unconstrained fn first_block(l: Lanes17) -> [u64; 25] {
    [
        l.0, l.1, l.2, l.3, l.4, l.5, l.6, l.7, l.8, l.9, l.10, l.11, l.12, l.13, l.14, l.15, l.16,
        0, 0, 0, 0, 0, 0, 0, 0,
    ]
}

/// Whether a node's four blocks of lanes have the layout of a branch whose 16
/// children are all hashes and whose value is empty, the commonest node: the
/// header f9 02 11 (a 529-byte list, 532 bytes in all), 0xa0 at byte 3 + 33j for
/// each child j, and 0x80 at byte 531. Each of these is the prefix a scan of
/// the items would read at that offset, so together they fix the parse: child
/// j is the 32-byte hash at byte 4 + 33j, and the value item ends the node.
#[inline_always]
unconstrained fn is_full_branch(b0: Lanes17, b1: Lanes17, b2: Lanes17, b3: Lanes17) -> bool {
    // Byte k of a lane is bits 8k to 8k + 7. Block b holds lanes 17b to 17b + 16.
    ((b0.0 & 0xffffffff) == 0xa01102f9) // bytes 0 to 3
        & ((b0.4 & 0xff00000000) == 0xa000000000) // byte 36
        & ((b0.8 & 0xff0000000000) == 0xa00000000000) // byte 69
        & ((b0.12 & 0xff000000000000) == 0xa0000000000000) // byte 102
        & ((b0.16 & 0xff00000000000000) == 0xa000000000000000) // byte 135
        & ((b1.4 & 0xff) == 0xa0) // byte 168
        & ((b1.8 & 0xff00) == 0xa000) // byte 201
        & ((b1.12 & 0xff0000) == 0xa00000) // byte 234
        & ((b1.16 & 0xff000000) == 0xa0000000) // byte 267
        & ((b2.3 & 0xff00000000) == 0xa000000000) // byte 300
        & ((b2.7 & 0xff0000000000) == 0xa00000000000) // byte 333
        & ((b2.11 & 0xff000000000000) == 0xa0000000000000) // byte 366
        & ((b2.15 & 0xff00000000000000) == 0xa000000000000000) // byte 399
        & ((b3.3 & 0xff) == 0xa0) // byte 432
        & ((b3.7 & 0xff00) == 0xa000) // byte 465
        & ((b3.11 & 0xff0000) == 0xa00000) // byte 498
        & ((b3.15 & 0xff000000) == 0x80000000) // byte 531
}

/// Keccak-256 of the first `length` bytes of a packed node, and whether the node
/// has the layout `is_full_branch` checks. Bytes from `length` to the end of its
/// last block must be zero (any other value changes the digest, so a nonzero
/// tail only makes the node fail to match).
unconstrained fn hash_node(node: [Field; NODE_FIELDS], length: u32) -> ([u64; 4], bool) {
    let full = length / RATE;
    let rest = length % RATE;
    // The message and its padding fill blocks 0 to `full` (at most 3, as
    // `length` is below four blocks). Each is absorbed from the node, whose
    // bytes from `length` on are zero; unrolled, every block's lane positions
    // are constants.
    let b0 = block_lanes(node, 0);
    let mut state = first_block(b0);
    let mut full_branch = false;
    if full > 0 {
        let b1 = block_lanes(node, 1);
        state = absorb(keccakf1600(state), b1);
        if full > 1 {
            let b2 = block_lanes(node, 2);
            state = absorb(keccakf1600(state), b2);
            if full > 2 {
                let b3 = block_lanes(node, 3);
                state = absorb(keccakf1600(state), b3);
                full_branch = is_full_branch(b0, b1, b2, b3);
            }
        }
    }
    state[rest / 8] ^= 1 << ((rest % 8) * 8) as u64;
    state[16] ^= 0x80 << 56;
    state = keccakf1600(state);
    ([state[0], state[1], state[2], state[3]], full_branch)
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
    // The list header gives the node's length. Its bytes are the low bytes of
    // field 0 (see `byte`).
    let head: [u8; 24] = node[0].to_be_bytes();
    let first = head[23];
    let (start, length) = if first <= 0xf7 {
        assert(first >= 0xc0, "Node is not an RLP list");
        (1, (first - 0xc0) as u32 + 1)
    } else if first == 0xf8 {
        (2, head[22] as u32 + 2)
    } else {
        assert_eq(first, 0xf9, "Node is not an RLP list");
        (3, head[22] as u32 * 256 + head[21] as u32 + 3)
    };
    assert(length < NODE_CAPACITY, "Node exceeds capacity");
    let (digest, full_branch) = hash_node(node, length);
    assert_eq(digest, parent, "Node hash differs from its parent reference");

    let selected = nibble_at(key, nibble) as u32;
    if full_branch {
        // The hashed node's child prefixes and empty value were read by
        // `is_full_branch`: the selected child is the hash after its 0xa0.
        (Reference { lanes: lanes_at(node, 4 + 33 * selected), length: 32 }, nibble + 1)
    } else if length > 68 {
        // An extension is at most 68 bytes (a 33-byte path item and a 33-byte
        // child), so this is a branch or a leaf. A leaf's two items fill it;
        // a branch has fifteen more. The bytes are the hashed node's, so the
        // items after that and after the selected child need no reading.
        let after_two = skip_items(node, start, 2);
        assert(after_two < length, "Expected branch, not leaf");
        let offset = if selected < 2 {
            skip_items(node, start, selected)
        } else {
            skip_items(node, after_two, selected - 2)
        };
        // Defence in depth: a node that hashes to its parent's reference is a
        // well-formed branch, whose selected child always starts before its end.
        assert(offset < length, "Node items do not end at its length");
        assert_eq(byte(node, length - 1), 0x80, "Branch value is not empty");
        (branch_child(node, offset), nibble + 1)
    } else {
        short_node(node, start, length, key, nibble, selected)
    }
}

/// The offset of the item `count` items after the one at `offset`.
#[inline_always]
unconstrained fn skip_items(node: [Field; NODE_FIELDS], mut offset: u32, count: u32) -> u32 {
    for _ in 0..count {
        offset += item_length(byte(node, offset));
    }
    offset
}

/// The reference held by the branch child whose item starts at `offset`.
unconstrained fn branch_child(node: [Field; NODE_FIELDS], offset: u32) -> Reference {
    let prefix = byte(node, offset);
    // An empty child has no hash to follow: descending past it would let the
    // prover choose the subtree, so the walk stops.
    assert(prefix != 0x80, "Missing child");
    if prefix == 0xa0 {
        Reference { lanes: lanes_at(node, offset + 1), length: 32 }
    } else {
        assert((prefix >= 0xc0) & (prefix <= 0xde), "Expected child hash");
        Reference { lanes: lanes_at(node, offset), length: (prefix - 0xc0) as u32 + 1 }
    }
}

/// A node of at most 68 bytes: an extension, a branch with embedded children,
/// or a leaf, which is rejected.
/// Its items are all scanned to tell these apart.
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
        assert(path_length > 0, "Extension path is empty");
        let flag = byte(node, path);
        assert(flag >> 4 <= 1, "Expected extension, not leaf");
        if flag >> 4 == 1 {
            assert_eq(flag & 0x0f, nibble_at(key, nibble), "Extension path differs from the key");
            nibble += 1;
        } else {
            assert_eq(flag & 0x0f, 0, "Nonzero extension path padding");
            assert(path_length > 1, "Extension path has no nibbles");
        }
        // An extension must leave at least one nibble for its child.
        assert(nibble + 2 * (path_length - 1) < 64, "Extension path is longer than the key");
        for j in 1..path_length {
            let b = byte(node, path + j);
            assert_eq(b >> 4, nibble_at(key, nibble), "Extension path differs from the key");
            assert_eq(
                b & 0x0f,
                nibble_at(key, nibble + 1),
                "Extension path low nibble differs from the key",
            );
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

/// The packed node of `length` pattern bytes, and the Keccak-256 of those bytes
/// from the byte-wise sponge.
unconstrained fn pattern_node(length: u32) -> ([Field; NODE_FIELDS], [u64; 4]) {
    let mut lanes: [u64; 69] = [0; 69];
    let mut sponge = crate::sink::Sponge::new();
    for i in 0..length {
        let b = ((i * 7 + 3) % 256) as u64;
        lanes[i / 8] += b << ((i % 8) * 8) as u64;
        crate::sink::Sink::add_chunk(&mut sponge, b, 1);
    }
    let mut node = [0; NODE_FIELDS];
    for k in 0..NODE_FIELDS {
        node[k] = lanes[3 * k] as Field
            + lanes[3 * k + 1] as Field * 0x10000000000000000
            + lanes[3 * k + 2] as Field * 0x100000000000000000000000000000000;
    }
    (node, sponge.finish())
}

// Lengths on both sides of each block boundary, where the padding moves into a
// block of its own.
#[test]
unconstrained fn hash_node_matches_sponge_at_block_boundaries() {
    for length in [2, 135, 136, 137, 271, 272, 273, 407, 408, 409, 543] {
        let (node, digest) = pattern_node(length);
        assert_eq(hash_node(node, length).0, digest);
    }
}

// A nonzero byte in a padding-only block changes the digest.
#[test]
unconstrained fn hash_node_reads_the_padding_block() {
    let (mut node, digest) = pattern_node(136);
    // Byte 136 is the low byte of lane 17: field 5, bits 128 to 135.
    node[5] += 0x100000000000000000000000000000000;
    assert(hash_node(node, 136).0 != digest);
}

/// The number of full branches among the first `count` nodes, checking that
/// for each the layout check gives every child the offset an item scan gives.
unconstrained fn check_full_branches<let D: u32>(
    nodes: [[Field; NODE_FIELDS]; D],
    count: u32,
) -> u32 {
    let mut full_branches = 0;
    for i in 0..count {
        let node = nodes[i];
        if byte(node, 0) == 0xf9 {
            let length = byte(node, 1) as u32 * 256 + byte(node, 2) as u32 + 3;
            let (_, full_branch) = hash_node(node, length);
            assert_eq(full_branch, length == 532);
            if full_branch {
                full_branches += 1;
                assert_eq(skip_items(node, 3, 17), length);
                for child in 0..16 {
                    let offset = skip_items(node, 3, child);
                    assert_eq(offset, 3 + 33 * child);
                    assert_eq(branch_child(node, offset).lanes, lanes_at(node, 4 + 33 * child));
                }
            }
        }
    }
    full_branches
}

#[test]
unconstrained fn full_branch_offsets_match_the_item_scan() {
    let (_, _, account_nodes, account_count, _, _, _, storage_nodes, storage_count) =
        crate::fixtures_tests::mainnet();
    assert_eq(
        check_full_branches(account_nodes, account_count)
            + check_full_branches(storage_nodes, storage_count),
        11,
    );
}

// Every offset, against lanes assembled byte by byte.
#[test]
unconstrained fn lanes_at_matches_the_bytes() {
    let (node, _) = pattern_node(543);
    for offset in 0..543 {
        let mut expected = [0; 4];
        for i in 0..32 {
            let at = offset + i;
            let b = if at < 543 {
                ((at * 7 + 3) % 256) as u64
            } else {
                0
            };
            expected[i / 8] += b << ((i % 8) * 8) as u64;
        }
        assert_eq(lanes_at(node, offset), expected);
        assert_eq(byte(node, offset), ((offset * 7 + 3) % 256) as u8);
    }
}
