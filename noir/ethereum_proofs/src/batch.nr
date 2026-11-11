//! Ordered multi-slot inclusion against one storage root. Internal node hashes
//! are shared; every path still checks its own key, child links and terminal leaf.
use crate::{
    keccak::{keccak256, keccak256_limbs},
    proof::{
        advance_node, advance_parsed, empty_layout, EncodedNode, new_cursor, parse_layout,
        verify_storage_leaf,
    },
    types::StorageSlot,
    utils::to_nibbles,
};

/// A used prefix of indices into the shared internal-node table; leaf excluded.
pub struct IndexedPath<let D: u32> {
    pub indices: [u32; D],
    pub count: u32,
}

/// Prove K ordered, nonzero slots. Duplicate keys are allowed and each occurrence
/// must carry its correct value. Table indices may be reused; cycles cannot bypass
/// the parser's strictly increasing nibble cursor or the final leaf binding.
/// P bounds table entries, D bounds each path, and B bounds each node's bytes.
/// Unused table entries and unused path indices may contain arbitrary padding.
/// The table need not be sorted or deduplicated for correctness. Deduplicate it
/// in the host preparer to reduce P and save hashing work. Every entry below
/// node_count must have length <= B; unused suffix entries have no such condition.
pub fn verify_storage_batch<let K: u32, let P: u32, let D: u32, let B: u32>(
    root: [u64; 4],
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    nodes: [EncodedNode<B>; P],
    node_count: u32,
    paths: [IndexedPath<D>; K],
) {
    verify_storage_batch_mode::<K, P, D, B, 0>(root, slot_keys, values, nodes, node_count, paths);
}

/// Cache canonical node structure once per referenced table entry. Claim order,
/// duplicate keys, embedded references and arbitrary unused padding remain supported.
pub fn verify_storage_batch_parsed<let K: u32, let P: u32, let D: u32, let B: u32>(
    root: [u64; 4],
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    nodes: [EncodedNode<B>; P],
    node_count: u32,
    paths: [IndexedPath<D>; K],
) {
    verify_storage_batch_mode::<K, P, D, B, 1>(root, slot_keys, values, nodes, node_count, paths);
}

fn verify_storage_batch_mode<let K: u32, let P: u32, let D: u32, let B: u32, let PARSED: u32>(
    root: [u64; 4],
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    nodes: [EncodedNode<B>; P],
    node_count: u32,
    paths: [IndexedPath<D>; K],
) {
    std::static_assert(K > 0, "A batch must contain at least one claim");
    std::static_assert(B >= 3, "Node capacity must be at least 3");
    assert(node_count <= P, "Node count exceeds capacity");
    let mut hashes = [[0; 4]; P];
    for i in 0..P {
        // Neutralize inactive lengths before entering the no_predicates hash.
        let length = if i < node_count { nodes[i].length } else { 0 };
        hashes[i] = keccak256_limbs(nodes[i].bytes, length);
    }
    verify_storage_paths::<K, P, D, B, 0, PARSED>(
        root,
        slot_keys,
        values,
        nodes,
        hashes,
        node_count,
        paths,
        [false; P],
    );
}

/// Reuse one account proof for all slots in the batch. The caller must bind the
/// intended account address and authenticate the Ethereum state root.
pub fn verify_l1_storage_batch<let AD: u32, let AB: u32, let K: u32, let P: u32, let D: u32, let B: u32>(
    state_root: [u64; 4],
    account: crate::types::Account,
    account_nodes: [EncodedNode<AB>; AD],
    account_count: u32,
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    nodes: [EncodedNode<B>; P],
    node_count: u32,
    paths: [IndexedPath<D>; K],
) {
    crate::proof::verify_account(state_root, account, account_nodes, account_count);
    verify_storage_batch(
        account.storage_hash,
        slot_keys,
        values,
        nodes,
        node_count,
        paths,
    );
}

// Digests are supplied only by constrained hashing in this module. Keep private:
// callers must never be allowed to supply an unauthenticated digest cache.
fn verify_storage_paths<let K: u32, let P: u32, let D: u32, let B: u32, let SPARSE: u32, let PARSED: u32>(
    root: [u64; 4],
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    nodes: [EncodedNode<B>; P],
    hashes: [[u64; 4]; P],
    node_count: u32,
    paths: [IndexedPath<D>; K],
    active: [bool; P],
) {
    let mut layouts = [empty_layout(); P];
    if PARSED == 1 {
        let mut needed = [false; P];
        if P != 0 {
            for k in 0..K {
                assert(paths[k].count <= D, "Path count exceeds capacity");
                for j in 0..D {
                    if j < paths[k].count {
                        let index = paths[k].indices[j];
                        if SPARSE == 0 {
                            assert(index < node_count, "Path index outside active node table");
                        } else {
                            assert(index < P, "Path index outside table capacity");
                            assert(active[index], "Path index references an unused bucket entry");
                        }
                        needed[index] = true;
                    }
                }
            }
            for i in 0..P {
                if needed[i] {
                    layouts[i] = parse_layout(nodes[i]);
                }
            }
        }
    }
    for k in 0..K {
        let key = keccak256(slot_keys[k], 32);
        let nibbles = to_nibbles(key);
        let mut cursor = new_cursor(root);
        assert(paths[k].count <= D, "Path count exceeds capacity");
        if P == 0 {
            assert_eq(paths[k].count, 0, "Path count exceeds capacity");
        } else {
            for j in 0..D {
                if j < paths[k].count {
                    let index = paths[k].indices[j];
                    if SPARSE == 0 {
                        assert(index < node_count, "Path index outside active node table");
                    } else {
                        assert(index < P, "Path index outside table capacity");
                        assert(active[index], "Path index references an unused bucket entry");
                    }
                    let node = nodes[index];
                    if cursor.reference_length == 32 {
                        assert_eq(
                            hashes[index],
                            cursor.hash,
                            "Node hash differs from its parent reference",
                        );
                    } else {
                        assert(cursor.reference_length > 0, "Missing child");
                        assert(cursor.reference_length < 32, "Expected child hash");
                        assert_eq(
                            node.length,
                            cursor.reference_length,
                            "Embedded node differs from its parent reference",
                        );
                        for b in 0..31 {
                            if b < node.length {
                                assert_eq(
                                    node.bytes[b],
                                    (cursor.hash[b / 8] >> ((b % 8) * 8) as u64) as u8,
                                    "Embedded node differs from its parent reference",
                                );
                            }
                        }
                    }
                    cursor = if PARSED == 1 {
                        advance_parsed(node, layouts[index], cursor, nibbles)
                    } else {
                        advance_node::<B, 1>(node, cursor, nibbles)
                    };
                }
            }
        }
        verify_storage_leaf(cursor, key, values[k]);
    }
}

/// One independently sized bucket in a mixed-capacity node table.
/// Only the first count entries are active; the remaining bytes/lengths are padding.
pub struct NodeBucket<let P: u32, let B: u32> {
    pub nodes: [EncodedNode<B>; P],
    pub count: u32,
}

fn append_bucket<let P: u32, let B: u32, let T: u32>(
    bucket: NodeBucket<P, B>,
    offset: u32,
    nodes: &mut [EncodedNode<532>; T],
    hashes: &mut [[u64; 4]; T],
    active: &mut [bool; T],
) {
    std::static_assert(B <= 532, "Bucket exceeds maximum node capacity");
    assert(bucket.count <= P, "Node count exceeds capacity");
    assert(offset + P <= T, "Node count exceeds capacity");
    for i in 0..P {
        let used = i < bucket.count;
        hashes[offset + i] = keccak256_limbs(
            bucket.nodes[i].bytes,
            if used { bucket.nodes[i].length } else { 0 },
        );
        active[offset + i] = used;
        nodes[offset + i].length = bucket.nodes[i].length;
        nodes[offset + i].is_extension = bucket.nodes[i].is_extension;
        for j in 0..B {
            nodes[offset + i].bytes[j] = bucket.nodes[i].bytes[j];
        }
    }
}

/// Shared-node batch with 1/2/3/4-block Keccak capacities. Indices address bucket
/// capacities concatenated in this order, including unused entries between buckets.
/// Active indices must refer to an entry below that bucket's count. The table can
/// be permuted within each bucket; unused bytes, lengths and path indices are ignored.
pub fn verify_storage_batch_mixed<let K: u32, let A: u32, let B: u32, let C: u32, let E: u32, let D: u32>(
    root: [u64; 4],
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    small: NodeBucket<A, 135>,
    medium: NodeBucket<B, 271>,
    large: NodeBucket<C, 407>,
    full: NodeBucket<E, 532>,
    paths: [IndexedPath<D>; K],
) {
    verify_storage_batch_mixed_mode::<K, A, B, C, E, D, 0>(
        root,
        slot_keys,
        values,
        small,
        medium,
        large,
        full,
        paths,
    );
}

/// Mixed hash capacities with shared structural parsing. Same input domain as
/// verify_storage_batch_mixed; compare costs for the intended batch workload.
pub fn verify_storage_batch_mixed_parsed<let K: u32, let A: u32, let B: u32, let C: u32, let E: u32, let D: u32>(
    root: [u64; 4],
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    small: NodeBucket<A, 135>,
    medium: NodeBucket<B, 271>,
    large: NodeBucket<C, 407>,
    full: NodeBucket<E, 532>,
    paths: [IndexedPath<D>; K],
) {
    verify_storage_batch_mixed_mode::<K, A, B, C, E, D, 1>(
        root,
        slot_keys,
        values,
        small,
        medium,
        large,
        full,
        paths,
    );
}

fn verify_storage_batch_mixed_mode<let K: u32, let A: u32, let B: u32, let C: u32, let E: u32, let D: u32, let PARSED: u32>(
    root: [u64; 4],
    slot_keys: [[u8; 32]; K],
    values: [StorageSlot; K],
    small: NodeBucket<A, 135>,
    medium: NodeBucket<B, 271>,
    large: NodeBucket<C, 407>,
    full: NodeBucket<E, 532>,
    paths: [IndexedPath<D>; K],
) {
    std::static_assert(K > 0, "A batch must contain at least one claim");
    let mut nodes =
        [EncodedNode { bytes: [0; 532], length: 0, is_extension: false }; A + B + C + E];
    let mut hashes = [[0; 4]; A + B + C + E];
    let mut active = [false; A + B + C + E];
    append_bucket(small, 0, &mut nodes, &mut hashes, &mut active);
    append_bucket(medium, A, &mut nodes, &mut hashes, &mut active);
    append_bucket(large, A + B, &mut nodes, &mut hashes, &mut active);
    append_bucket(full, A + B + C, &mut nodes, &mut hashes, &mut active);
    verify_storage_paths::<K, A + B + C + E, D, 532, 1, PARSED>(
        root,
        slot_keys,
        values,
        nodes,
        hashes,
        A + B + C + E,
        paths,
        active,
    );
}
