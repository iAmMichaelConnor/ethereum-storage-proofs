//! SSZ SHA256 Merkle inclusion. A trusted SSZ root and the correct schema/index
//! are caller inputs; this module does not verify beacon consensus or finality.
use std::hash::sha256_compression;

/// SHA256(left || right), including the second compression for 64-byte padding.
pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut message = [0; 16];
    for i in 0..8 {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        for j in 0..4 {
            a = a * 256 + left[4 * i + j] as u32;
            b = b * 256 + right[4 * i + j] as u32;
        }
        message[i] = a;
        message[i + 8] = b;
    }
    let state = sha256_compression(
        message,
        [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ],
    );
    let mut padding = [0; 16];
    padding[0] = 0x80000000;
    padding[15] = 512;
    let state = sha256_compression(padding, state);
    let mut result = [0; 32];
    for i in 0..8 {
        let bytes: [u8; 4] = (state[i] as Field).to_be_bytes();
        for j in 0..4 {
            result[i * 4 + j] = bytes[j];
        }
    }
    result
}

/// Exact-depth branch; siblings are ordered from the leaf toward the root.
/// A generalized index includes its leading 1 (root=1, children=2 and 3).
/// It is NOT a zero-based leaf offset. Depth is limited to 63 by the u64 index.
pub fn verify_branch<let D: u32>(
    leaf: [u8; 32],
    branch: [[u8; 32]; D],
    gindex: u64,
    root: [u8; 32],
) {
    // D is compile-time: the bounded traversal specializes to an exact branch.
    verify_branch_bounded(leaf, branch, D, gindex, root);
}

/// Padded capacity variant. Only the prefix `depth` is used, and the index must
/// have exactly that depth. Unused suffix siblings do not affect the statement.
pub fn verify_branch_bounded<let MAX: u32>(
    leaf: [u8; 32],
    branch: [[u8; 32]; MAX],
    depth: u32,
    gindex: u64,
    root: [u8; 32],
) {
    std::static_assert(MAX <= 63, "Generalized index exceeds u64");
    assert(depth <= MAX, "Depth exceeds branch capacity");
    assert_eq(gindex >> depth as u64, 1, "Index has wrong depth");
    let mut node = leaf;
    let mut index = gindex;
    for i in 0..MAX {
        if i < depth {
            let left = if index & 1 == 0 { node } else { branch[i] };
            let right = if index & 1 == 0 { branch[i] } else { node };
            node = hash_pair(left, right);
            index >>= 1;
        }
    }
    assert_eq(node, root, "Branch does not reach the root");
}

/// SSZ uint64 hash-tree-root: little-endian eight bytes, then 24 zero bytes.
pub fn uint64_root(value: u64) -> [u8; 32] {
    let bytes: [u8; 8] = (value as Field).to_le_bytes();
    let mut root = [0; 32];
    for i in 0..8 {
        root[i] = bytes[i];
    }
    root
}

/// Convert an SSZ Bytes32 execution state root to the MPT library's lane format.
pub fn execution_root_limbs(root: [u8; 32]) -> [u64; 4] {
    let mut lanes = [0; 4];
    for i in 0..4 {
        for j in 0..8 {
            lanes[i] += (root[8 * i + j] as u64) << (8 * j) as u64;
        }
    }
    lanes
}

/// Deneb BeaconBlock/BeaconBlockHeader root -> ExecutionPayload root ->
/// execution state root AND block number. This authenticates their association
/// under the supplied beacon root, not the beacon root's consensus status.
/// Fork-specific layout: body index 4/8, payload index 9/16, payload fields 2 and 6/32.
/// The same generalized indices (201, 34, 38) hold for Deneb, Electra and Fulu.
/// A Capella or earlier root fails closed. Gloas (EIP-7732) moves the payload out
/// of the body, so this layout must not be used for it: under some Gloas layouts a
/// genuine root gives a zero state root and block number 0.
/// This function does not read the slot, so the caller must already know that the
/// root is from a Deneb, Electra or Fulu block. Prefer
/// verify_deneb_execution_anchor_at_slot, which binds the slot and checks a fork range.
/// The root is the unsigned block/header root, not SignedBeaconBlock's root.
/// An EIP-4788 root read for execution block N is the parent beacon root: it
/// anchors block N-1. Take block identity from the bound block_number.
pub fn verify_deneb_execution_anchor(
    beacon_root: [u8; 32],
    payload_root: [u8; 32],
    payload_branch: [[u8; 32]; 7],
    state_root: [u8; 32],
    state_branch: [[u8; 32]; 5],
    block_number: u64,
    number_branch: [[u8; 32]; 5],
) {
    verify_branch(payload_root, payload_branch, 201, beacon_root);
    // The paths from indices 34 and 38 meet at index 4. Authenticate each
    // distinct ancestor once, binding every node in both original branches.
    let subtree8 = hash_pair(state_branch[1], hash_pair(state_root, state_branch[0]));
    let subtree9 = hash_pair(
        number_branch[1],
        hash_pair(uint64_root(block_number), number_branch[0]),
    );
    assert_eq(state_branch[2], subtree9, "State branch disagrees with the block number");
    assert_eq(number_branch[2], subtree8, "Number branch disagrees with the state root");
    assert_eq(state_branch[3], number_branch[3]);
    assert_eq(state_branch[4], number_branch[4]);
    let subtree4 = hash_pair(subtree8, subtree9);
    let subtree2 = hash_pair(subtree4, state_branch[3]);
    assert_eq(hash_pair(subtree2, state_branch[4]), payload_root);
}

/// First slot of the Deneb fork on Ethereum mainnet (epoch 269568 x 32 slots).
pub global MAINNET_DENEB_FIRST_SLOT: u64 = 8626176;

/// verify_deneb_execution_anchor, and also authenticate the block's slot
/// (BeaconBlock field 0, generalized index 8) and require
/// `first_slot <= slot < end_slot`. Pass the fork range in which the Deneb layout
/// holds on the caller's chain: on mainnet, MAINNET_DENEB_FIRST_SLOT up to the
/// first Gloas slot (or u64::MAX until Gloas is scheduled; update it then).
/// slot_branch is [proposer_index root, hash(parent_root, state_root)]: the
/// siblings of generalized indices 8 and 4. The ancestor at index 2 must equal
/// payload_branch[6], so the slot and the payload are bound to one beacon root.
pub fn verify_deneb_execution_anchor_at_slot(
    beacon_root: [u8; 32],
    slot: u64,
    slot_branch: [[u8; 32]; 2],
    first_slot: u64,
    end_slot: u64,
    payload_root: [u8; 32],
    payload_branch: [[u8; 32]; 7],
    state_root: [u8; 32],
    state_branch: [[u8; 32]; 5],
    block_number: u64,
    number_branch: [[u8; 32]; 5],
) {
    assert(first_slot <= slot, "Slot is before the anchor's fork range");
    assert(slot < end_slot, "Slot is after the anchor's fork range");
    verify_deneb_execution_anchor(
        beacon_root,
        payload_root,
        payload_branch,
        state_root,
        state_branch,
        block_number,
        number_branch,
    );
    let header_left = hash_pair(hash_pair(uint64_root(slot), slot_branch[0]), slot_branch[1]);
    assert_eq(payload_branch[6], header_left, "Slot is not bound to the beacon root");
}
mod benchmarks;
