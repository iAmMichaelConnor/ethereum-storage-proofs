//! Inclusion proofs for Ethereum's secure account and storage tries.
//! Supports hashed and embedded children. Hash-only entry points provide a smaller specialization.
use crate::{
    account_hash::{assert_canonical_account, compute_account_hash_unchecked},
    keccak::{keccak256, keccak256_limbs},
    slot_hash::{assert_canonical_slot, encode_slot_unchecked},
    types::{Account, StorageSlot},
    utils::to_nibbles,
};

/// One RLP-encoded internal node. B is a circuit capacity, not the actual length.
/// Zero padding is ignored. No leaf is included in the internal-node path.
pub struct EncodedNode<let B: u32> {
    pub bytes: [u8; B],
    pub length: u32,
    pub is_extension: bool,
}

/// Intermediate state for composing sections with different depth/byte capacities.
/// The fields are crate-private: a cursor is a security boundary, because a leaf
/// verifier binds its leaf to whatever reference the cursor holds.
/// Composition obligations (the library cannot check them for you):
/// - The first cursor must be new_cursor(authenticated_root). Every later cursor
///   must be the unmodified output of the previous section on the same path.
/// - Every section and the final leaf verifier must use the same hashed key.
/// - Cursor::from_authenticated_parts is the only other constructor. Use it only to
///   resume a path whose parts another constrained check has already bound to the
///   root (for example the public output of a verified proof of an earlier section).
pub struct Cursor {
    /// Hash limbs if reference_length == 32; otherwise zero-padded embedded RLP limbs.
    pub(crate) hash: [u64; 4],
    pub(crate) reference_length: u32,
    pub(crate) nibble: u32,
}

impl Cursor {
    /// Rebuild a cursor from its parts. This checks nothing: a cursor built from
    /// prover input makes a leaf verifier check a leaf that no root binds.
    pub fn from_authenticated_parts(
        reference: [u64; 4],
        reference_length: u32,
        nibbles_consumed: u32,
    ) -> Self {
        Cursor { hash: reference, reference_length, nibble: nibbles_consumed }
    }

    /// The pending child reference: hash limbs if reference_byte_length() == 32,
    /// otherwise the zero-padded embedded RLP limbs.
    pub fn reference(self) -> [u64; 4] {
        self.hash
    }

    pub fn reference_byte_length(self) -> u32 {
        self.reference_length
    }

    /// Key nibbles consumed by the sections verified so far.
    pub fn nibbles_consumed(self) -> u32 {
        self.nibble
    }
}

/// Start a path at `root`. The root must already be authenticated by the caller.
pub fn new_cursor(root: [u64; 4]) -> Cursor {
    Cursor { hash: root, reference_length: 32, nibble: 0 }
}

// Decode the outer list, checking minimal RLP and its exact endpoint.
fn list_start<let B: u32>(node: EncodedNode<B>) -> u32 {
    std::static_assert(B >= 3, "Node capacity must be at least 3");
    assert(node.length <= B, "Node length exceeds capacity");
    assert(node.length >= 2, "Node is not an RLP list");
    let first = node.bytes[0];
    assert(first >= 0xc0, "Node is not an RLP list");
    assert(first <= 0xf9, "Node is not an RLP list");
    let (offset, length) = if first <= 0xf7 {
        (1, (first - 0xc0) as u32)
    } else if first == 0xf8 {
        let length = node.bytes[1] as u32;
        assert(length >= 56, "Noncanonical RLP list length");
        (2, length)
    } else {
        let length = node.bytes[1] as u32 * 256 + node.bytes[2] as u32;
        assert(length >= 256, "Noncanonical RLP list length");
        (3, length)
    };
    assert_eq(offset + length, node.length, "Node length differs from its RLP length");
    offset
}

fn read_reference<let B: u32, let INLINE: u32>(
    bytes: [u8; B],
    offset: u32,
    length: u32,
) -> [u64; 4] {
    assert(offset + length <= B, "Child reference exceeds node capacity");
    let mut result = [0; 4];
    for i in 0..4 {
        for j in 0..8 {
            if (INLINE == 0) | (8 * i + j < length) {
                result[i] += (bytes[offset + 8 * i + j] as u64) << (8 * j) as u64;
            }
        }
    }
    result
}

fn child_reference<let INLINE: u32>(prefix: u8, offset: u32) -> (u32, u32) {
    if (INLINE == 1) & (prefix >= 0xc0) {
        assert(prefix <= 0xde, "Embedded node must be shorter than 32 bytes");
        (offset, (prefix - 0xc0) as u32 + 1)
    } else {
        assert_eq(prefix, 0xa0, "Expected child hash");
        (offset + 1, 32)
    }
}

fn check_reference<let B: u32, let INLINE: u32>(cursor: Cursor, bytes: [u8; B], length: u32) {
    if (INLINE == 1) & (cursor.reference_length < 32) {
        assert(cursor.reference_length > 0, "Missing child");
        assert_eq(
            length,
            cursor.reference_length,
            "Embedded node differs from its parent reference",
        );
        for i in 0..31 {
            if i < length {
                let expected = (cursor.hash[i / 8] >> ((i % 8) * 8) as u64) as u8;
                assert_eq(bytes[i], expected, "Embedded node differs from its parent reference");
            }
        }
    } else {
        assert_eq(cursor.reference_length, 32, "Expected child hash");
        assert_eq(
            keccak256_limbs(bytes, length),
            cursor.hash,
            "Node hash differs from its parent reference",
        );
    }
}

// Structural parsing is shared by selected-child traversal and cached batches.
fn extension_header<let B: u32>(node: EncodedNode<B>, start: u32) -> (u32, u32) {
    let prefix = node.bytes[start];
    let (path_start, path_length) = if prefix <= 0x7f {
        (start, 1)
    } else {
        assert(prefix >= 0x82, "Malformed extension path");
        assert(prefix <= 0xa0, "Malformed extension path");
        (start + 1, (prefix - 0x80) as u32)
    };
    (path_start, path_length)
}

fn match_extension<let B: u32>(
    bytes: [u8; B],
    path_start: u32,
    path_length: u32,
    mut nibble: u32,
    nibbles: [u8; 64],
) -> u32 {
    let flag = bytes[path_start];
    assert(flag <= 0x1f, "Expected extension, not leaf");
    let odd = flag >= 0x10;
    let consumed = 2 * (path_length - 1) + odd as u32;
    assert(consumed > 0, "Empty extension");
    // An extension must leave at least one nibble for its child.
    assert(nibble + consumed < 64, "Extension path is longer than the key");
    if odd {
        assert_eq(flag & 15, nibbles[nibble], "Extension path differs from the key");
        nibble += 1;
    } else {
        assert_eq(flag, 0, "Nonzero extension path padding");
    }
    for j in 0..31 {
        if j + 1 < path_length {
            let byte = bytes[path_start + j + 1];
            assert_eq(byte >> 4, nibbles[nibble], "Extension path differs from the key");
            assert_eq(byte & 15, nibbles[nibble + 1], "Extension path differs from the key");
            nibble += 2;
        }
    }
    nibble
}

fn extension_reference<let B: u32, let INLINE: u32>(
    node: EncodedNode<B>,
    path_start: u32,
    path_length: u32,
) -> (u32, u32) {
    let child_prefix = path_start + path_length;
    let (offset, length) = child_reference::<INLINE>(node.bytes[child_prefix], child_prefix);
    assert_eq(offset + length, node.length, "Extension node has trailing bytes");
    (offset, length)
}

fn branch_layout<let B: u32, let INLINE: u32, let ALL: u32>(
    node: EncodedNode<B>,
    start: u32,
    selected: u32,
) -> ([u32; 16], [u32; 16]) {
    let mut offsets = [0; 16];
    let mut lengths = [0; 16];
    let mut pos = start;
    for j in 0..16 {
        let prefix = node.bytes[pos];
        let (offset, length) = if prefix == 0x80 {
            (pos + 1, 0)
        } else {
            child_reference::<INLINE>(prefix, pos)
        };
        if ALL == 1 {
            offsets[j] = offset;
            lengths[j] = length;
        } else if j == selected {
            assert(length > 0, "Missing child");
            offsets[0] = offset;
            lengths[0] = length;
        }
        pos = offset + length;
    }
    assert_eq(node.bytes[pos], 0x80, "Malformed branch node");
    assert_eq(pos + 1, node.length, "Malformed branch node");
    (offsets, lengths)
}

// Parse one already authenticated node. The batch verifier reuses this exact
// parser after binding its node-table digest or embedded reference.
pub(crate) fn advance_node<let B: u32, let INLINE: u32>(
    node: EncodedNode<B>,
    mut cursor: Cursor,
    nibbles: [u8; 64],
) -> Cursor {
    let start = list_start(node);
    assert(cursor.nibble < 64, "Path is longer than the key");
    let (child_offset, child_length) = if node.is_extension {
        let (path_start, path_length) = extension_header(node, start);
        cursor.nibble =
            match_extension(node.bytes, path_start, path_length, cursor.nibble, nibbles);
        extension_reference::<B, INLINE>(node, path_start, path_length)
    } else {
        let selected = nibbles[cursor.nibble] as u32;
        let (offsets, lengths) = branch_layout::<B, INLINE, 0>(node, start, selected);
        cursor.nibble += 1;
        (offsets[0], lengths[0])
    };
    cursor.hash = read_reference::<B, INLINE>(node.bytes, child_offset, child_length);
    cursor.reference_length = if INLINE == 0 { 32 } else { child_length };
    cursor
}

/// Verify up to D internal nodes. B can be any bound >= 3 (532 covers all
/// hash-only Ethereum branch nodes). Choose 135, 271, 407, or 532 to cap
/// Keccak at 1, 2, 3, or 4 permutations respectively.
/// The actual length is private; unused entries do not affect the result.
fn verify_section<let D: u32, let B: u32, let INLINE: u32>(
    nodes: [EncodedNode<B>; D],
    count: u32,
    mut cursor: Cursor,
    key: [u8; 32],
) -> Cursor {
    assert(count <= D, "Node count exceeds capacity");
    assert(cursor.nibble <= 64, "Cursor is beyond the key");
    let nibbles: [u8; 64] = to_nibbles(key);
    for i in 0..D {
        // Keccak uses no_predicates internally, so even an inactive call must
        // receive an in-range length. Preserve arbitrary unused node padding.
        let hash_length = if i < count { nodes[i].length } else { 0 };
        if i < count {
            let node = nodes[i];
            // One shared Keccak circuit for both node kinds. Sibling payloads
            // are already authenticated by this hash; do not decode/re-encode them.
            check_reference::<B, INLINE>(cursor, node.bytes, hash_length);
            cursor = advance_node::<B, INLINE>(node, cursor, nibbles);
        }
    }
    cursor
}

/// Verify a section with full hashed/embedded child support.
/// `cursor` must come from new_cursor(authenticated_root) or from the previous
/// section of the same path. `key` is the hashed trie key (keccak(slot) for
/// storage, keccak(address) for accounts); use the same key in every section and
/// in the leaf verifier. The result is only meaningful as input to the next
/// section or to a leaf verifier.
pub fn verify_path_section<let D: u32, let B: u32>(
    nodes: [EncodedNode<B>; D],
    count: u32,
    cursor: Cursor,
    key: [u8; 32],
) -> Cursor {
    verify_section::<D, B, 1>(nodes, count, cursor, key)
}

/// Smaller specialization. Rejects embedded children anywhere in the section,
/// including siblings, so a small embedded sibling leaf on the path makes it fail.
/// The cursor and key obligations of verify_path_section apply.
pub fn verify_hashed_path_section<let D: u32, let B: u32>(
    nodes: [EncodedNode<B>; D],
    count: u32,
    cursor: Cursor,
    key: [u8; 32],
) -> Cursor {
    verify_section::<D, B, 0>(nodes, count, cursor, key)
}

/// Finish an inclusion proof of a nonzero storage value. `key` is keccak(slot),
/// the same key that every section of this path used. `cursor` must be the output
/// of the last section that started at new_cursor(authenticated storage root);
/// a cursor from any other source proves nothing.
/// A zero value requires a non-membership proof (see the absence module).
pub fn verify_storage_leaf(cursor: Cursor, key: [u8; 32], slot: StorageSlot) {
    assert(cursor.nibble <= 64, "Path is longer than the key");
    assert_canonical_slot(slot);
    let (bytes, length) = encode_slot_unchecked(slot, cursor.nibble, key);
    check_reference::<70, 1>(cursor, bytes, length);
}

// General and hash-only public APIs specialize the same complete storage path.
fn verify_storage_mode<let D: u32, let B: u32, let INLINE: u32>(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<B>; D],
    count: u32,
) {
    let key = keccak256(slot_key, 32);
    let cursor = verify_section::<D, B, INLINE>(nodes, count, new_cursor(root), key);
    verify_storage_leaf(cursor, key, value);
}

/// Prove a nonzero slot value against an authenticated account storage root.
/// The slot is its raw 32-byte Ethereum storage key, before the secure-trie hash.
pub fn verify_storage<let D: u32, let B: u32>(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<B>; D],
    count: u32,
) {
    verify_storage_mode::<D, B, 1>(root, slot_key, value, nodes, count);
}

/// Smaller storage verifier for proofs whose internal children are all hashes.
/// Rejects unsupported embedded references rather than silently accepting them.
pub fn verify_storage_hashed<let D: u32, let B: u32>(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<B>; D],
    count: u32,
) {
    verify_storage_mode::<D, B, 0>(root, slot_key, value, nodes, count);
}

/// Finish an account proof. The address must be bound by the calling circuit.
/// `cursor` must be the output of the last section that started at
/// new_cursor(authenticated state root) and walked keccak(account.address). The
/// leaf check recomputes that key, but it does not check the sections' key.
pub fn verify_account_leaf(cursor: Cursor, account: Account) {
    assert_eq(cursor.reference_length, 32, "Expected child hash");
    assert(cursor.nibble <= 64, "Path is longer than the key");
    assert_canonical_account(account);
    let key = keccak256(account.address, 20);
    assert_eq(
        compute_account_hash_unchecked(account, cursor.nibble, key),
        cursor.hash,
        "Account leaf hash differs from its parent reference",
    );
}

/// Prove an account against an authenticated Ethereum state root.
pub fn verify_account<let D: u32, let B: u32>(
    state_root: [u64; 4],
    account: Account,
    nodes: [EncodedNode<B>; D],
    count: u32,
) {
    let key = keccak256(account.address, 20);
    let cursor = verify_hashed_path_section(nodes, count, new_cursor(state_root), key);
    verify_account_leaf(cursor, account);
}

/// Compose private account and storage inclusion checks. Account and storage
/// paths have independent capacity parameters.
pub fn verify_l1_storage<let AD: u32, let AB: u32, let SD: u32, let SB: u32>(
    state_root: [u64; 4],
    account: Account,
    account_nodes: [EncodedNode<AB>; AD],
    account_count: u32,
    slot_key: [u8; 32],
    value: StorageSlot,
    storage_nodes: [EncodedNode<SB>; SD],
    storage_count: u32,
) {
    verify_account(state_root, account, account_nodes, account_count);
    verify_storage(
        account.storage_hash,
        slot_key,
        value,
        storage_nodes,
        storage_count,
    );
}

// Private constrained metadata. Never accept this as an unconstrained witness.
pub(crate) struct NodeLayout {
    pub path_start: u32,
    pub path_length: u32,
    pub offsets: [u32; 16],
    pub lengths: [u32; 16],
}

pub(crate) fn empty_layout() -> NodeLayout {
    NodeLayout { path_start: 0, path_length: 0, offsets: [0; 16], lengths: [0; 16] }
}

pub(crate) fn parse_layout<let B: u32>(node: EncodedNode<B>) -> NodeLayout {
    let start = list_start(node);
    let mut layout = empty_layout();
    if node.is_extension {
        let (path_start, path_length) = extension_header(node, start);
        let (offset, length) = extension_reference::<B, 1>(node, path_start, path_length);
        layout.path_start = path_start;
        layout.path_length = path_length;
        layout.offsets[0] = offset;
        layout.lengths[0] = length;
    } else {
        let (offsets, lengths) = branch_layout::<B, 1, 1>(node, start, 0);
        layout.offsets = offsets;
        layout.lengths = lengths;
    }
    layout
}

pub(crate) fn advance_parsed<let B: u32>(
    node: EncodedNode<B>,
    layout: NodeLayout,
    mut cursor: Cursor,
    nibbles: [u8; 64],
) -> Cursor {
    assert(cursor.nibble < 64, "Path is longer than the key");
    let selected = if node.is_extension {
        cursor.nibble = match_extension(
            node.bytes,
            layout.path_start,
            layout.path_length,
            cursor.nibble,
            nibbles,
        );
        0
    } else {
        let selected = nibbles[cursor.nibble] as u32;
        cursor.nibble += 1;
        selected
    };
    let length = layout.lengths[selected];
    assert(length > 0, "Missing child");
    cursor.hash = read_reference::<B, 1>(node.bytes, layout.offsets[selected], length);
    cursor.reference_length = length;
    cursor
}
