//! Absence in Ethereum secure tries (64-nibble keys). Authenticate the root separately.
//! A terminal proves an empty branch child or a different compact path; a prefix alone never suffices.
use crate::{
    keccak::{keccak256, keccak256_limbs},
    proof::{Cursor, EncodedNode, new_cursor, verify_path_section},
};
use crate::rlp::{Item, read_item};

pub global BRANCH: u8 = 0;
pub global EXTENSION: u8 = 1;
pub global LEAF: u8 = 2;
pub global EMPTY: u8 = 3;

/// Keccak256(RLP(empty string)), four little-endian u64 lanes.
pub fn empty_root() -> [u64; 4] {
    [0xa655cc1b171fe856, 0x6ef8c092e64583ff, 0xc0ad6c991be0485b, 0x21b463e3b52f6201]
}

fn child(item: Item, start: u32) {
    if item.is_list {
        assert(item.end - start < 32, "Malformed branch child");
    } else {
        assert((item.length == 0) | (item.length == 32), "Malformed branch child");
    }
}

/// Finish at an authenticated branch, extension or leaf. `key` is already Keccak hashed.
/// The cursor must come from new_cursor(trusted_root) or verified matching path sections.
/// Sibling subtrees and the divergent leaf's value are opaque: the root must describe a valid Ethereum trie.
pub fn verify_terminal<let T: u32>(
    cursor: Cursor,
    key: [u8; 32],
    bytes: [u8; T],
    length: u32,
    kind: u8,
) {
    std::static_assert(T >= 3, "Terminal capacity must be at least 3");
    assert(cursor.nibble <= 64, "Path is longer than the key");
    assert(length <= T, "Terminal length exceeds capacity");
    assert(kind <= LEAF, "Unknown terminal kind");
    // Keep no_predicates Keccak in range even when an enclosing caller is disabled.
    let hash_length = if length <= T { length } else { 0 };
    if cursor.reference_length == 32 {
        assert_eq(
            keccak256_limbs(bytes, hash_length),
            cursor.hash,
            "Terminal hash differs from its parent reference",
        );
    } else {
        assert(
            (cursor.reference_length > 0) & (cursor.reference_length < 32),
            "Embedded terminal differs from its parent reference",
        );
        assert_eq(
            length,
            cursor.reference_length,
            "Embedded terminal differs from its parent reference",
        );
        for i in 0..31 {
            if i < length {
                assert_eq(
                    bytes[i],
                    (cursor.hash[i / 8] >> ((i % 8) * 8) as u64) as u8,
                    "Embedded terminal differs from its parent reference",
                );
            }
        }
    }
    let outer = read_item(bytes, 0, length);
    assert(outer.is_list, "Terminal is not an RLP list");
    assert_eq(outer.end, length, "Terminal length differs from its RLP length");
    if kind == BRANCH {
        assert(cursor.nibble < 64, "Branch terminal at the end of the key");
        let byte = key[cursor.nibble / 2];
        let selected = if cursor.nibble % 2 == 0 {
            byte >> 4
        } else {
            byte & 15
        };
        let mut pos = outer.payload;
        for i in 0..16 {
            let item = read_item(bytes, pos, outer.end);
            child(item, pos);
            if i == selected as u32 {
                assert(!item.is_list, "Selected branch child is not empty");
                assert_eq(item.length, 0, "Selected branch child is not empty");
            }
            pos = item.end;
        }
        let value = read_item(bytes, pos, outer.end);
        assert(!value.is_list, "Malformed branch terminal");
        assert_eq(value.length, 0, "Malformed branch terminal");
        assert_eq(value.end, outer.end, "Malformed branch terminal");
    } else {
        let path = read_item(bytes, outer.payload, outer.end);
        assert(!path.is_list, "Malformed terminal path");
        assert((path.length > 0) & (path.length <= 33), "Malformed terminal path");
        let flag = bytes[path.payload] >> 4;
        let odd = flag & 1;
        assert_eq(
            flag / 2,
            if kind == LEAF { 1 } else { 0 },
            "Terminal kind differs from its path flag",
        );
        if odd == 0 {
            assert_eq(bytes[path.payload] & 15, 0, "Malformed terminal path");
        }
        let consumed = 2 * (path.length - 1) + odd as u32;
        if kind == LEAF {
            assert_eq(cursor.nibble + consumed, 64, "Terminal path does not fit the key");
        } else {
            assert(consumed > 0, "Terminal path does not fit the key");
            assert(cursor.nibble + consumed < 64, "Terminal path does not fit the key");
        }
        let mut differs = false;
        for i in 0..64 {
            if i < consumed {
                let p = i + 2 - odd as u32;
                let b = bytes[path.payload + p / 2];
                let actual = if p % 2 == 0 { b >> 4 } else { b & 15 };
                let k = cursor.nibble + i;
                let b = key[k / 2];
                let expected = if k % 2 == 0 { b >> 4 } else { b & 15 };
                differs = differs | (actual != expected);
            }
        }
        assert(differs, "Matching path is not an absence proof");
        let value = read_item(bytes, path.end, outer.end);
        assert_eq(value.end, outer.end, "Malformed terminal value");
        if kind == LEAF {
            assert(!value.is_list, "Malformed terminal value");
            assert(value.length > 0, "Malformed terminal value");
        } else {
            child(value, path.end);
            assert(value.is_list | (value.length == 32), "Malformed terminal value");
        }
    }
}

/// General secure-trie non-inclusion. D counts matching internal nodes, excluding the terminal.
/// EMPTY requires the canonical empty root and count=0; all byte buffers are then unused.
pub fn verify_absence<let D: u32, let B: u32, let T: u32>(
    root: [u64; 4],
    key: [u8; 32],
    mut nodes: [EncodedNode<B>; D],
    count: u32,
    terminal: [u8; T],
    terminal_length: u32,
    kind: u8,
) {
    assert(kind <= EMPTY, "Unknown terminal kind");
    if kind == EMPTY {
        assert_eq(root, empty_root(), "Root is not the empty trie root");
        assert_eq(count, 0, "Empty trie has no nodes");
    } else {
        for i in 0..D {
            if i < count {
                assert(nodes[i].length <= B, "Node length exceeds capacity");
            }
            nodes[i].length = if nodes[i].length <= B {
                nodes[i].length
            } else {
                0
            };
        }
        let cursor = verify_path_section(nodes, count, new_cursor(root), key);
        verify_terminal(cursor, key, terminal, terminal_length, kind);
    }
}

/// Zero storage is absence, not a present leaf encoding zero. slot is the raw 32-byte storage key.
pub fn verify_storage_zero<let D: u32, let B: u32, let T: u32>(
    root: [u64; 4],
    slot: [u8; 32],
    nodes: [EncodedNode<B>; D],
    count: u32,
    terminal: [u8; T],
    terminal_length: u32,
    kind: u8,
) {
    verify_absence(
        root,
        keccak256(slot, 32),
        nodes,
        count,
        terminal,
        terminal_length,
        kind,
    );
}

pub fn verify_account_absent<let D: u32, let B: u32, let T: u32>(
    root: [u64; 4],
    address: [u8; 20],
    nodes: [EncodedNode<B>; D],
    count: u32,
    terminal: [u8; T],
    terminal_length: u32,
    kind: u8,
) {
    verify_absence(
        root,
        keccak256(address, 20),
        nodes,
        count,
        terminal,
        terminal_length,
        kind,
    );
}

/// Included account under a state root, followed by absence under that account's storage root.
/// An absent account uses verify_account_absent instead; this entry point requires account inclusion.
pub fn verify_l1_zero<let A: u32, let AB: u32, let D: u32, let B: u32, let T: u32>(
    state_root: [u64; 4],
    account: crate::types::Account,
    mut account_nodes: [EncodedNode<AB>; A],
    account_count: u32,
    slot: [u8; 32],
    nodes: [EncodedNode<B>; D],
    count: u32,
    terminal: [u8; T],
    terminal_length: u32,
    kind: u8,
) {
    // Keep upstream unpredicated hashing in range under a disabled caller.
    for i in 0..A {
        if i < account_count {
            assert(account_nodes[i].length <= AB, "Node length exceeds capacity");
        }
        account_nodes[i].length = if account_nodes[i].length <= AB {
            account_nodes[i].length
        } else {
            0
        };
    }
    crate::proof::verify_account(state_root, account, account_nodes, account_count);
    verify_storage_zero(
        account.storage_hash,
        slot,
        nodes,
        count,
        terminal,
        terminal_length,
        kind,
    );
}

// Terminal-kind paths (branch, extension, leaf) need trie fixtures; the generated
// absence_tests in ethereum_storage_proofs cover them. These tests pin the fixture-free empty-trie path.
mod tests {
    use crate::proof::EncodedNode;
    use super::{BRANCH, EMPTY, empty_root, verify_absence};

    unconstrained fn witness<T>(x: T) -> T {
        x
    }

    fn check(root: [u64; 4], count: u32, terminal: [u8; 3], terminal_length: u32, kind: u8) {
        let nodes: [EncodedNode<3>; 1] =
            [EncodedNode { bytes: [0; 3], length: 0, is_extension: false }];
        // Safety: test inputs; the constrained verifier under test checks them.
        let (root, count, terminal, terminal_length, kind) =
            unsafe { witness((root, count, terminal, terminal_length, kind)) };
        verify_absence(root, [7; 32], nodes, count, terminal, terminal_length, kind);
    }

    #[test]
    fn empty_trie_proves_absence_and_ignores_the_buffers() {
        check(empty_root(), 0, [0; 3], 0, EMPTY);
        check(empty_root(), 0, [0xff; 3], 0, EMPTY);
    }

    #[test(should_fail_with = "Root is not the empty trie root")]
    fn empty_kind_rejects_another_root() {
        check([1, 2, 3, 4], 0, [0; 3], 0, EMPTY);
    }

    #[test(should_fail_with = "Empty trie has no nodes")]
    fn empty_kind_rejects_a_node_count() {
        check(empty_root(), 1, [0; 3], 0, EMPTY);
    }

    // RLP("") = 0x80 hashes to the empty root, but it is not a branch, extension or leaf.
    #[test(should_fail_with = "Terminal is not an RLP list")]
    fn empty_root_preimage_is_not_a_terminal() {
        check(empty_root(), 0, [0x80, 0, 0], 1, BRANCH);
    }
}
