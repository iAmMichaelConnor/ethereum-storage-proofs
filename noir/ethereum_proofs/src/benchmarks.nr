// Benchmark entry points: one exported function per operation and capacity.
// `nargo export` compiles each to its own program for the gates report.
use crate::proof::{
    EncodedNode, new_cursor, verify_account, verify_hashed_path_section, verify_storage,
    verify_storage_hashed, verify_storage_leaf,
};
use crate::slot_key::{address_mapping_slot, mapping_slot};
use crate::types::{Account, StorageSlot};
use ethereum_keccak::keccak256;

// One storage value under a storage root, general mode (embedded children accepted).

#[export]
pub(crate) fn storage_general_d3_b135(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<135>; 3],
    count: u32,
) {
    verify_storage(root, slot_key, value, nodes, count);
}

#[export]
pub(crate) fn storage_general_d8_b532(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<532>; 8],
    count: u32,
) {
    verify_storage(root, slot_key, value, nodes, count);
}

// The same, hash-only mode (every child reference in a visited node is a hash).

#[export]
pub(crate) fn storage_hashed_d1_b532(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<532>; 1],
    count: u32,
) {
    verify_storage_hashed(root, slot_key, value, nodes, count);
}

#[export]
pub(crate) fn storage_hashed_d3_b135(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<135>; 3],
    count: u32,
) {
    verify_storage_hashed(root, slot_key, value, nodes, count);
}

#[export]
pub(crate) fn storage_hashed_d3_b532(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<532>; 3],
    count: u32,
) {
    verify_storage_hashed(root, slot_key, value, nodes, count);
}

#[export]
pub(crate) fn storage_hashed_d8_b532(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<532>; 8],
    count: u32,
) {
    verify_storage_hashed(root, slot_key, value, nodes, count);
}

// Seven hashed nodes of decreasing capacity, all used: five of 532 bytes, then 407 and 271.
#[export]
pub(crate) fn storage_mixed_d7_b532(
    root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    node0: EncodedNode<532>,
    node1: EncodedNode<532>,
    node2: EncodedNode<532>,
    node3: EncodedNode<532>,
    node4: EncodedNode<532>,
    node5: EncodedNode<407>,
    node6: EncodedNode<271>,
) {
    let key = keccak256(slot_key, 32);
    let mut cursor = new_cursor(root);
    cursor = verify_hashed_path_section([node0], 1, cursor, key);
    cursor = verify_hashed_path_section([node1], 1, cursor, key);
    cursor = verify_hashed_path_section([node2], 1, cursor, key);
    cursor = verify_hashed_path_section([node3], 1, cursor, key);
    cursor = verify_hashed_path_section([node4], 1, cursor, key);
    cursor = verify_hashed_path_section([node5], 1, cursor, key);
    cursor = verify_hashed_path_section([node6], 1, cursor, key);
    verify_storage_leaf(cursor, key, value);
}

// Solidity slot derivation from a runtime key and declaration slot.
#[export]
pub(crate) fn slot_mapping(key: [u8; 32], slot: u32) -> [u8; 32] {
    mapping_slot(key, slot)
}

// An account's ETH balance and nonce, as in the README's account example
// (two account nodes of 135 bytes).
#[export]
pub(crate) fn account_balance(
    state_root: [u64; 4],
    address: [u8; 20],
    account: Account,
    account_nodes: [EncodedNode<135>; 2],
    account_count: u32,
) -> (Field, u64) {
    assert_eq(account.address, address, "proof is for a different account");
    verify_account(state_root, account, account_nodes, account_count);
    (account.balance_as_field(), account.nonce_as_u64())
}

// An ERC-20 balance at mapping slot 9, as in the README's token example (two account
// nodes and two storage nodes of 135 bytes).
#[export]
pub(crate) fn erc20_balance(
    state_root: [u64; 4],
    token: [u8; 20],
    holder: [u8; 20],
    account: Account,
    account_nodes: [EncodedNode<135>; 2],
    account_count: u32,
    value: StorageSlot,
    storage_nodes: [EncodedNode<135>; 2],
    storage_count: u32,
) -> u128 {
    assert_eq(account.address, token, "proof is for a different account");
    verify_account(state_root, account, account_nodes, account_count);
    let key = address_mapping_slot(holder, 9);
    verify_storage(
        account.storage_hash,
        key,
        value,
        storage_nodes,
        storage_count,
    );
    value.to_u128()
}
