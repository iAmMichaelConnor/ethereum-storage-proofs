// Benchmark entry points: one exported function per producer shape. Each verifies an
// opening and returns the domain-separated statement that a recursive consumer binds.
// `nargo export` compiles each to its own program for the gates report; the ABI tests
// in this crate call the same functions.
use crate::batch::{IndexedPath, verify_storage_batch};
use crate::keccak::keccak256;
use crate::proof::{
    EncodedNode, new_cursor, verify_account_leaf, verify_hashed_path_section, verify_path_section,
    verify_storage_leaf,
};
use crate::recursive_proof::absence::{
    account_absent_statement, AccountAbsentClaim, l1_zero_statement, L1ZeroClaim,
    storage_zero_statement, StorageZeroClaim,
};
use crate::recursive_proof::{
    account_statement, AccountClaim, assert_value_at_least, batch_storage_statement,
    BatchStorageClaim, l1_statement, L1Claim, storage_statement, StorageClaim, threshold_statement,
    ThresholdClaim, value_word,
};
use crate::recursive_proof::receipts::{
    event_statement, EventClaim, receipt_statement, ReceiptClaim,
};
use crate::types::{Account, StorageSlot};

#[export]
pub(crate) fn storage_small(
    claim: StorageClaim,
    value: StorageSlot,
    storage_count: u32,
    storage_node0: EncodedNode<271>,
    storage_node1: EncodedNode<271>,
    storage_node2: EncodedNode<271>,
    storage_node3: EncodedNode<271>,
) -> Field {
    assert_eq(value_word(value), claim.value, "Value differs from the claim");
    let storage_key = keccak256(claim.slot_key, 32);
    let mut storage_cursor = new_cursor(claim.storage_root);
    assert(storage_count <= 4, "Node count exceeds capacity");
    storage_cursor = verify_hashed_path_section(
        [storage_node0],
        if storage_count > 0 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_hashed_path_section(
        [storage_node1],
        if storage_count > 1 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_hashed_path_section(
        [storage_node2],
        if storage_count > 2 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_hashed_path_section(
        [storage_node3],
        if storage_count > 3 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    verify_storage_leaf(storage_cursor, storage_key, value);
    storage_statement(claim)
}

#[export]
pub(crate) fn storage_d8(
    claim: StorageClaim,
    value: StorageSlot,
    storage_count: u32,
    storage_node0: EncodedNode<532>,
    storage_node1: EncodedNode<532>,
    storage_node2: EncodedNode<532>,
    storage_node3: EncodedNode<532>,
    storage_node4: EncodedNode<532>,
    storage_node5: EncodedNode<532>,
    storage_node6: EncodedNode<532>,
    storage_node7: EncodedNode<532>,
) -> Field {
    assert_eq(value_word(value), claim.value, "Value differs from the claim");
    let storage_key = keccak256(claim.slot_key, 32);
    let mut storage_cursor = new_cursor(claim.storage_root);
    assert(storage_count <= 8, "Node count exceeds capacity");
    storage_cursor = verify_path_section(
        [storage_node0],
        if storage_count > 0 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node1],
        if storage_count > 1 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node2],
        if storage_count > 2 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node3],
        if storage_count > 3 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node4],
        if storage_count > 4 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node5],
        if storage_count > 5 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node6],
        if storage_count > 6 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node7],
        if storage_count > 7 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    verify_storage_leaf(storage_cursor, storage_key, value);
    storage_statement(claim)
}

#[export]
pub(crate) fn storage_deep(
    claim: StorageClaim,
    value: StorageSlot,
    storage_count: u32,
    storage_node0: EncodedNode<532>,
    storage_node1: EncodedNode<532>,
    storage_node2: EncodedNode<532>,
    storage_node3: EncodedNode<532>,
    storage_node4: EncodedNode<532>,
    storage_node5: EncodedNode<532>,
    storage_node6: EncodedNode<532>,
    storage_node7: EncodedNode<532>,
    storage_node8: EncodedNode<532>,
    storage_node9: EncodedNode<532>,
    storage_node10: EncodedNode<532>,
    storage_node11: EncodedNode<532>,
    storage_node12: EncodedNode<532>,
    storage_node13: EncodedNode<532>,
    storage_node14: EncodedNode<532>,
    storage_node15: EncodedNode<532>,
) -> Field {
    assert_eq(value_word(value), claim.value, "Value differs from the claim");
    let storage_key = keccak256(claim.slot_key, 32);
    let mut storage_cursor = new_cursor(claim.storage_root);
    assert(storage_count <= 16, "Node count exceeds capacity");
    storage_cursor = verify_path_section(
        [storage_node0],
        if storage_count > 0 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node1],
        if storage_count > 1 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node2],
        if storage_count > 2 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node3],
        if storage_count > 3 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node4],
        if storage_count > 4 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node5],
        if storage_count > 5 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node6],
        if storage_count > 6 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node7],
        if storage_count > 7 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node8],
        if storage_count > 8 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node9],
        if storage_count > 9 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node10],
        if storage_count > 10 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node11],
        if storage_count > 11 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node12],
        if storage_count > 12 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node13],
        if storage_count > 13 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node14],
        if storage_count > 14 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node15],
        if storage_count > 15 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    verify_storage_leaf(storage_cursor, storage_key, value);
    storage_statement(claim)
}

#[export]
pub(crate) fn threshold_d8(
    claim: ThresholdClaim,
    value: StorageSlot,
    storage_count: u32,
    storage_node0: EncodedNode<532>,
    storage_node1: EncodedNode<532>,
    storage_node2: EncodedNode<532>,
    storage_node3: EncodedNode<532>,
    storage_node4: EncodedNode<532>,
    storage_node5: EncodedNode<532>,
    storage_node6: EncodedNode<532>,
    storage_node7: EncodedNode<532>,
) -> Field {
    assert_value_at_least(value_word(value), claim.minimum);
    let storage_key = keccak256(claim.slot_key, 32);
    let mut storage_cursor = new_cursor(claim.storage_root);
    assert(storage_count <= 8, "Node count exceeds capacity");
    storage_cursor = verify_path_section(
        [storage_node0],
        if storage_count > 0 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node1],
        if storage_count > 1 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node2],
        if storage_count > 2 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node3],
        if storage_count > 3 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node4],
        if storage_count > 4 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node5],
        if storage_count > 5 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node6],
        if storage_count > 6 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node7],
        if storage_count > 7 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    verify_storage_leaf(storage_cursor, storage_key, value);
    threshold_statement(claim)
}

#[export]
pub(crate) fn account_d8(
    claim: AccountClaim,
    account: Account,
    account_count: u32,
    account_node0: EncodedNode<532>,
    account_node1: EncodedNode<532>,
    account_node2: EncodedNode<532>,
    account_node3: EncodedNode<532>,
    account_node4: EncodedNode<532>,
    account_node5: EncodedNode<532>,
    account_node6: EncodedNode<532>,
    account_node7: EncodedNode<532>,
) -> Field {
    assert_eq(account.address, claim.address, "Address differs from the claim");
    let mut account_cursor = new_cursor(claim.state_root);
    assert_eq(account.storage_hash, claim.storage_root, "Storage root differs from the claim");
    let account_key = keccak256(claim.address, 20);
    assert(account_count <= 8, "Node count exceeds capacity");
    account_cursor = verify_hashed_path_section(
        [account_node0],
        if account_count > 0 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node1],
        if account_count > 1 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node2],
        if account_count > 2 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node3],
        if account_count > 3 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node4],
        if account_count > 4 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node5],
        if account_count > 5 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node6],
        if account_count > 6 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node7],
        if account_count > 7 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    verify_account_leaf(account_cursor, account);
    account_statement(claim)
}

#[export]
pub(crate) fn l1_d8(
    claim: L1Claim,
    value: StorageSlot,
    account: Account,
    account_count: u32,
    storage_count: u32,
    account_node0: EncodedNode<532>,
    account_node1: EncodedNode<532>,
    account_node2: EncodedNode<532>,
    account_node3: EncodedNode<532>,
    account_node4: EncodedNode<532>,
    account_node5: EncodedNode<532>,
    account_node6: EncodedNode<532>,
    account_node7: EncodedNode<532>,
    storage_node0: EncodedNode<532>,
    storage_node1: EncodedNode<532>,
    storage_node2: EncodedNode<532>,
    storage_node3: EncodedNode<532>,
    storage_node4: EncodedNode<532>,
    storage_node5: EncodedNode<532>,
    storage_node6: EncodedNode<532>,
    storage_node7: EncodedNode<532>,
) -> Field {
    assert_eq(value_word(value), claim.value, "Value differs from the claim");
    assert_eq(account.address, claim.address, "Address differs from the claim");
    let mut account_cursor = new_cursor(claim.state_root);
    let account_key = keccak256(claim.address, 20);
    assert(account_count <= 8, "Node count exceeds capacity");
    account_cursor = verify_hashed_path_section(
        [account_node0],
        if account_count > 0 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node1],
        if account_count > 1 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node2],
        if account_count > 2 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node3],
        if account_count > 3 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node4],
        if account_count > 4 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node5],
        if account_count > 5 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node6],
        if account_count > 6 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node7],
        if account_count > 7 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    verify_account_leaf(account_cursor, account);
    let storage_key = keccak256(claim.slot_key, 32);
    let mut storage_cursor = new_cursor(account.storage_hash);
    assert(storage_count <= 8, "Node count exceeds capacity");
    storage_cursor = verify_path_section(
        [storage_node0],
        if storage_count > 0 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node1],
        if storage_count > 1 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node2],
        if storage_count > 2 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node3],
        if storage_count > 3 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node4],
        if storage_count > 4 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node5],
        if storage_count > 5 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node6],
        if storage_count > 6 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node7],
        if storage_count > 7 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    verify_storage_leaf(storage_cursor, storage_key, value);
    l1_statement(claim)
}

#[export]
pub(crate) fn l1_mixed(
    claim: L1Claim,
    value: StorageSlot,
    account: Account,
    account_count: u32,
    storage_count: u32,
    account_node0: EncodedNode<532>,
    account_node1: EncodedNode<532>,
    account_node2: EncodedNode<532>,
    account_node3: EncodedNode<532>,
    account_node4: EncodedNode<532>,
    account_node5: EncodedNode<532>,
    account_node6: EncodedNode<532>,
    storage_node0: EncodedNode<532>,
    storage_node1: EncodedNode<532>,
    storage_node2: EncodedNode<532>,
    storage_node3: EncodedNode<532>,
    storage_node4: EncodedNode<532>,
    storage_node5: EncodedNode<407>,
    storage_node6: EncodedNode<271>,
) -> Field {
    assert_eq(value_word(value), claim.value, "Value differs from the claim");
    assert_eq(account.address, claim.address, "Address differs from the claim");
    let mut account_cursor = new_cursor(claim.state_root);
    let account_key = keccak256(claim.address, 20);
    assert(account_count <= 7, "Node count exceeds capacity");
    account_cursor = verify_hashed_path_section(
        [account_node0],
        if account_count > 0 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node1],
        if account_count > 1 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node2],
        if account_count > 2 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node3],
        if account_count > 3 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node4],
        if account_count > 4 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node5],
        if account_count > 5 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    account_cursor = verify_hashed_path_section(
        [account_node6],
        if account_count > 6 { 1 } else { 0 },
        account_cursor,
        account_key,
    );
    verify_account_leaf(account_cursor, account);
    let storage_key = keccak256(claim.slot_key, 32);
    let mut storage_cursor = new_cursor(account.storage_hash);
    assert(storage_count <= 7, "Node count exceeds capacity");
    storage_cursor = verify_path_section(
        [storage_node0],
        if storage_count > 0 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node1],
        if storage_count > 1 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node2],
        if storage_count > 2 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node3],
        if storage_count > 3 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node4],
        if storage_count > 4 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node5],
        if storage_count > 5 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    storage_cursor = verify_path_section(
        [storage_node6],
        if storage_count > 6 { 1 } else { 0 },
        storage_cursor,
        storage_key,
    );
    verify_storage_leaf(storage_cursor, storage_key, value);
    l1_statement(claim)
}

#[export]
pub(crate) fn batch4(
    claim: BatchStorageClaim<4>,
    values: [StorageSlot; 4],
    node_count: u32,
    nodes: [EncodedNode<135>; 3],
    paths: [IndexedPath<2>; 4],
) -> Field {
    for i in 0..4 {
        assert_eq(value_word(values[i]), claim.values[i], "Value differs from the claim");
    }
    verify_storage_batch(
        claim.storage_root,
        claim.slot_keys,
        values,
        nodes,
        node_count,
        paths,
    );
    batch_storage_statement(claim)
}

#[export]
pub(crate) fn receipt_summary(
    claim: ReceiptClaim,
    count: u32,
    leaf: [u8; 1024],
    leaf_length: u32,
    nodes: [EncodedNode<532>; 4],
) -> Field {
    let view = crate::receipts::verify_receipt::<4, 532, 1024, 3>(
        claim.receipts_root,
        claim.transaction_index,
        nodes,
        count,
        leaf,
        leaf_length,
    );
    assert_eq(view.receipt_type, claim.receipt_type, "Receipt type differs from the claim");
    assert_eq(
        view.has_post_state,
        claim.has_post_state,
        "Receipt outcome kind differs from the claim",
    );
    assert_eq(view.status, claim.status, "Receipt status differs from the claim");
    assert_eq(view.post_state, claim.post_state, "Receipt post-state differs from the claim");
    assert_eq(
        view.cumulative_gas_used,
        claim.cumulative_gas_used,
        "Receipt gas differs from the claim",
    );
    receipt_statement(claim)
}

#[export]
pub(crate) fn event(
    claim: EventClaim,
    count: u32,
    leaf: [u8; 1024],
    leaf_length: u32,
    nodes: [EncodedNode<532>; 4],
    data: [u8; 256],
) -> Field {
    let expected = crate::events::Event {
        emitter: claim.emitter,
        topics: claim.topics,
        topic_count: claim.topic_count,
        data,
        data_length: claim.data_length,
    };
    let _ = crate::events::verify_event::<4, 532, 1024, 3, 256>(
        claim.receipts_root,
        claim.transaction_index,
        nodes,
        count,
        leaf,
        leaf_length,
        claim.log_index,
        expected,
    );
    assert(claim.data_length <= 256, "Event data length exceeds capacity");
    let hash_length = if claim.data_length <= 256 {
        claim.data_length
    } else {
        0
    };
    assert_eq(
        crate::keccak::keccak256_limbs(data, hash_length),
        claim.data_hash,
        "Event data hash differs from the claim",
    );
    event_statement(claim)
}

#[export]
pub(crate) fn storage_zero(
    claim: StorageZeroClaim,
    count: u32,
    terminal: [u8; 532],
    terminal_length: u32,
    kind: u8,
    nodes: [EncodedNode<532>; 4],
) -> Field {
    crate::absence::verify_storage_zero(
        claim.storage_root,
        claim.slot_key,
        nodes,
        count,
        terminal,
        terminal_length,
        kind,
    );
    storage_zero_statement(claim)
}

#[export]
pub(crate) fn account_absent(
    claim: AccountAbsentClaim,
    count: u32,
    terminal: [u8; 532],
    terminal_length: u32,
    kind: u8,
    nodes: [EncodedNode<532>; 4],
) -> Field {
    crate::absence::verify_account_absent(
        claim.state_root,
        claim.address,
        nodes,
        count,
        terminal,
        terminal_length,
        kind,
    );
    account_absent_statement(claim)
}

#[export]
pub(crate) fn l1_zero(
    claim: L1ZeroClaim,
    count: u32,
    terminal: [u8; 532],
    terminal_length: u32,
    kind: u8,
    nodes: [EncodedNode<532>; 4],
    account: Account,
    account_count: u32,
    account_nodes: [EncodedNode<532>; 4],
) -> Field {
    assert_eq(account.address, claim.address, "Address differs from the claim");
    crate::proof::verify_account(claim.state_root, account, account_nodes, account_count);
    crate::absence::verify_storage_zero(
        account.storage_hash,
        claim.slot_key,
        nodes,
        count,
        terminal,
        terminal_length,
        kind,
    );
    l1_zero_statement(claim)
}
