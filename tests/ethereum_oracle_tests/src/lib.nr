//! Differential tests. nargo's fuzzer draws a random seed for each run of a
//! test; the oracle server (oracle_server.mjs) builds a case from it
//! with EthereumJS, and the verifier must accept the case and agree with the
//! fields the server encoded. Run them with ./run.sh. The tests
//! are unconstrained, so they execute the verifiers' Brillig form only.
use ethereum_proofs::{
    absence::verify_absence,
    events::{Event, verify_event},
    proof::{
        Cursor, EncodedNode, new_cursor, verify_account_leaf, verify_path_section,
        verify_storage_leaf,
    },
    receipts::verify_receipt,
    types::{Account, StorageSlot},
};

// Capacities, as in the server: internal nodes, bytes per node, receipt leaf
// bytes, logs per receipt and event data bytes.
global D: u32 = 8;
global B: u32 = 532;
global LEAF: u32 = 1024;
global MAX_LOGS: u32 = 3;
global DATA: u32 = 256;

pub struct StorageCase {
    root: [u64; 4],
    key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<B>; D],
    count: u32,
    terminal: [u8; B],
    terminal_length: u32,
    kind: u8,
}

pub struct AccountCase {
    account: Account,
    nibble: u32,
    hash: [u64; 4],
}

pub struct ReceiptCase {
    root: [u64; 4],
    index: u64,
    nodes: [EncodedNode<B>; D],
    count: u32,
    leaf: [u8; LEAF],
    leaf_length: u32,
    receipt_type: u8,
    has_post_state: bool,
    status: bool,
    post_state: [u8; 32],
    cumulative_gas_used: u64,
    log_count: u32,
    log_index: u32,
    event: Event<DATA>,
}

#[oracle(storage_case)]
unconstrained fn storage_case(seed: Field, absent: bool) -> StorageCase {}

#[oracle(account_case)]
unconstrained fn account_case(seed: Field) -> AccountCase {}

#[oracle(receipt_case)]
unconstrained fn receipt_case(seed: Field) -> ReceiptCase {}

// A stored value of a random raw-key trie, through its path and storage leaf.
#[test]
unconstrained fn storage_inclusion(seed: Field) {
    let c = storage_case(seed, false);
    let cursor = verify_path_section(c.nodes, c.count, new_cursor(c.root), c.key);
    verify_storage_leaf(cursor, c.key, c.value);
}

// A key that leaves a stored key of such a trie at a random nibble.
#[test]
unconstrained fn storage_absence(seed: Field) {
    let c = storage_case(seed, true);
    verify_absence(
        c.root,
        c.key,
        c.nodes,
        c.count,
        c.terminal,
        c.terminal_length,
        c.kind,
    );
}

// An account leaf at a random nibble of keccak(address).
#[test]
unconstrained fn account_leaf(seed: Field) {
    let c = account_case(seed);
    verify_account_leaf(
        Cursor::from_authenticated_parts(c.hash, 32, c.nibble),
        c.account,
    );
}

// A random receipt in a random receipts trie: its decoded fields, and one of
// its logs as an event.
#[test]
unconstrained fn receipt_and_event(seed: Field) {
    let c = receipt_case(seed);
    let view = if c.log_count == 0 {
        verify_receipt::<D, B, LEAF, MAX_LOGS>(
            c.root,
            c.index,
            c.nodes,
            c.count,
            c.leaf,
            c.leaf_length,
        )
    } else {
        verify_event::<D, B, LEAF, MAX_LOGS, DATA>(
            c.root,
            c.index,
            c.nodes,
            c.count,
            c.leaf,
            c.leaf_length,
            c.log_index,
            c.event,
        )
    };
    assert_eq(view.receipt_type, c.receipt_type);
    assert_eq(view.has_post_state, c.has_post_state);
    assert_eq(view.status, c.status);
    assert_eq(view.post_state, c.post_state);
    assert_eq(view.cumulative_gas_used, c.cumulative_gas_used);
    assert_eq(view.log_count, c.log_count);
}
