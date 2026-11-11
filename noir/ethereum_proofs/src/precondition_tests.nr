// Tests for the preconditions of the public low-level helpers.
// Inputs pass through an unconstrained identity so that the checks are not constant-folded.
use crate::{
    encoding::{compute_account_hash, encode_slot},
    keccak::keccak256_limbs,
    receipts::ReceiptView,
    types::{Account, StorageSlot},
};

unconstrained fn witness<T>(x: T) -> T {
    x
}

fn key() -> [u8; 32] {
    let mut key = [0; 32];
    for i in 0..32 {
        key[i] = ((7 * i) % 256) as u8;
    }
    key
}

fn slot() -> StorageSlot {
    let mut value = [0; 32];
    value[0] = 1;
    value[1] = 2;
    value[2] = 3;
    StorageSlot { value, value_length: 3 }
}

fn account() -> Account {
    let mut nonce = [0; 8];
    nonce[0] = 5;
    let mut balance = [0; 32];
    balance[0] = 9;
    Account {
        nonce,
        balance,
        address: [1; 20],
        nonce_length: 1,
        balance_length: 1,
        storage_hash: [1, 2, 3, 4],
        code_hash: [5, 6, 7, 8],
    }
}

fn encode_at(slot: StorageSlot, nibble: u32) -> ([u8; 70], u32) {
    // Safety: the test witnesses are checked by the constrained encoder.
    let (slot, nibble, key) = unsafe { witness((slot, nibble, key())) };
    encode_slot(slot, nibble, key)
}

fn account_hash_at(account: Account, nibble: u32) -> [u64; 4] {
    // Safety: the test witnesses are checked by the constrained hash.
    let (account, nibble, key) = unsafe { witness((account, nibble, key())) };
    compute_account_hash(account, nibble, key)
}

#[test]
fn encode_slot_accepts_every_leaf_depth_and_zeroes_the_tail() {
    for nibble in [0, 1, 63, 64] {
        let (bytes, length) = encode_at(slot(), nibble);
        for i in 0..70 {
            if i >= length {
                assert_eq(bytes[i], 0);
            }
        }
        assert(keccak256_limbs(bytes, length) != [0; 4]);
    }
    let mut full = [0xff; 32];
    full[0] = 0x80;
    let _ = encode_at(StorageSlot { value: full, value_length: 32 }, 0);
}

#[test]
fn compute_account_hash_accepts_canonical_accounts() {
    let _ = account_hash_at(account(), 0);
    let _ = account_hash_at(account(), 64);
    let mut empty = account();
    empty.nonce = [0; 8];
    empty.balance = [0; 32];
    empty.nonce_length = 0;
    empty.balance_length = 0;
    let _ = account_hash_at(empty, 63);
}

// A u8 cast of the nibble would alias n = 320, 576, ... to n = 64.
#[test(should_fail_with = "Leaf nibble index exceeds the 64-nibble key")]
fn encode_slot_rejects_nibble_320() {
    let _ = encode_at(slot(), 320);
}

#[test(should_fail_with = "Leaf nibble index exceeds the 64-nibble key")]
fn encode_slot_rejects_nibble_4294967104() {
    let _ = encode_at(slot(), 4294967104);
}

#[test(should_fail_with = "Leaf nibble index exceeds the 64-nibble key")]
fn encode_slot_rejects_nibble_65() {
    let _ = encode_at(slot(), 65);
}

#[test(should_fail_with = "Leaf nibble index exceeds the 64-nibble key")]
fn compute_account_hash_rejects_nibble_320() {
    let _ = account_hash_at(account(), 320);
}

#[test(should_fail_with = "Leaf nibble index exceeds the 64-nibble key")]
fn compute_account_hash_rejects_nibble_4294967104() {
    let _ = account_hash_at(account(), 4294967104);
}

// The encoder never reads bytes past value_length, so without the padding check a
// padded struct would encode and hash like the real leaf 0x010203.
#[test(should_fail_with = "Nonzero value padding")]
fn encode_slot_rejects_padded_value() {
    let mut padded = slot();
    for i in 3..32 {
        padded.value[i] = 0xff;
    }
    let _ = encode_at(padded, 64);
}

#[test(should_fail_with = "Noncanonical storage integer")]
fn encode_slot_rejects_leading_zero() {
    let mut value = [0; 32];
    value[1] = 1;
    let _ = encode_at(StorageSlot { value, value_length: 2 }, 0);
}

#[test(should_fail_with = "Zero storage value has no leaf")]
fn encode_slot_rejects_zero_value() {
    let _ = encode_at(StorageSlot { value: [0; 32], value_length: 0 }, 0);
}

#[test(should_fail_with = "Storage value exceeds 32 bytes")]
fn encode_slot_rejects_overlong_value() {
    let mut value = [0xff; 32];
    value[0] = 1;
    let _ = encode_at(StorageSlot { value, value_length: 33 }, 0);
}

#[test(should_fail_with = "Nonzero nonce padding")]
fn compute_account_hash_rejects_padded_nonce() {
    let mut padded = account();
    padded.nonce[7] = 0xff;
    let _ = account_hash_at(padded, 64);
}

#[test(should_fail_with = "Nonzero balance padding")]
fn compute_account_hash_rejects_padded_balance() {
    let mut padded = account();
    padded.balance[31] = 0xff;
    let _ = account_hash_at(padded, 64);
}

#[test(should_fail_with = "Noncanonical account balance")]
fn compute_account_hash_rejects_leading_zero_balance() {
    let mut padded = account();
    padded.balance[0] = 0;
    padded.balance[1] = 9;
    padded.balance_length = 2;
    let _ = account_hash_at(padded, 0);
}

#[test(should_fail_with = "Noncanonical account nonce")]
fn compute_account_hash_rejects_leading_zero_nonce() {
    let mut padded = account();
    padded.nonce[0] = 0;
    padded.nonce[1] = 5;
    padded.nonce_length = 2;
    let _ = account_hash_at(padded, 0);
}

fn view(has_post_state: bool, status: bool) -> ReceiptView {
    // Safety: the views are inputs to the helpers under test.
    unsafe {
        witness(
            ReceiptView {
                receipt_type: 0,
                has_post_state,
                status,
                post_state: [if has_post_state { 7 } else { 0 }; 32],
                cumulative_gas_used: 21000,
                logs_start: 0,
                logs_end: 0,
                log_count: 0,
            },
        )
    }
}

// status = false is shared by failed and pre-Byzantium receipts.
#[test]
fn receipt_outcome_helpers_separate_pre_byzantium_receipts() {
    assert(view(false, true).succeeded());
    assert(!view(false, true).failed());
    assert(view(false, false).failed());
    assert(!view(false, false).succeeded());
    let historical = view(true, false);
    assert(!historical.status);
    assert(!historical.succeeded());
    assert(!historical.failed());
}
