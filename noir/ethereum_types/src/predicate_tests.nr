// Each conversion behind a runtime branch: a malformed quantity must not constrain a
// disabled caller, and an active caller must reject it at the named check. Only the
// selected conversion's quantity is checked, so the other malformed fields must not
// leak constraints through the branches. Inputs are runtime witnesses (black_box).
use super::{Account, StorageSlot};
use std::hint::black_box;

fn convert(enabled: bool, mode: u8, value: StorageSlot, account: Account) -> [Field; 2] {
    let (enabled, mode, value, account) = black_box((enabled, mode, value, account));
    let mut out = [0; 2];
    if enabled {
        if mode == 0 {
            out[0] = value.is_zero() as Field;
        } else if mode == 1 {
            out[0] = value.to_field();
        } else if mode == 2 {
            out[0] = value.to_u128() as Field;
        } else if mode == 3 {
            let (high, low) = value.to_u128_pair();
            out = [high as Field, low as Field];
        } else if mode == 4 {
            out[0] = account.balance_as_field();
        } else {
            out[0] = account.nonce_as_u64() as Field;
        }
    }
    out
}

// Every buffer has a nonzero last byte; `length` 255 also exceeds every capacity.
fn malformed(length: u8) -> (StorageSlot, Account) {
    let mut bytes = [0; 32];
    bytes[0] = 1;
    bytes[31] = 1;
    let mut nonce = [0; 8];
    nonce[0] = 1;
    nonce[7] = 1;
    let account = Account {
        nonce,
        balance: bytes,
        address: [0; 20],
        nonce_length: length,
        balance_length: length,
        storage_hash: [0; 4],
        code_hash: [0; 4],
    };
    (StorageSlot { value: bytes, value_length: length }, account)
}

// A canonical quantity of `length` bytes, all 0xff, or 258 when `length` is 2.
fn quantity(length: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    for i in 0..32 {
        if i < length as u32 {
            bytes[i] = 0xff;
        }
    }
    if length == 2 {
        bytes[0] = 1;
        bytes[1] = 2;
    }
    bytes
}

fn valid(length: u8, nonce_length: u8) -> (StorageSlot, Account) {
    let mut nonce = [0; 8];
    for i in 0..8 {
        if i < nonce_length as u32 {
            nonce[i] = 0xff;
        }
    }
    let account = Account {
        nonce,
        balance: quantity(length),
        address: [0; 20],
        nonce_length,
        balance_length: length,
        storage_hash: [0; 4],
        code_hash: [0; 4],
    };
    (StorageSlot { value: quantity(length), value_length: length }, account)
}

#[test]
fn is_zero_ignores_length_255_when_disabled() {
    let (value, account) = malformed(255);
    assert_eq(convert(false, 0, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity length exceeds capacity")]
fn is_zero_rejects_length_255() {
    let (value, account) = malformed(255);
    let _ = convert(true, 0, value, account);
}

#[test]
fn is_zero_ignores_padding_when_disabled() {
    let (value, account) = malformed(1);
    assert_eq(convert(false, 0, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity has nonzero padding")]
fn is_zero_rejects_padding() {
    let (value, account) = malformed(1);
    let _ = convert(true, 0, value, account);
}

#[test]
fn to_field_ignores_length_255_when_disabled() {
    let (value, account) = malformed(255);
    assert_eq(convert(false, 1, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity length exceeds capacity")]
fn to_field_rejects_length_255() {
    let (value, account) = malformed(255);
    let _ = convert(true, 1, value, account);
}

#[test]
fn to_field_ignores_padding_when_disabled() {
    let (value, account) = malformed(1);
    assert_eq(convert(false, 1, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity has nonzero padding")]
fn to_field_rejects_padding() {
    let (value, account) = malformed(1);
    let _ = convert(true, 1, value, account);
}

#[test]
fn to_u128_ignores_length_255_when_disabled() {
    let (value, account) = malformed(255);
    assert_eq(convert(false, 2, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity exceeds u128")]
fn to_u128_rejects_length_255() {
    let (value, account) = malformed(255);
    let _ = convert(true, 2, value, account);
}

#[test]
fn to_u128_ignores_padding_when_disabled() {
    let (value, account) = malformed(1);
    assert_eq(convert(false, 2, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity has nonzero padding")]
fn to_u128_rejects_padding() {
    let (value, account) = malformed(1);
    let _ = convert(true, 2, value, account);
}

#[test]
fn to_u128_pair_ignores_length_255_when_disabled() {
    let (value, account) = malformed(255);
    assert_eq(convert(false, 3, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity length exceeds capacity")]
fn to_u128_pair_rejects_length_255() {
    let (value, account) = malformed(255);
    let _ = convert(true, 3, value, account);
}

#[test]
fn to_u128_pair_ignores_padding_when_disabled() {
    let (value, account) = malformed(1);
    assert_eq(convert(false, 3, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity has nonzero padding")]
fn to_u128_pair_rejects_padding() {
    let (value, account) = malformed(1);
    let _ = convert(true, 3, value, account);
}

#[test]
fn balance_as_field_ignores_length_255_when_disabled() {
    let (value, account) = malformed(255);
    assert_eq(convert(false, 4, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity length exceeds capacity")]
fn balance_as_field_rejects_length_255() {
    let (value, account) = malformed(255);
    let _ = convert(true, 4, value, account);
}

#[test]
fn balance_as_field_ignores_padding_when_disabled() {
    let (value, account) = malformed(1);
    assert_eq(convert(false, 4, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity has nonzero padding")]
fn balance_as_field_rejects_padding() {
    let (value, account) = malformed(1);
    let _ = convert(true, 4, value, account);
}

#[test]
fn nonce_as_u64_ignores_length_255_when_disabled() {
    let (value, account) = malformed(255);
    assert_eq(convert(false, 5, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity length exceeds capacity")]
fn nonce_as_u64_rejects_length_255() {
    let (value, account) = malformed(255);
    let _ = convert(true, 5, value, account);
}

#[test]
fn nonce_as_u64_ignores_padding_when_disabled() {
    let (value, account) = malformed(1);
    assert_eq(convert(false, 5, value, account), [0; 2]);
}

#[test(should_fail_with = "quantity has nonzero padding")]
fn nonce_as_u64_rejects_padding() {
    let (value, account) = malformed(1);
    let _ = convert(true, 5, value, account);
}

#[test]
fn is_zero_accepts_canonical_quantity() {
    let (value, account) = valid(0, 0);
    assert_eq(convert(true, 0, value, account), [1, 0]);
}

#[test]
fn to_field_accepts_canonical_quantity() {
    let (value, account) = valid(2, 0);
    assert_eq(convert(true, 1, value, account), [258, 0]);
}

#[test]
fn to_u128_accepts_canonical_quantity() {
    let (value, account) = valid(16, 0);
    assert_eq(convert(true, 2, value, account), [0xffffffffffffffffffffffffffffffff, 0]);
}

#[test]
fn to_u128_pair_accepts_canonical_quantity() {
    let (value, account) = valid(32, 0);
    assert_eq(
        convert(true, 3, value, account),
        [0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff],
    );
}

#[test]
fn balance_as_field_accepts_canonical_quantity() {
    let (value, account) = valid(2, 0);
    assert_eq(convert(true, 4, value, account), [258, 0]);
}

#[test]
fn nonce_as_u64_accepts_canonical_quantity() {
    let (value, account) = valid(0, 8);
    assert_eq(convert(true, 5, value, account), [0xffffffffffffffff, 0]);
}
