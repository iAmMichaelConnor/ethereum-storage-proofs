use super::{Account, StorageSlot};
use std::hint::black_box;

fn slot(value: [u8; 32], length: u8) -> StorageSlot {
    StorageSlot { value: black_box(value), value_length: black_box(length) }
}

fn account(balance: [u8; 32], balance_length: u8, nonce: [u8; 8], nonce_length: u8) -> Account {
    Account {
        balance: black_box(balance),
        balance_length: black_box(balance_length),
        nonce: black_box(nonce),
        nonce_length: black_box(nonce_length),
        address: [0; 20],
        storage_hash: [0; 4],
        code_hash: [0; 4],
    }
}

fn prefix(value: u8, length: u32) -> [u8; 32] {
    let mut bytes = [0; 32];
    for i in 0..32 {
        if i < length {
            bytes[i] = value;
        }
    }
    bytes
}

#[test]
fn empty_and_one_byte_values() {
    let zero = slot([0; 32], 0);
    assert(zero.is_zero());
    assert_eq(zero.to_field(), 0);
    assert_eq(zero.to_u128(), 0);
    assert_eq(zero.to_u128_pair(), (0, 0));
    let one = slot(prefix(255, 1), 1);
    assert(!one.is_zero());
    assert_eq(one.to_field(), 255);
    assert_eq(one.to_u128(), 255);
    assert_eq(one.to_u128_pair(), (0, 255));
    let a = account([0; 32], 0, [0; 8], 0);
    assert_eq(a.balance_as_field(), 0);
    assert_eq(a.nonce_as_u64(), 0);
    let a = account(prefix(255, 1), 1, [255, 0, 0, 0, 0, 0, 0, 0], 1);
    assert_eq(a.balance_as_field(), 255);
    assert_eq(a.nonce_as_u64(), 255);
}

#[test]
fn eight_sixteen_and_thirty_one_byte_maxima() {
    let eight = slot(prefix(255, 8), 8);
    assert_eq(eight.to_field(), 18446744073709551615);
    assert_eq(eight.to_u128(), 18446744073709551615);
    assert_eq(eight.to_u128_pair(), (0, 18446744073709551615));
    assert_eq(account(prefix(255, 8), 8, [255; 8], 8).nonce_as_u64(), 18446744073709551615);
    let sixteen = slot(prefix(255, 16), 16);
    assert_eq(sixteen.to_u128(), 0xffffffffffffffffffffffffffffffff);
    assert_eq(sixteen.to_field(), 0xffffffffffffffffffffffffffffffff);
    assert_eq(sixteen.to_u128_pair(), (0, 0xffffffffffffffffffffffffffffffff));
    let thirty_one = slot(prefix(255, 31), 31);
    assert_eq(
        thirty_one.to_field(),
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
    );
    assert_eq(
        thirty_one.to_u128_pair(),
        (0xffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff),
    );
    assert_eq(account(prefix(255, 31), 31, [0; 8], 0).balance_as_field(), thirty_one.to_field());
}

#[test]
fn full_width_split_and_seventeen_byte_alignment() {
    assert_eq(
        slot([255; 32], 32).to_u128_pair(),
        (0xffffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff),
    );
    let mut value = [0; 32];
    value[0] = 1;
    value[15] = 2;
    value[16] = 3;
    value[31] = 4;
    assert_eq(
        slot(value, 32).to_u128_pair(),
        (0x01000000000000000000000000000002, 0x03000000000000000000000000000004),
    );
    let mut seventeen = [0; 32];
    seventeen[0] = 1;
    seventeen[16] = 2;
    assert_eq(slot(seventeen, 17).to_u128_pair(), (1, 2));
    assert_eq(slot(seventeen, 17).to_field(), 340282366920938463463374607431768211458);
}

#[test(should_fail_with = "quantity exceeds u128")]
fn seventeen_bytes_reject_u128_cast() {
    let _ = slot(prefix(1, 17), 17).to_u128();
}
#[test(should_fail_with = "quantity exceeds u128")]
fn full_width_rejects_u128_cast() {
    let _ = slot([255; 32], 32).to_u128();
}
#[test(should_fail_with = "quantity length exceeds capacity")]
fn nonce_oversize_rejects() {
    let _ = account([0; 32], 0, [1; 8], 9).nonce_as_u64();
}
#[test(should_fail_with = "quantity length exceeds capacity")]
fn slot_length_oversize_rejects() {
    let _ = slot([1; 32], 33).to_u128_pair();
}
#[test(should_fail_with = "quantity length exceeds capacity")]
fn balance_length_oversize_rejects() {
    let _ = account([1; 32], 33, [0; 8], 0).balance_as_field();
}
#[test(should_fail_with = "quantity has a leading zero")]
fn zero_encoded_as_one_byte_rejects() {
    let _ = slot([0; 32], 1).is_zero();
}
#[test(should_fail_with = "quantity has a leading zero")]
fn u128_leading_zero_rejects() {
    let mut v = [0; 32];
    v[1] = 1;
    let _ = slot(v, 2).to_u128();
}
#[test(should_fail_with = "quantity has a leading zero")]
fn nonce_leading_zero_rejects() {
    let _ = account([0; 32], 0, [0, 1, 0, 0, 0, 0, 0, 0], 2).nonce_as_u64();
}
#[test(should_fail_with = "quantity has a leading zero")]
fn balance_leading_zero_rejects() {
    let _ = account([0; 32], 1, [0; 8], 0).balance_as_field();
}
#[test(should_fail_with = "quantity has nonzero padding")]
fn zero_with_padding_rejects() {
    let mut v = [0; 32];
    v[31] = 1;
    let _ = slot(v, 0).is_zero();
}
#[test(should_fail_with = "quantity has nonzero padding")]
fn field_padding_rejects() {
    let _ = slot(prefix(1, 2), 1).to_field();
}
#[test(should_fail_with = "quantity has nonzero padding")]
fn pair_padding_rejects() {
    let _ = slot([1; 32], 31).to_u128_pair();
}
#[test(should_fail_with = "quantity has nonzero padding")]
fn nonce_padding_rejects() {
    let _ = account([0; 32], 0, [1, 0, 0, 0, 0, 0, 0, 1], 1).nonce_as_u64();
}
#[test(should_fail_with = "quantity has nonzero padding")]
fn balance_padding_rejects() {
    let _ = account(prefix(1, 2), 1, [0; 8], 0).balance_as_field();
}
#[test(should_fail_with = "quantity has nonzero padding")]
fn u128_padding_rejects() {
    let _ = slot(prefix(1, 2), 1).to_u128();
}
