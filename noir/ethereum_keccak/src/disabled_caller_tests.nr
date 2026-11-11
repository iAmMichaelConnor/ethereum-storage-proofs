// Both public functions must stay satisfiable under a runtime-disabled caller whatever
// length it carries, while an active call with message_size > N still fails. N = 100 is
// a one-block capacity and N = 300 a multi-block one; the upstream hashing kernel is
// #[no_predicates]. Inputs go through black_box, so `enabled` and
// `length` are runtime witnesses, not constants the compiler could fold.
use crate::{keccak256, keccak256_limbs};
use std::hint::black_box;

fn hash_if(enabled: bool, length: u32) -> [u64; 4] {
    let mut a = [0; 100];
    let mut b = [0; 300];
    for i in 0..300 {
        b[i] = (i % 251) as u8;
        if i < 100 {
            a[i] = (i % 251) as u8;
        }
    }
    let (a, b, enabled, length) = black_box((a, b, enabled, length));
    let mut out = [0; 4];
    if enabled {
        let h1 = keccak256(a, length);
        let h2 = keccak256_limbs(a, length);
        let h3 = keccak256(b, length);
        let h4 = keccak256_limbs(b, length);
        out = [h2[0] + (h1[0] as u64), h4[0] + (h3[0] as u64), h2[1], h4[1]];
    }
    out
}

#[test]
fn disabled_call_accepts_length_within_capacity() {
    assert_eq(hash_if(false, 50), [0; 4]);
}

#[test]
fn disabled_call_accepts_length_above_one_block_capacity() {
    assert_eq(hash_if(false, 101), [0; 4]);
}

#[test]
fn disabled_call_accepts_length_above_multi_block_capacity() {
    assert_eq(hash_if(false, 301), [0; 4]);
}

#[test]
fn disabled_call_accepts_maximum_length() {
    assert_eq(hash_if(false, 4294967295), [0; 4]);
}

#[test]
fn enabled_call_accepts_length_within_capacity() {
    let _ = hash_if(true, 50);
}

#[test]
fn enabled_call_accepts_length_at_capacity() {
    let _ = hash_if(true, 100);
}

#[test(should_fail_with = "Keccak message_size exceeds input capacity")]
fn enabled_call_rejects_length_above_one_block_capacity() {
    let _ = hash_if(true, 101);
}

#[test(should_fail_with = "Keccak message_size exceeds input capacity")]
fn enabled_call_rejects_length_above_multi_block_capacity() {
    let _ = hash_if(true, 301);
}
