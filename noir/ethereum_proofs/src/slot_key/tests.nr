use crate::slot_key_vectors::{
    ADDRESS_001122_SLOT5, ARRAY_SLOT7_INDEX0_STRIDE1, ARRAY_SLOT7_INDEX2_STRIDE3,
    ARRAY_SLOT7_MAX_PRODUCT, MAPPING_ONE_SLOT_ZERO, NESTED_1_2_SLOT5,
};
use super::{
    add_offset, add_offset_u64, address_mapping_slot, array_element_slot, mapping_slot,
    nested_mapping_slot, value_slot,
};
use std::hint::black_box;

#[test]
fn value_slots_are_big_endian_words() {
    assert(value_slot(black_box(0)) == [0; 32]);
    let mut expected = [0; 32];
    for i in 28..32 {
        expected[i] = 255;
    }
    assert(value_slot(black_box(0xffff_ffff)) == expected);
    expected[28] = 0x12;
    expected[29] = 0x34;
    expected[30] = 0x56;
    expected[31] = 0x78;
    assert(value_slot(black_box(0x1234_5678)) == expected);
}

#[test]
fn mapping_matches_independent_keccak_vector() {
    assert(mapping_slot(black_box(value_slot(1)), black_box(0)) == MAPPING_ONE_SLOT_ZERO);
    assert(mapping_slot(black_box(value_slot(0)), black_box(1)) != MAPPING_ONE_SLOT_ZERO);
}

#[test]
fn address_mapping_uses_left_padding() {
    let address = black_box([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00, 0x11, 0x22, 0x33,
    ]);
    assert(address_mapping_slot(address, black_box(5)) == ADDRESS_001122_SLOT5);
    let mut padded = [0; 32];
    let mut right_padded = [0; 32];
    for i in 0..20 {
        padded[12 + i] = address[i];
        right_padded[i] = address[i];
    }
    assert(mapping_slot(padded, 5) == ADDRESS_001122_SLOT5);
    assert(mapping_slot(right_padded, 5) != ADDRESS_001122_SLOT5);
}

#[test]
fn nested_mapping_preserves_outer_inner_order() {
    assert(
        nested_mapping_slot(
            black_box(value_slot(1)),
            black_box(value_slot(2)),
            black_box(5),
        )
            == NESTED_1_2_SLOT5,
    );
    assert(
        nested_mapping_slot(
            black_box(value_slot(2)),
            black_box(value_slot(1)),
            black_box(5),
        )
            != NESTED_1_2_SLOT5,
    );
}

#[test]
fn array_whole_slot_vectors() {
    assert(
        array_element_slot(black_box(7), black_box(0), black_box(1)) == ARRAY_SLOT7_INDEX0_STRIDE1,
    );
    assert(
        array_element_slot(black_box(7), black_box(2), black_box(3)) == ARRAY_SLOT7_INDEX2_STRIDE3,
    );
}

#[test]
fn array_product_is_widened_before_multiplication() {
    let location = array_element_slot(black_box(7), black_box(0xffff_ffff), black_box(0xffff_ffff));
    assert(location == ARRAY_SLOT7_MAX_PRODUCT);
    assert(location != add_offset(black_box(ARRAY_SLOT7_INDEX0_STRIDE1), 1));
}

#[test(should_fail_with = "array stride must be positive")]
fn zero_array_stride_rejected() {
    let _ = array_element_slot(black_box(7), black_box(0), black_box(0));
}

#[test]
fn offset_zero_and_max_u32() {
    assert(add_offset(black_box([255; 32]), black_box(0)) == [255; 32]);
    assert(add_offset(black_box([0; 32]), black_box(0xffff_ffff)) == value_slot(0xffff_ffff));
}

#[test]
fn offset_carries_through_every_byte() {
    let mut input = [255; 32];
    input[0] = 7;
    let mut expected = [0; 32];
    expected[0] = 8;
    assert(add_offset(black_box(input), black_box(1)) == expected);
}

#[test]
fn full_u64_offset_carries_without_truncation() {
    let mut input = [255; 32];
    input[0] = 254;
    let mut expected = [0; 32];
    expected[0] = 255;
    for i in 24..32 {
        expected[i] = 255;
    }
    expected[31] = 254;
    assert(add_offset_u64(black_box(input), black_box(0xffff_ffff_ffff_ffff)) == expected);
}

#[test(should_fail_with = "slot key overflow")]
fn overflowing_u32_offset_rejected() {
    let _ = add_offset(black_box([255; 32]), black_box(1));
}

#[test(should_fail_with = "slot key overflow")]
fn overflowing_u64_offset_rejected() {
    let _ = add_offset_u64(black_box([255; 32]), black_box(0xffff_ffff_ffff_ffff));
}

// add_offset behind a runtime branch: a carry out of the top byte must not constrain a
// disabled caller; an active caller rejects it, and carries through every byte.
fn offset_if(enabled: bool, key: [u8; 32], offset: u32) -> [u8; 32] {
    let (enabled, key, offset) = std::hint::black_box((enabled, key, offset));
    let mut out = [0; 32];
    if enabled {
        out = add_offset(key, offset);
    }
    out
}

#[test]
fn add_offset_overflow_ignored_when_disabled() {
    assert_eq(offset_if(false, [255; 32], 1), [0; 32]);
}

#[test(should_fail_with = "slot key overflow")]
fn add_offset_overflow_rejected_when_active() {
    let _ = offset_if(true, [255; 32], 1);
}

#[test]
fn add_offset_zero_to_maximum_word() {
    assert_eq(offset_if(true, [255; 32], 0), [255; 32]);
}

#[test]
fn add_offset_carries_through_every_byte() {
    let mut key = [255; 32];
    key[0] = 7;
    let mut expected = [0; 32];
    expected[0] = 8;
    assert_eq(offset_if(true, key, 1), expected);
}
