//! Canonical bounded RLP framing. Container children must be checked by the caller.
//! Length arithmetic uses u64 before narrowing to u32 circuit-buffer offsets.
pub struct Item {
    pub payload: u32,
    pub length: u32,
    pub end: u32,
    pub is_list: bool,
}

pub fn read_item<let N: u32>(bytes: [u8; N], position: u32, limit: u32) -> Item {
    assert(limit <= N);
    assert(position < limit);
    let prefix = bytes[position];
    let is_list = prefix >= 0xc0;
    let mut start = position as u64;
    let mut length: u64 = 1;
    if prefix >= 0x80 {
        let base: u8 = if is_list { 0xc0 } else { 0x80 };
        let tag = prefix - base;
        start += 1;
        if tag <= 55 {
            length = tag as u64;
        } else {
            let width = (tag - 55) as u32;
            // Buffers and offsets are u32. Larger length fields cannot fit.
            assert(width <= 4);
            assert(start + width as u64 <= limit as u64);
            assert(bytes[start as u32] != 0, "Nonminimal RLP length");
            length = 0;
            for i in 0..4 {
                if i < width {
                    length = length * 256 + bytes[(start + i as u64) as u32] as u64;
                }
            }
            start += width as u64;
            assert(length >= 56, "Long RLP used for short payload");
        }
    }
    let end = start + length;
    assert(end <= limit as u64, "RLP item exceeds its container");
    if (prefix == 0x81) & (length == 1) {
        assert(bytes[start as u32] >= 0x80, "Nonminimal single-byte RLP");
    }
    Item { payload: start as u32, length: length as u32, end: end as u32, is_list }
}

pub fn read_uint64<let N: u32>(bytes: [u8; N], item: Item) -> u64 {
    assert(!item.is_list);
    assert(item.length <= 8);
    assert(item.payload as u64 + item.length as u64 <= N as u64);
    let mut result: u64 = 0;
    for i in 0..8 {
        if i < item.length {
            let byte = bytes[item.payload + i];
            if i == 0 {
                assert(byte != 0, "Nonminimal RLP integer");
            }
            result = result * 256 + byte as u64;
        }
    }
    result
}

mod tests {
    use super::{read_item, read_uint64};

    unconstrained fn witness<T>(x: T) -> T {
        x
    }

    // A 64-byte runtime buffer that starts with `prefix`; the rest is zero.
    fn buffer(prefix: [u8; 3]) -> [u8; 64] {
        let mut bytes = [0; 64];
        for i in 0..3 {
            bytes[i] = prefix[i];
        }
        // Safety: test input; the constrained parser under test checks it.
        unsafe {
            witness(bytes)
        }
    }

    fn shape(prefix: [u8; 3]) -> (u32, u32, u32, bool) {
        let item = read_item(buffer(prefix), 0, 64);
        (item.payload, item.length, item.end, item.is_list)
    }

    #[test]
    fn reads_each_canonical_form() {
        assert_eq(shape([0x7f, 0, 0]), (0, 1, 1, false));
        assert_eq(shape([0x80, 0, 0]), (1, 0, 1, false));
        assert_eq(shape([0x81, 0x80, 0]), (1, 1, 2, false));
        assert_eq(shape([0xb7, 0, 0]), (1, 55, 56, false));
        assert_eq(shape([0xb8, 56, 0]), (2, 56, 58, false));
        assert_eq(shape([0xc0, 0, 0]), (1, 0, 1, true));
        assert_eq(shape([0xf7, 0, 0]), (1, 55, 56, true));
        assert_eq(shape([0xf8, 56, 0]), (2, 56, 58, true));
    }

    #[test(should_fail_with = "Nonminimal single-byte RLP")]
    fn rejects_prefixed_single_byte_below_0x80() {
        let _ = shape([0x81, 0x7f, 0]);
    }

    #[test(should_fail_with = "Long RLP used for short payload")]
    fn rejects_long_form_for_55_bytes() {
        let _ = shape([0xb8, 55, 0]);
    }

    #[test(should_fail_with = "Nonminimal RLP length")]
    fn rejects_length_with_leading_zero() {
        let _ = shape([0xb9, 0, 56]);
    }

    #[test(should_fail_with = "RLP item exceeds its container")]
    fn rejects_item_past_its_limit() {
        let _ = read_item(buffer([0x83, 1, 2]), 0, 3);
    }

    #[test]
    fn reads_minimal_integers() {
        let bytes = buffer([0x82, 0x01, 0x00]);
        assert_eq(read_uint64(bytes, read_item(bytes, 0, 64)), 256);
        let bytes = buffer([0x80, 0, 0]);
        assert_eq(read_uint64(bytes, read_item(bytes, 0, 64)), 0);
    }

    #[test(should_fail_with = "Nonminimal RLP integer")]
    fn rejects_integer_with_leading_zero() {
        let bytes = buffer([0x82, 0x00, 0x01]);
        let _ = read_uint64(bytes, read_item(bytes, 0, 64));
    }
}
