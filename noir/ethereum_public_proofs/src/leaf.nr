//! Account and storage leaves, encoded from integers so that every encoding is
//! canonical by construction.
use crate::node::split3;
use crate::sink::{chunk, hash_short, Matcher, Reference, Sink, Sponge};

/// An account as integers. `balance_high * 2^128 + balance_low` is the balance;
/// the hashes are four little-endian lanes, as everywhere in this library.
pub struct PublicAccount {
    pub address: Field,
    pub nonce: u64,
    pub balance_high: u128,
    pub balance_low: u128,
    pub storage_hash: [u64; 4],
    pub code_hash: [u64; 4],
}

impl PublicAccount {
    /// Decode `[address, nonce, balance_high, balance_low, storage_hash lanes
    /// 0-2, storage_hash lane 3, code_hash lanes 0-2, code_hash lane 3]`, where
    /// three lanes share a field as `lane0 + lane1 * 2^64 + lane2 * 2^128`.
    /// Every field must be in range, so the encoding is unique.
    pub unconstrained fn from_fields(fields: [Field; crate::ACCOUNT_FIELDS]) -> Self {
        assert(fields[0].lt(TWO_160), "Address exceeds 160 bits");
        let nonce = fields[1] as u64;
        assert_eq(nonce as Field, fields[1], "Nonce exceeds u64");
        let balance_high = fields[2] as u128;
        assert_eq(balance_high as Field, fields[2], "Balance half exceeds u128");
        let balance_low = fields[3] as u128;
        assert_eq(balance_low as Field, fields[3], "Balance half exceeds u128");
        PublicAccount {
            address: fields[0],
            nonce,
            balance_high,
            balance_low,
            storage_hash: hash_lanes(fields[4], fields[5]),
            code_hash: hash_lanes(fields[6], fields[7]),
        }
    }

    /// keccak(address) as four lanes. Fails for an address of 2^160 or more.
    pub unconstrained fn key_hash(self) -> [u64; 4] {
        let address: [u8; 20] = self.address.to_be_bytes();
        hash_short(
            [chunk(address, 0, 8), chunk(address, 8, 8), chunk(address, 16, 4)],
            20,
        )
    }
}

global TWO_160: Field = 0x10000000000000000000000000000000000000000;
global TWO_192: Field = 0x1000000000000000000000000000000000000000000000000;

unconstrained fn hash_lanes(first: Field, last: Field) -> [u64; 4] {
    assert(first.lt(TWO_192), "Hash lanes exceed 192 bits");
    let (lane0, lane1, lane2) = split3(first);
    let lane3 = last as u64;
    assert_eq(lane3 as Field, last, "Hash lane exceeds u64");
    [lane0, lane1, lane2, lane3]
}

/// Big-endian bytes of `high * 2^128 + low`.
unconstrained fn word_bytes(high: u128, low: u128) -> [u8; 32] {
    let high_bytes: [u8; 16] = (high as Field).to_be_bytes();
    let low_bytes: [u8; 16] = (low as Field).to_be_bytes();
    let mut bytes = [0; 32];
    for i in 0..16 {
        bytes[i] = high_bytes[i];
        bytes[16 + i] = low_bytes[i];
    }
    bytes
}

/// Index of the first nonzero byte, or N for zero.
unconstrained fn first_nonzero<let N: u32>(bytes: [u8; N]) -> u32 {
    let mut start = N;
    for i in 0..N {
        if (start == N) & (bytes[i] != 0) {
            start = i;
        }
    }
    start
}

/// RLP length of the minimal big-endian integer `bytes[start..]`.
unconstrained fn integer_rlp_length<let N: u32>(bytes: [u8; N], start: u32) -> u32 {
    let length = N - start;
    if (length == 0) | ((length == 1) & (bytes[N - 1] < 0x80)) {
        1
    } else {
        length + 1
    }
}

/// Append `bytes[start..]`, eight at a time.
unconstrained fn add_bytes<S: Sink, let N: u32>(bytes: [u8; N], mut start: u32, sink: &mut S) {
    while start < N {
        let n = if N - start < 8 { N - start } else { 8 };
        sink.add_chunk(chunk(bytes, start, n), n);
        start += n;
    }
}

unconstrained fn add_integer<S: Sink, let N: u32>(bytes: [u8; N], start: u32, sink: &mut S) {
    let length = N - start;
    if length == 0 {
        sink.add_chunk(0x80, 1);
    } else if (length == 1) & (bytes[N - 1] < 0x80) {
        sink.add_chunk(bytes[N - 1] as u64, 1);
    } else {
        sink.add_chunk(0x80 + length as u64, 1);
        add_bytes(bytes, start, sink);
    }
}

unconstrained fn add_lanes<S: Sink>(lanes: [u64; 4], sink: &mut S) {
    sink.add_chunk(lanes[0], 8);
    sink.add_chunk(lanes[1], 8);
    sink.add_chunk(lanes[2], 8);
    sink.add_chunk(lanes[3], 8);
}

/// Byte `index` of a key held as lanes.
#[inline_always]
unconstrained fn key_byte(key: [u64; 4], index: u32) -> u8 {
    (key[index / 8] >> ((index % 8) * 8) as u64) as u8
}

/// The leaf's compact path: its flag byte and the first key byte after it.
unconstrained fn leaf_path(key: [u64; 4], nibble: u32) -> (u8, u32) {
    if nibble % 2 == 1 {
        (0x30 + (key_byte(key, nibble / 2) & 0x0f), (nibble + 1) / 2)
    } else {
        (0x20, nibble / 2)
    }
}

unconstrained fn path_rlp_length(start: u32) -> u32 {
    let compact_length = 33 - start;
    if compact_length == 1 {
        1
    } else {
        compact_length + 1
    }
}

/// Append the path item: its RLP prefix (none for a lone flag byte, which is
/// below 0x80), the flag and the key bytes from `start`.
unconstrained fn add_path<S: Sink>(key: [u64; 4], flag: u8, start: u32, sink: &mut S) {
    let compact_length = 33 - start;
    if compact_length == 1 {
        sink.add_chunk(flag as u64, 1);
    } else {
        sink.add_chunk((0x80 + compact_length as u64) | ((flag as u64) << 8), 2);
    }
    // The key bytes from `start`: a partial first lane, then whole lanes.
    let mut lane = start / 8;
    let skip = start % 8;
    if (skip != 0) & (lane < 4) {
        sink.add_chunk(key[lane] >> (skip * 8) as u64, 8 - skip);
        lane += 1;
    }
    for i in lane..4 {
        sink.add_chunk(key[i], 8);
    }
}

unconstrained fn encode_account<S: Sink>(
    key: [u64; 4],
    nibble: u32,
    account: PublicAccount,
    sink: &mut S,
) {
    let (flag, start) = leaf_path(key, nibble);
    let nonce: [u8; 8] = (account.nonce as Field).to_be_bytes();
    let nonce_start = first_nonzero(nonce);
    let balance = word_bytes(account.balance_high, account.balance_low);
    let balance_start = first_nonzero(balance);
    // [nonce, balance, storage hash, code hash]: 68 to 108 bytes, so both the
    // account list and the leaf value string take a one-byte long-form length.
    let account_payload =
        integer_rlp_length(nonce, nonce_start) + integer_rlp_length(balance, balance_start) + 66;
    let leaf_payload = path_rlp_length(start) + account_payload + 4;
    sink.add_chunk(0xf8 | ((leaf_payload as u64) << 8), 2);
    add_path(key, flag, start, sink);
    sink.add_chunk(
        0xb8
            | ((account_payload as u64 + 2) << 8)
            | (0xf8 << 16)
            | ((account_payload as u64) << 24),
        4,
    );
    add_integer(nonce, nonce_start, sink);
    add_integer(balance, balance_start, sink);
    sink.add_chunk(0xa0, 1);
    add_lanes(account.storage_hash, sink);
    sink.add_chunk(0xa0, 1);
    add_lanes(account.code_hash, sink);
}

unconstrained fn encode_storage<S: Sink>(
    key: [u64; 4],
    nibble: u32,
    value: [u8; 32],
    value_start: u32,
    sink: &mut S,
) {
    let (flag, start) = leaf_path(key, nibble);
    // The trie stores RLP(RLP(value)); a single byte below 0x80 encodes itself
    // at both levels.
    let inner_length = integer_rlp_length(value, value_start);
    let outer_length = if inner_length == 1 {
        1
    } else {
        inner_length + 1
    };
    let payload = path_rlp_length(start) + outer_length;
    if payload <= 55 {
        sink.add_chunk(0xc0 + payload as u64, 1);
    } else {
        sink.add_chunk(0xf8 | ((payload as u64) << 8), 2);
    }
    add_path(key, flag, start, sink);
    if inner_length != 1 {
        sink.add_chunk(0x80 + inner_length as u64, 1);
    }
    add_integer(value, value_start, sink);
}

pub(crate) unconstrained fn check_account(
    reference: Reference,
    nibble: u32,
    key: [u64; 4],
    account: PublicAccount,
) {
    // An account leaf is at least 70 bytes, so it is never embedded.
    assert_eq(reference.length, 32, "Account leaf differs from its parent reference");
    let mut sponge = Sponge::new();
    encode_account(key, nibble, account, &mut sponge);
    assert_eq(sponge.finish(), reference.lanes, "Account leaf differs from its parent reference");
}

pub(crate) unconstrained fn check_storage(
    reference: Reference,
    nibble: u32,
    key: [u64; 4],
    value_high: u128,
    value_low: u128,
) {
    let value = word_bytes(value_high, value_low);
    let value_start = first_nonzero(value);
    assert(value_start < 32, "Zero storage value has no leaf");
    if reference.length == 32 {
        let mut sponge = Sponge::new();
        encode_storage(key, nibble, value, value_start, &mut sponge);
        assert_eq(
            sponge.finish(),
            reference.lanes,
            "Storage leaf differs from its parent reference",
        );
    } else {
        let mut matcher = Matcher::new(reference);
        encode_storage(key, nibble, value, value_start, &mut matcher);
        matcher.finish();
    }
}
