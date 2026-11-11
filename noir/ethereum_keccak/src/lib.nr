//! Ethereum Keccak-256 (original Keccak padding `0x01 .. 0x80`, not FIPS SHA3)
//! over the first `message_size` bytes of a fixed-capacity buffer.
//!
//! `keccak256` and `keccak256_limbs` are safe to call inside a branch that is
//! disabled at run time. An active call with `message_size > N` fails.
//! `keccak256` and `keccak256_limbs` are `keccak256` and `keccak256_lanes` of
//! noir-lang/keccak256, vendored in `vendor/keccak256` (see NOTICE).
use std::hash::keccakf1600;

global BLOCK_SIZE_IN_BYTES: u32 = 136; //(1600 - BITS * 2) / WORD_SIZE;
global WORD_SIZE: u32 = 8; // Limbs are made up of u64s so 8 bytes each.
global LIMBS_PER_BLOCK: u32 = BLOCK_SIZE_IN_BYTES / WORD_SIZE;
global NUM_KECCAK_LANES: u32 = 25;

pub struct KeccakHasher {
    state: [u64; NUM_KECCAK_LANES],
    limb_index_to_write: u32,

    current_limb: u64,
    current_limb_shift: u64,
}

impl KeccakHasher {
    pub fn new() -> Self {
        Self {
            state: [0; NUM_KECCAK_LANES],
            limb_index_to_write: 0,
            current_limb: 0,
            current_limb_shift: 0,
        }
    }

    pub fn hash_bytes<let N: u32>(bytes: [u8; N], length: u32) -> [u8; 32] {
        let mut hasher = Self::new();
        for i in 0..length {
            hasher.add_byte(bytes[i]);
        }
        hasher.finish()
    }

    pub fn hash_bytes_to_limbs<let N: u32>(bytes: [u8; N], length: u32) -> [u64; 4] {
        let mut hasher = Self::new();
        for i in 0..length {
            hasher.add_byte(bytes[i]);
        }
        hasher.finish_to_limbs()
    }

    pub fn add_byte(&mut self, byte: u8) {
        let byte_as_u64 = byte as u64;
        let shifted_byte = byte_as_u64 << self.current_limb_shift;
        self.current_limb += shifted_byte;

        if self.current_limb_shift == 56 {
            self.finish_limb();
        } else {
            self.current_limb_shift += 8;
        }
    }

    pub fn add_u64(&mut self, value: u64) {
        if self.current_limb_shift == 0 {
            // Aligned case - direct write
            self.current_limb = value;
            self.finish_limb();
        } else {
            // Unaligned case - split across two limbs
            let shift = self.current_limb_shift;
            self.current_limb = self.current_limb + (value << shift);
            self.finish_limb();
            self.current_limb = value >> (64 - shift);
            self.current_limb_shift = shift;
        }
    }

    #[inline_always]
    fn finish_limb(&mut self) {
        self.state[self.limb_index_to_write] =
            self.state[self.limb_index_to_write] ^ self.current_limb;
        self.current_limb_shift = 0;
        self.current_limb = 0;
        if self.limb_index_to_write == (LIMBS_PER_BLOCK - 1) {
            self.finish_block();
        } else {
            self.limb_index_to_write += 1;
        }
    }

    #[inline_always]
    fn finish_block(&mut self) {
        self.state = keccakf1600(self.state);
        self.limb_index_to_write = 0;
    }

    #[inline_always]
    fn apply_padding(&mut self) {
        self.state[self.limb_index_to_write] = self.state[self.limb_index_to_write]
            ^ (self.current_limb + (0x01 << self.current_limb_shift));
        self.state[LIMBS_PER_BLOCK - 1] = self.state[LIMBS_PER_BLOCK - 1] ^ (0x80 << 56);
    }

    pub fn finish_to_limbs(mut self) -> [u64; 4] {
        self.apply_padding();
        self.finish_block();

        [self.state[0], self.state[1], self.state[2], self.state[3]]
    }

    pub fn finish(mut self) -> [u8; 32] {
        self.apply_padding();
        self.finish_block();
        let mut result = [0; 32];
        for i in 0..4 {
            let lane = self.state[i] as Field;
            let lane_le: [u8; 8] = lane.to_be_bytes();
            for j in 0..8 {
                result[8 * i + j] = lane_le[7 - j];
            }
        }
        result
    }
}

/// Keccak-256 digest bytes of `input[0..message_size]`.
///
/// Requires `message_size <= N` when the call is active. Under a disabled
/// caller, any `message_size` is accepted and the unused result is unspecified.
pub fn keccak256<let N: u32>(input: [u8; N], message_size: u32) -> [u8; 32] {
    ::keccak256::keccak256(input, message_size)
}

/// Keccak-256 digest of `input[0..message_size]` as four little-endian u64 lanes.
///
/// The same length rule as `keccak256` applies.
pub fn keccak256_limbs<let N: u32>(input: [u8; N], message_size: u32) -> [u64; 4] {
    ::keccak256::keccak256_lanes(input, message_size)
}

fn bytes_to_u64<let N: u32, let K: u32>(bytes: [u8; N]) -> [u64; K] {
    std::static_assert(
        K * 8 == N,
        "Invalid number of u64s for given number of bytes",
    );
    let mut result = [0; K];
    for i in 0..K {
        let mut value = 0;
        for j in 0..8 {
            let byte = bytes[i * 8 + j];
            value += byte as u64 << (8 * j) as u64;
        }
        result[i] = value;
    }
    result
}

#[test]
fn single_block_matches_reference_at_every_length() {
    let mut input = [0; 135];
    for i in 0..135 {
        input[i] = (i % 251) as u8;
    }
    for length in 0..136 {
        let reference = ::keccak256::keccak256(input, length);
        assert_eq(keccak256_limbs(input, length), bytes_to_u64(reference));
    }
}

#[test(should_fail_with = "Keccak message_size exceeds input capacity")]
fn single_block_rejects_overflow() {
    let _hash = keccak256([0; 70], 71);
}

#[test]
fn multi_block_matches_reference_at_block_boundaries() {
    let mut input = [0; 300];
    for i in 0..300 {
        input[i] = (i % 251) as u8;
    }
    for length in [0, 1, 135, 136, 137, 271, 272, 273, 300] {
        let reference = ::keccak256::keccak256(input, length);
        assert_eq(keccak256_limbs(input, length), bytes_to_u64(reference));
    }
}

#[test(should_fail_with = "Keccak message_size exceeds input capacity")]
fn multi_block_rejects_overflow() {
    let _hash = keccak256_limbs([0; 300], 301);
}
mod benchmarks;
mod disabled_caller_tests;
