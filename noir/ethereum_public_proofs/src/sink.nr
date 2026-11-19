//! Byte sinks that the leaf encoders stream into: a Keccak-256 sponge that
//! takes up to eight bytes per call, or a comparison against an embedded
//! (shorter than 32 bytes) reference.
use std::hash::keccakf1600;

pub(crate) trait Sink {
    /// Append the low `n` bytes of `value` (1 to 8), least significant first.
    /// The bytes of `value` above `n` must be zero.
    fn add_chunk(&mut self, value: u64, n: u32);
}

/// A child reference: a 32-byte hash (`length == 32`), or the RLP bytes of an
/// embedded node (`length < 32`). Both are stored as four little-endian lanes.
pub(crate) struct Reference {
    pub(crate) lanes: [u64; 4],
    pub(crate) length: u32,
}

/// Byte `index` of four little-endian lanes.
#[inline_always]
pub(crate) fn lane_byte(lanes: [u64; 4], index: u32) -> u8 {
    (lanes[index / 8] >> ((index % 8) * 8) as u64) as u8
}

/// Keccak-256 over chunks.
pub(crate) struct Sponge {
    state: [u64; 25],
    lane: u32,
    pending: u64,
    filled: u32,
}

impl Sponge {
    pub(crate) unconstrained fn new() -> Self {
        Self { state: [0; 25], lane: 0, pending: 0, filled: 0 }
    }

    pub(crate) unconstrained fn finish(mut self) -> [u64; 4] {
        self.state[self.lane] ^= self.pending | (1 << (self.filled * 8) as u64);
        self.state[16] ^= 0x80 << 56;
        let state = keccakf1600(self.state);
        [state[0], state[1], state[2], state[3]]
    }
}

impl Sink for Sponge {
    #[inline_always]
    fn add_chunk(&mut self, value: u64, n: u32) {
        let total = self.filled + n;
        let shift = (self.filled * 8) as u64;
        let lane = if self.filled == 0 {
            value
        } else {
            self.pending | (value << shift)
        };
        if total < 8 {
            self.pending = lane;
            self.filled = total;
        } else {
            self.state[self.lane] ^= lane;
            if self.lane == 16 {
                self.state = keccakf1600(self.state);
                self.lane = 0;
            } else {
                self.lane += 1;
            }
            self.pending = if self.filled == 0 {
                0
            } else {
                value >> (64 - shift)
            };
            self.filled = total - 8;
        }
    }
}

/// Checks that the streamed bytes are exactly the embedded reference's bytes.
pub(crate) struct Matcher {
    reference: Reference,
    index: u32,
}

impl Matcher {
    pub(crate) unconstrained fn new(reference: Reference) -> Self {
        Self { reference, index: 0 }
    }

    pub(crate) unconstrained fn finish(self) {
        assert_eq(
            self.index,
            self.reference.length,
            "Embedded node differs from its parent reference",
        );
    }
}

impl Sink for Matcher {
    fn add_chunk(&mut self, value: u64, n: u32) {
        for i in 0..n {
            let expected = lane_byte(self.reference.lanes, self.index);
            assert(
                self.index < self.reference.length,
                "Embedded node differs from its parent reference",
            );
            assert_eq(
                (value >> (8 * i) as u64) as u8,
                expected,
                "Embedded node differs from its parent reference",
            );
            self.index += 1;
        }
    }
}

/// Keccak-256 of at most 135 bytes held as little-endian lanes, `length` bytes
/// long. Lanes past the message must be zero.
#[inline_always]
pub(crate) unconstrained fn hash_short<let N: u32>(lanes: [u64; N], length: u32) -> [u64; 4] {
    let mut state = [0; 25];
    for i in 0..N {
        state[i] = lanes[i];
    }
    state[length / 8] ^= 1 << ((length % 8) * 8) as u64;
    state[16] ^= 0x80 << 56;
    let state = keccakf1600(state);
    [state[0], state[1], state[2], state[3]]
}

/// Big-endian bytes `bytes[start..start + n]` (n at most 8) as a chunk.
#[inline_always]
pub(crate) unconstrained fn chunk<let N: u32>(bytes: [u8; N], start: u32, n: u32) -> u64 {
    let mut value = 0;
    for j in 0..n {
        value |= (bytes[start + j] as u64) << (8 * j) as u64;
    }
    value
}

/// Keccak-256 of 32 bytes, as lanes.
pub(crate) unconstrained fn hash_word(bytes: [u8; 32]) -> [u64; 4] {
    hash_short(
        [chunk(bytes, 0, 8), chunk(bytes, 8, 8), chunk(bytes, 16, 8), chunk(bytes, 24, 8)],
        32,
    )
}
