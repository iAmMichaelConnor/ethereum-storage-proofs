pub struct Account {
    pub nonce: [u8; 8],
    pub balance: [u8; 32],
    pub address: [u8; 20],
    pub nonce_length: u8,
    pub balance_length: u8,
    pub storage_hash: [u64; 4],
    pub code_hash: [u64; 4],
}

pub struct StorageSlot {
    pub value: [u8; 32],
    pub value_length: u8,
}

/// Decode a standalone canonical Ethereum quantity, stored left-aligned and
/// minimally encoded in big-endian order. Zero uses length zero and zero padding.
/// Each accumulator consumes at most 16 bytes, so all u128 operations are exact.
fn quantity_halves<let N: u32>(value: [u8; N], length: u8) -> (u128, u128) {
    assert(N <= 32, "quantity capacity exceeds 32 bytes");
    let len = length as u32;
    assert(len <= N, "quantity length exceeds capacity");
    if len > 0 {
        assert(value[0] != 0, "quantity has a leading zero");
    }
    let high_len = if len > 16 { len - 16 } else { 0 };
    let mut high: u128 = 0;
    let mut low: u128 = 0;
    for i in 0..N {
        if i < high_len {
            high = high * 256 + value[i] as u128;
        } else if i < len {
            low = low * 256 + value[i] as u128;
        } else {
            assert(value[i] == 0, "quantity has nonzero padding");
        }
    }
    (high, low)
}

fn quantity_field(value: [u8; 32], length: u8) -> Field {
    let (high, low) = quantity_halves(value, length);
    // Canonical bytes of -1 give p-1 for the actual native Field. Comparing
    // integer halves before field arithmetic prevents reduction modulo p.
    let max_bytes: [u8; 32] = (-1 as Field).to_be_bytes();
    let (max_high, max_low) = quantity_halves(max_bytes, 32);
    assert(
        (high < max_high) | ((high == max_high) & (low <= max_low)),
        "quantity exceeds native Field",
    );
    high as Field * 340282366920938463463374607431768211456 + low as Field
}

impl Account {
    /// Decode this account's canonical ETH balance, rejecting values >= the
    /// native Field modulus. Valid 32-byte values below that modulus are accepted.
    /// This conversion does not authenticate an account or validate other fields.
    pub fn balance_as_field(self) -> Field {
        quantity_field(self.balance, self.balance_length)
    }

    /// Decode this account's canonical nonce without truncation. This validates
    /// the nonce encoding only; authenticate the account separately.
    pub fn nonce_as_u64(self) -> u64 {
        let (_, low) = quantity_halves(self.nonce, self.nonce_length);
        // The eight-byte capacity bounds the integer to u64 before this cast.
        low as u64
    }
}

impl StorageSlot {
    /// Whether this standalone canonical quantity is zero (empty encoding).
    /// This neither proves trie absence nor authenticates the slot's storage root.
    pub fn is_zero(self) -> bool {
        let _ = quantity_halves(self.value, self.value_length);
        self.value_length == 0
    }

    /// Decode the canonical quantity as a Field, rejecting integers >= p rather
    /// than reducing them. Authenticate the storage proof separately.
    pub fn to_field(self) -> Field {
        quantity_field(self.value, self.value_length)
    }

    /// Decode the canonical quantity as u128, rejecting larger values.
    pub fn to_u128(self) -> u128 {
        assert(self.value_length <= 16, "quantity exceeds u128");
        let (_, low) = quantity_halves(self.value, self.value_length);
        low
    }

    /// Decode the full canonical 256-bit quantity as (high, low), in numerical
    /// big-endian order: value = high * 2^128 + low. Neither half is truncated.
    pub fn to_u128_pair(self) -> (u128, u128) {
        quantity_halves(self.value, self.value_length)
    }
}

mod tests;
mod reference_vectors;
mod predicate_tests;
