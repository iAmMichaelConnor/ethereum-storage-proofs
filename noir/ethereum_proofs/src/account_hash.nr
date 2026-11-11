use super::{
    bytes_sink::{BytesChecker, BytesSink, BytesWriter},
    keccak::{keccak256_limbs, KeccakHasher},
    types::Account,
    utils::{get_low_nibble, get_rlp_length, runtime_loop, unroll_loop},
};

global ACCOUNT_RLP_MAX_LENGTH: u32 = 148;

#[inline_always]
fn rlp_encode_to_sink<S: BytesSink>(
    account: Account,
    start_nibble_idx: u32,
    trie_key: [u8; 32],
    sink: &mut S,
) {
    let mut current_nibble_idx = start_nibble_idx;

    let first_key_byte = if current_nibble_idx % 2 == 0 {
        0x20
    } else {
        let first_byte = trie_key[(current_nibble_idx / 2) as u32];
        current_nibble_idx += 1;
        0x30 + get_low_nibble(first_byte)
    };

    let key_length = 32 - (current_nibble_idx as u8) / 2 + 1;

    let leaf_key_rlp_length = get_rlp_length(first_key_byte, key_length);
    assert(account.nonce_length <= 8);

    let leaf_value_rlp_data_length = get_rlp_length(account.balance[0], account.balance_length)
        + get_rlp_length(account.nonce[0], account.nonce_length)
        + 33 // code
        + 33; // storage

    let leaf_rlp_total_length = leaf_key_rlp_length + leaf_value_rlp_data_length + 2 + 2;
    sink.add_byte(0xf8);
    sink.add_byte(leaf_rlp_total_length);

    // key
    if (key_length == 1) & (first_key_byte <= 127) {
        sink.add_byte(first_key_byte);
    } else {
        sink.add_byte(0x80 + key_length);
        sink.add_byte(first_key_byte);
        let start_byte_idx = current_nibble_idx / 2;
        let end_byte_idx = start_byte_idx + ((key_length - 1) as u32);

        runtime_loop!(
            quote { i },
            quote { start_byte_idx },
            quote { end_byte_idx },
            quote { trie_key.len() },
            quote {
                sink.add_byte(trie_key[i]);
            },
        );
    }

    sink.add_byte(0xb8);
    sink.add_byte(leaf_value_rlp_data_length + 2);

    sink.add_byte(0xf8);
    sink.add_byte(leaf_value_rlp_data_length);

    // nonce
    if account.nonce_length == 0 {
        sink.add_byte(0x80);
    } else if (account.nonce_length == 1) & (account.nonce[0] <= 127) {
        sink.add_byte(account.nonce[0]);
    } else {
        sink.add_byte(0x80 + account.nonce_length);
        runtime_loop!(
            quote { i },
            quote { 0 },
            quote { (account.nonce_length as u32) },
            quote { 32 },
            quote {
                sink.add_byte(account.nonce[i]);
            },
        );
    }

    // balance
    if account.balance_length == 0 {
        sink.add_byte(0x80);
    } else if (account.balance_length == 1) & (account.balance[0] <= 127) {
        sink.add_byte(account.balance[0]);
    } else {
        sink.add_byte(0x80 + account.balance_length);
        runtime_loop!(
            quote { i },
            quote { 0 },
            quote { (account.balance_length as u32) },
            quote { 32 },
            quote {
                sink.add_byte(account.balance[i]);
            },
        );
    }

    // storage hash
    sink.add_byte(0xa0);
    unroll_loop!(
        0_u32,
        4_u32,
        |i| {
            quote {
                sink.add_u64(account.storage_hash[$i]);
            }
        },
    );

    // code hash
    sink.add_byte(0xa0);
    unroll_loop!(
        0_u32,
        4_u32,
        |i| {
            quote {
                sink.add_u64(account.code_hash[$i]);
            }
        },
    );
}

unconstrained fn rlp_encode_unconstrained(
    account: Account,
    start_nibble_idx: u32,
    trie_key: [u8; 32],
) -> ([u8; ACCOUNT_RLP_MAX_LENGTH], u32) {
    let mut writer = BytesWriter::new();
    rlp_encode_to_sink(account, start_nibble_idx, trie_key, &mut writer);
    writer.finish()
}

/// Rejects account fields that no canonical trie leaf contains: lengths above
/// 8 (nonce) or 32 (balance), a leading zero byte, or nonzero bytes past a length.
pub(crate) fn assert_canonical_account(account: Account) {
    assert(account.nonce_length <= 8, "Account nonce exceeds 8 bytes");
    assert(account.balance_length <= 32, "Account balance exceeds 32 bytes");
    if account.nonce_length > 0 {
        assert(account.nonce[0] != 0, "Noncanonical account nonce");
    }
    if account.balance_length > 0 {
        assert(account.balance[0] != 0, "Noncanonical account balance");
    }
    for i in 0..8 {
        if i >= account.nonce_length as u32 {
            assert_eq(account.nonce[i], 0, "Nonzero nonce padding");
        }
    }
    for i in 0..32 {
        if i >= account.balance_length as u32 {
            assert_eq(account.balance[i], 0, "Nonzero balance padding");
        }
    }
}

/// Internal hash. The caller must check `start_nibble_idx <= 64` and
/// assert_canonical_account.
pub(crate) fn compute_account_hash_unchecked(
    account: Account,
    start_nibble_idx: u32,
    trie_key: [u8; 32],
) -> [u64; 4] {
    if std::runtime::is_unconstrained() {
        let mut hasher: KeccakHasher = KeccakHasher::new();
        rlp_encode_to_sink(account, start_nibble_idx, trie_key, &mut hasher);
        hasher.finish_to_limbs()
    } else {
        // Safety: Constrained below
        let (bytes, length) =
            unsafe { rlp_encode_unconstrained(account, start_nibble_idx, trie_key) };

        let mut checker = BytesChecker::new(bytes, length);
        rlp_encode_to_sink(account, start_nibble_idx, trie_key, &mut checker);
        checker.finish();

        keccak256_limbs(bytes, length)
    }
}

/// Keccak of the RLP account leaf at `start_nibble_idx` of `trie_key`
/// (keccak(address)). This computes a hash only: it does not prove inclusion.
/// Preconditions, enforced here: `start_nibble_idx <= 64`; nonce and balance are
/// canonical big-endian integers (no leading zero byte, zero padding).
pub fn compute_account_hash(
    account: Account,
    start_nibble_idx: u32,
    trie_key: [u8; 32],
) -> [u64; 4] {
    assert(start_nibble_idx <= 64, "Leaf nibble index exceeds the 64-nibble key");
    assert_canonical_account(account);
    compute_account_hash_unchecked(account, start_nibble_idx, trie_key)
}
