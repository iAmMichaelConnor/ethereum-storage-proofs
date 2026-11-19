//! Conversions from the `ethereum_proofs` input types to the packed form, for
//! Noir callers that already hold raw `eth_getProof` nodes. They only reshape
//! data; verification is what checks it. Off-chain, the TypeScript SDK's
//! `packPublicNode` and `packPublicAccount` produce the same fields.
use crate::{NODE_FIELDS, PublicAccount};
use ethereum_proofs::proof::EncodedNode;
use ethereum_types::{Account, StorageSlot};

global TWO_64: Field = 18446744073709551616;
global TWO_128: Field = 340282366920938463463374607431768211456;

/// Pack one raw node, as `eth_getProof` returns it (the layout of `node.nr`).
pub unconstrained fn pack_node<let B: u32>(node: EncodedNode<B>) -> [Field; NODE_FIELDS] {
    assert(node.length < 544, "Node exceeds capacity");
    let mut lanes: [u64; 69] = [0; 69];
    for i in 0..node.length {
        lanes[i / 8] += (node.bytes[i] as u64) << ((i % 8) * 8) as u64;
    }
    let mut packed = [0; NODE_FIELDS];
    for k in 0..NODE_FIELDS {
        packed[k] = lanes[3 * k] as Field
            + lanes[3 * k + 1] as Field * TWO_64
            + lanes[3 * k + 2] as Field * TWO_128;
    }
    packed
}

/// Big-endian `bytes[0..length]` as (high, low) 128-bit halves.
pub unconstrained fn quantity_halves<let N: u32>(bytes: [u8; N], length: u32) -> (u128, u128) {
    let mut high: u128 = 0;
    let mut low: u128 = 0;
    for i in 0..length {
        high = (high << 8) + (low >> 120);
        low = (low << 8) + bytes[i] as u128;
    }
    (high, low)
}

pub unconstrained fn pack_account(account: Account) -> PublicAccount {
    let mut address: Field = 0;
    for i in 0..20 {
        address = address * 256 + account.address[i] as Field;
    }
    let (_, nonce) = quantity_halves(account.nonce, account.nonce_length as u32);
    let (balance_high, balance_low) =
        quantity_halves(account.balance, account.balance_length as u32);
    PublicAccount {
        address,
        nonce: nonce as u64,
        balance_high,
        balance_low,
        storage_hash: account.storage_hash,
        code_hash: account.code_hash,
    }
}

/// The inverse of `PublicAccount::from_fields`.
pub unconstrained fn account_fields(account: PublicAccount) -> [Field; crate::ACCOUNT_FIELDS] {
    let s = account.storage_hash;
    let c = account.code_hash;
    [
        account.address,
        account.nonce as Field,
        account.balance_high as Field,
        account.balance_low as Field,
        s[0] as Field + s[1] as Field * TWO_64 + s[2] as Field * TWO_128,
        s[3] as Field,
        c[0] as Field + c[1] as Field * TWO_64 + c[2] as Field * TWO_128,
        c[3] as Field,
    ]
}

/// A slot value as (high, low) halves.
pub unconstrained fn slot_halves(slot: StorageSlot) -> (u128, u128) {
    quantity_halves(slot.value, slot.value_length as u32)
}
