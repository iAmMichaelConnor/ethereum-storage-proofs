//! Solidity storage locations, encoded as big-endian 256-bit words.
//!
//! Adapted from joeandrews/noir-storage-proofs, lib/src/slot_key.nr at
//! b4792c374399d6e07f2522a36a1002a35789412c (Apache-2.0).
//! These helpers derive locations only. Callers must bind the contract, keys
//! and declaration layout, authenticate the storage proof, and separately
//! enforce array bounds. Packed values/arrays, struct layout, and the special
//! bytes/string encodings are not inferred. Addition rejects overflow rather
//! than wrapping modulo 2^256.
use crate::keccak::KeccakHasher;

/// A whole-slot declaration location. Packed members also need a byte offset.
pub fn value_slot(slot: u32) -> [u8; 32] {
    let bytes: [u8; 4] = (slot as Field).to_be_bytes();
    let mut word = [0; 32];
    for i in 0..4 {
        word[28 + i] = bytes[i];
    }
    word
}

fn mapping_word(key: [u8; 32], declaration: [u8; 32]) -> [u8; 32] {
    let mut preimage = [0; 64];
    for i in 0..32 {
        preimage[i] = key[i];
        preimage[32 + i] = declaration[i];
    }
    KeccakHasher::hash_bytes(preimage, 64)
}

/// keccak256(key || pad32(slot)). The caller supplies the exact static-key
/// encoding (including signed-key extension); dynamic bytes/string keys need
/// their distinct Solidity encoding and are not handled by this helper.
pub fn mapping_slot(key: [u8; 32], slot: u32) -> [u8; 32] {
    mapping_word(key, value_slot(slot))
}

/// An address mapping key is left-padded with twelve zero bytes.
pub fn address_mapping_slot(address: [u8; 20], slot: u32) -> [u8; 32] {
    let mut key = [0; 32];
    for i in 0..20 {
        key[12 + i] = address[i];
    }
    mapping_slot(key, slot)
}

/// m[outer][inner]: hash the outer key first, then hash inner || outer_slot.
pub fn nested_mapping_slot(outer: [u8; 32], inner: [u8; 32], slot: u32) -> [u8; 32] {
    mapping_word(inner, mapping_slot(outer, slot))
}

/// A dynamic array of whole-slot elements begins at keccak256(pad32(slot)).
/// `slots_per_element` must be positive and match the actual layout. This is
/// not a packed-array derivation and does not check index against array length.
pub fn array_element_slot(slot: u32, index: u32, slots_per_element: u32) -> [u8; 32] {
    assert(slots_per_element > 0, "array stride must be positive");
    // Widen before multiplying. The complete u32*u32 product is <2^64,
    // including products above 2^32; no intermediate truncation is permitted.
    let offset = (index as u64) * (slots_per_element as u64);
    add_offset_u64(KeccakHasher::hash_bytes(value_slot(slot), 32), offset)
}

/// Add an explicit whole-slot member offset with full 256-bit carry checking.
pub fn add_offset(key: [u8; 32], offset: u32) -> [u8; 32] {
    add_offset_u64(key, offset as u64)
}

fn add_offset_u64(key: [u8; 32], offset: u64) -> [u8; 32] {
    let mut out = key;
    let mut carry = offset;
    for i in 0..32 {
        let index = 31 - i;
        let sum = (out[index] as u64) + (carry & 0xff);
        out[index] = (sum & 0xff) as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    assert(carry == 0, "slot key overflow");
    out
}

mod tests;
