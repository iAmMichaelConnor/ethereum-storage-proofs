// Benchmark entry points: Keccak-256 of a runtime-length message at several capacities
// (one permutation up to 135 bytes; 532 bytes needs four).
// `nargo export` compiles each to its own program for the gates report.
use crate::keccak256;

#[export]
fn keccak256_32(input: [u8; 32], length: u32) -> [u8; 32] {
    keccak256(input, length)
}

#[export]
fn keccak256_135(input: [u8; 135], length: u32) -> [u8; 32] {
    keccak256(input, length)
}

#[export]
fn keccak256_532(input: [u8; 532], length: u32) -> [u8; 32] {
    keccak256(input, length)
}
