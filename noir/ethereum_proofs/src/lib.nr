//! Ethereum account and nonzero storage inclusion using canonical MPT paths.
pub use ethereum_types as types;
pub mod proof;
pub mod batch;
pub use ethereum_keccak as keccak;
pub mod encoding;
mod account_hash;
mod bytes_sink;
mod slot_hash;
mod utils;
pub mod absence;
pub mod events;
pub mod receipts;
pub mod rlp;
pub mod slot_key;
pub use proof::{
    verify_account as verify_account_proof, verify_l1_storage as verify_account_and_storage_proof,
    verify_storage as verify_storage_proof,
};
mod slot_key_vectors;
mod precondition_tests;
mod benchmarks;
mod balance_tests;
