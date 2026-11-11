//! Facade that re-exports the focused packages in noir/; it implements nothing itself.
//! It also holds the producer-shape benchmarks and the generated cross-package tests.
pub use ethereum_proofs::{batch, keccak, proof, types};
pub use ethereum_recursive_proofs as recursive_proof;
pub use ethereum_ssz as ssz;

pub use ethereum_proofs::events;
pub use ethereum_proofs::receipts;
pub use ethereum_proofs::rlp;

pub use ethereum_proofs::absence;
pub use ethereum_proofs::encoding::compute_account_hash;
pub use ethereum_proofs::{
    slot_key, verify_account_and_storage_proof, verify_account_proof, verify_storage_proof,
};

mod benchmarks;

// The generated tests import the low-level leaf encoders through these modules.
mod account_hash;
mod slot_hash;
mod fixtures_tests;
mod adversarial_tests;
mod ssz_tests;
mod completeness_tests;
mod batch_tests;
mod receipt_tests;
mod absence_tests;
mod empty_child_tests;
