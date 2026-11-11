// Benchmark entry points. `nargo export` compiles each to its own program for the gates report.
use crate::{verify_branch, verify_deneb_execution_anchor};

// A depth-5 SSZ branch with a runtime generalized index.
#[export]
fn ssz_branch_5(leaf: [u8; 32], branch: [[u8; 32]; 5], gindex: u64, root: [u8; 32]) {
    verify_branch(leaf, branch, gindex, root);
}

// Execution state root and block number under a Deneb beacon block root.
#[export]
fn ssz_deneb_anchor(
    beacon_root: [u8; 32],
    payload_root: [u8; 32],
    payload_branch: [[u8; 32]; 7],
    state_root: [u8; 32],
    state_branch: [[u8; 32]; 5],
    block_number: u64,
    number_branch: [[u8; 32]; 5],
) {
    verify_deneb_execution_anchor(
        beacon_root,
        payload_root,
        payload_branch,
        state_root,
        state_branch,
        block_number,
        number_branch,
    );
}
