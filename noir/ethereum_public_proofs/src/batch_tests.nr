use crate::{
    NODE_FIELDS, PublicAccount, StorageProof, verify_account_and_storage_batch,
    verify_storage_batch,
};

// EthereumJS secure trie for slots 1 and 14 with values 11 and 22. Their
// hashes share one nibble, so both paths traverse the extension and branch,
// then select different child hashes from the branch.
global STORAGE_ROOT: [u64; 4] =
    [0xb4c0e72670047e3c, 0x54cdbbe567d5884d, 0x42aa0936099bdc97, 0xe31584b766a2a18f];

fn slot_key(last_byte: u8) -> [u8; 32] {
    let mut key = [0; 32];
    key[31] = last_byte;
    key
}

fn fixture() -> ([[Field; NODE_FIELDS]; 3], [StorageProof<3>; 2]) {
    let mut nodes = [[0; NODE_FIELDS]; 3];
    nodes[0][0] = 0x4cf400bd97836cc1f9889a69e72504c52d6a00ba2fa01be2;
    nodes[0][1] = 0xea77ef070cbf3bfbdd05ff;
    nodes[1][0] = 0x886a6d75a0af5c581187fe9ada862a98f612fd72a08051f8;
    nodes[1][1] = 0x5baea08080808080808080806ec68b0ac55c4965a8c9c9b9;
    nodes[1][2] = 0x460895d58e783f9ae06ea746ce51a2ce8ef031c1050fef23;
    nodes[1][3] = 0x8080808080810fcc54c039;
    let proofs = [
        StorageProof {
            slot_key: slot_key(1),
            value_high: 0,
            value_low: 11,
            node_indices: [0, 1, 99],
            count: 2,
        },
        StorageProof {
            slot_key: slot_key(14),
            value_high: 0,
            value_low: 22,
            node_indices: [0, 1, 99],
            count: 2,
        },
    ];
    (nodes, proofs)
}

#[test]
unconstrained fn verifies_shared_nodes_for_two_slots_under_one_account() {
    let (nodes, proofs) = fixture();
    // EthereumJS state trie with one account, whose storage hash is STORAGE_ROOT.
    let root = [0xdb0007b285fcf288, 0x56b381a44f7b4b6a, 0x880e29ea2d27813e, 0xd82e45efcd7deeba];
    let account = PublicAccount {
        address: 0x0707070707070707070707070707070707070707,
        nonce: 0,
        balance_high: 0,
        balance_low: 0,
        storage_hash: STORAGE_ROOT,
        code_hash: [0x3c23f7860146d2c5, 0xc003c7dcb27d7e92, 0x3b2782ca53b600e5, 0x70a4855d04d8fa7b],
    };
    verify_account_and_storage_batch(root, account, [], 0, nodes, 2, proofs, 2);
}

#[test(should_fail_with = "Node hash differs from its parent reference")]
unconstrained fn rejects_a_cached_node_under_a_different_parent_reference() {
    let (nodes, mut proofs) = fixture();
    // The first proof warms both rows. The second tries to reuse the branch
    // at the root, where only the extension is authenticated.
    proofs[1].node_indices[0] = 1;
    verify_storage_batch(STORAGE_ROOT, nodes, 2, proofs, 2);
}

#[test(should_fail_with = "Storage leaf differs from its parent reference")]
unconstrained fn rejects_the_wrong_value_after_reusing_shared_nodes() {
    let (nodes, mut proofs) = fixture();
    proofs[1].value_low = proofs[0].value_low;
    verify_storage_batch(STORAGE_ROOT, nodes, 2, proofs, 2);
}

#[test(should_fail_with = "Node index exceeds table count")]
unconstrained fn rejects_indices_into_unused_rows() {
    let (nodes, mut proofs) = fixture();
    proofs[1].node_indices[1] = 2;
    verify_storage_batch(STORAGE_ROOT, nodes, 2, proofs, 2);
}

#[test(should_fail_with = "Storage batch is empty")]
unconstrained fn rejects_an_empty_batch() {
    let (nodes, proofs) = fixture();
    verify_storage_batch(STORAGE_ROOT, nodes, 2, proofs, 0);
}

#[test]
unconstrained fn verifies_leaf_only_trie_without_packed_nodes() {
    let root = [0xfa77652e555a1472, 0x2f00c947469bd5c4, 0xcba817459e18380b, 0x7d84928c5aeff6ad];
    let proof = StorageProof {
        slot_key: slot_key(1),
        value_high: 0,
        value_low: 11,
        node_indices: [],
        count: 0,
    };
    verify_storage_batch(root, [], 0, [proof], 1);
}
