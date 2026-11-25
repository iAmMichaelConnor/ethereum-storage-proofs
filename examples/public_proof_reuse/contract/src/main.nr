use aztec::macros::aztec;

mod logic;
pub use logic::{
    AccountRoots, BatchSlot, prove_cached_slot, record_verified_account, SHARED_NODE_CAPACITY, SLOT_CAPACITY,
};

/// Demonstrates local reuse for a batch and persistent account verification for a snapshot.
/// The root registrar serves one Ethereum chain. Callers and root policy are application concerns.
#[aztec]
pub contract PublicProofReuse {
    use crate::{
        AccountRoots, BatchSlot, prove_cached_slot, record_verified_account, SHARED_NODE_CAPACITY, SLOT_CAPACITY,
    };
    use aztec::{
        macros::{functions::{external, initializer}, storage::storage},
        protocol::address::AztecAddress,
        state_vars::{Map, PublicImmutable, PublicMutable},
    };
    use ethereum_public_proofs::{PublicAccount, verify_account_and_storage_batch};
    use public_proofs_contract::{
        ACCOUNT_DEPTH, count_acceptance, node_fields, PackedNode, StateRoot, STORAGE_DEPTH, trusted_root,
    };

    #[storage]
    struct Storage<Context> {
        admin: PublicImmutable<AztecAddress, Context>,
        roots: Map<Field, PublicMutable<StateRoot, Context>, Context>,
        verified_accounts: AccountRoots<Context>,
        accepted: PublicMutable<Field, Context>,
    }

    #[initializer]
    #[external("public")]
    fn constructor(admin: AztecAddress) {
        self.storage.admin.initialize(admin);
    }

    #[external("public")]
    fn set_root(block_number: Field, root: StateRoot) {
        assert_eq(self.msg_sender(), self.storage.admin.read(), "Only the admin records roots");
        self.storage.roots.at(block_number).write(root);
    }

    #[external("public")]
    fn prove_slots(
        block_number: Field,
        account: [Field; 8],
        account_nodes: [PackedNode; ACCOUNT_DEPTH],
        account_count: u32,
        storage_nodes: [PackedNode; SHARED_NODE_CAPACITY],
        node_count: u32,
        proofs: [BatchSlot; SLOT_CAPACITY],
        proof_count: u32,
    ) {
        let root = trusted_root(self.storage.roots, block_number);
        verify_account_and_storage_batch(
            root,
            PublicAccount::from_fields(account),
            node_fields(account_nodes),
            account_count,
            node_fields(storage_nodes),
            node_count,
            proofs.map(|proof: BatchSlot| proof.proof()),
            proof_count,
        );
        count_acceptance(self.storage.accepted);
    }

    #[external("public")]
    fn cache_account(
        block_number: Field,
        account: [Field; 8],
        account_nodes: [PackedNode; ACCOUNT_DEPTH],
        account_count: u32,
    ) {
        let root = trusted_root(self.storage.roots, block_number);
        record_verified_account(
            self.storage.verified_accounts,
            root,
            account,
            node_fields(account_nodes),
            account_count,
        );
    }

    #[external("public")]
    fn prove_slot_from_cache(
        block_number: Field,
        address: Field,
        slot_key: [u8; 32],
        value_high: u128,
        value_low: u128,
        nodes: [PackedNode; STORAGE_DEPTH],
        count: u32,
    ) {
        let root = trusted_root(self.storage.roots, block_number);
        prove_cached_slot(
            self.storage.verified_accounts,
            root,
            address,
            slot_key,
            value_high,
            value_low,
            node_fields(nodes),
            count,
        );
        count_acceptance(self.storage.accepted);
    }

    #[external("public")]
    fn count() -> Field {
        self.storage.accepted.read()
    }
}
