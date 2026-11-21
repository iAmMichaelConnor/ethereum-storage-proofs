use aztec::macros::aztec;

mod logic;
pub use ethereum_public_proofs::NODE_FIELDS;
pub use logic::{
    ACCOUNT_DEPTH, count_acceptance, NODE_BYTES, node_fields, PackedNode, PRIVATE_STORAGE_DEPTH, ProofNode,
    prove_account_in_public, prove_slot_in_public, prove_storage_in_private, StateRoot, STORAGE_DEPTH, trusted_root,
};

/// Proves an Ethereum storage slot under a recorded state root, in two ways:
///
/// - `prove_slot` proves the account and the slot in one public call. Everything it is passed is public, including
///   the contract, the slot and the value.
/// - `prove_slot_privately` proves the slot in private and the account in public: the contract and its storage root
///   are public, the slot and the value are not.
///
/// The admin records state roots by block number. That is the trust assumption of this example: a production
/// contract would take roots from an authenticated source, such as an L1 portal that relays block hashes, and check
/// them against block headers. Proofs carry no time, so the application decides which blocks it accepts. Neither
/// function emits a nullifier: the same proof is accepted again.
#[aztec]
pub contract PublicProofs {
    use crate::{
        ACCOUNT_DEPTH, count_acceptance, node_fields, PackedNode, PRIVATE_STORAGE_DEPTH, ProofNode,
        prove_account_in_public, prove_slot_in_public, prove_storage_in_private, StateRoot, STORAGE_DEPTH, trusted_root,
    };
    use aztec::{
        macros::{functions::{external, initializer, only_self}, storage::storage},
        protocol::address::AztecAddress,
        state_vars::{Map, PublicImmutable, PublicMutable},
    };

    #[storage]
    struct Storage<Context> {
        admin: PublicImmutable<AztecAddress, Context>,
        roots: Map<Field, PublicMutable<StateRoot, Context>, Context>,
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
    fn prove_slot(
        block_number: Field,
        account: [Field; 8],
        account_nodes: [PackedNode; ACCOUNT_DEPTH],
        account_count: u32,
        slot_key: [u8; 32],
        value_high: u128,
        value_low: u128,
        storage_nodes: [PackedNode; STORAGE_DEPTH],
        storage_count: u32,
    ) {
        let root = trusted_root(self.storage.roots, block_number);
        prove_slot_in_public(
            root,
            account,
            node_fields(account_nodes),
            account_count,
            slot_key,
            value_high,
            value_low,
            node_fields(storage_nodes),
            storage_count,
        );
        count_acceptance(self.storage.accepted);
    }

    #[external("private")]
    fn prove_slot_privately(
        block_number: Field,
        account: [Field; 8],
        account_nodes: [PackedNode; ACCOUNT_DEPTH],
        account_count: u32,
        storage_root: [u64; 4],
        slot_key: [u8; 32],
        value: [u8; 32],
        value_length: u8,
        storage_nodes: [ProofNode; PRIVATE_STORAGE_DEPTH],
        storage_count: u32,
    ) {
        prove_storage_in_private(
            storage_root,
            slot_key,
            value,
            value_length,
            storage_nodes,
            storage_count,
        );
        // The account proof binds `storage_root` to the account under the recorded state root.
        self.enqueue_self.check_account(block_number, account, account_nodes, account_count, storage_root);
    }

    #[only_self]
    #[external("public")]
    fn check_account(
        block_number: Field,
        account: [Field; 8],
        account_nodes: [PackedNode; ACCOUNT_DEPTH],
        account_count: u32,
        storage_root: [u64; 4],
    ) {
        let root = trusted_root(self.storage.roots, block_number);
        prove_account_in_public(
            root,
            account,
            node_fields(account_nodes),
            account_count,
            storage_root,
        );
        count_acceptance(self.storage.accepted);
    }

    #[external("public")]
    fn count() -> Field {
        self.storage.accepted.read()
    }
}
