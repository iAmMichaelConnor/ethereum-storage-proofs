use aztec::macros::aztec;

mod entry;
pub use entry::{
    admit_member, apply_claim, DOMAIN_ENTRY, mapping_key, ProofNode, RegistryAccount, RegistryEntry, Terms,
    verify_entry,
};

/// WARNING: example only. Unaudited; not for deployment as-is.
///
/// Grants membership to the Aztec addresses that an Ethereum registry lists, proven under a state root that the
/// deployer pins. The registry is an L1 contract with a `mapping(bytes32 => uint256)` at storage slot `mapping_slot`,
/// keyed by an Aztec address (the beneficiary) as 32 big-endian bytes; the value is the attribute (for example a
/// membership tier). `ethereum_proofs::proof::verify_l1_storage` proves the registry account under the state root and
/// the nonzero value at `keccak256(beneficiary ++ mapping_slot)` under its storage root.
///
/// - Nothing on Aztec checks that the root is Ethereum's: the deployer vouches for it and should pin the root of a
///   finalized block. It is a snapshot, not a bridge, and a storage proof carries no time.
/// - Chain data is public, so anyone can build the proof for any entry. The effect goes to the beneficiary that the
///   entry names, so it does not depend on who submits; who can write the registry decides who is listed.
/// - The contract stores only a hash of its terms (a transaction has a small public-write limit); every call passes
///   them.
/// - One nullifier per (registry, mapping slot, beneficiary): each beneficiary is admitted once.
/// - Capacities: 8 account-path and 6 storage-path nodes of 532 bytes.
#[aztec]
pub contract RegistryGate {
    use crate::{admit_member, apply_claim, RegistryEntry, Terms};
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        protocol::address::AztecAddress,
        state_vars::{Map, PublicImmutable, PublicMutable},
    };

    #[storage]
    struct Storage<Context> {
        terms_hash: PublicImmutable<Field, Context>,
        members: Map<AztecAddress, PublicMutable<Field, Context>, Context>,
    }

    #[initializer]
    #[external("public")]
    fn constructor(terms: Terms) {
        self.storage.terms_hash.initialize(terms.hash());
    }

    /// Admits the entry's beneficiary once, with the entry's value, if the pinned registry lists it with at least
    /// `min_value`.
    #[external("private")]
    fn claim(terms: Terms, entry: RegistryEntry) {
        let (beneficiary, value) = apply_claim(self.context, self.storage.terms_hash.read(), terms, entry);
        self.enqueue_self.admit(beneficiary, value);
    }

    #[only_self]
    #[external("public")]
    fn admit(beneficiary: AztecAddress, value: Field) {
        admit_member(self.storage.members, beneficiary, value);
    }

    #[view]
    #[external("public")]
    fn membership(beneficiary: AztecAddress) -> Field {
        self.storage.members.at(beneficiary).read()
    }
}
