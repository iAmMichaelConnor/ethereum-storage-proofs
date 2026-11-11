# Accepted inputs and trust boundaries

## Trust boundary

A trie proof authenticates a value **relative to a root**. An Aztec application must bind the root to its authenticated L1 header/root mechanism and enforce its chain, block and finality policy; a private witness containing a root is not sufficient. The libraries contain no bridge, oracle, header verifier, contract or Aztec-node dependency. All verification must run in constrained code. The inclusion APIs reject zero slots and absent accounts; the separate `absence` APIs prove those. This implementation has not had an independent security audit. Application duties are listed under [consumer obligations](proofs.md#consumer-obligations).

## Accepted input domains and optimization obligations

An optimization must preserve both soundness and the accepted valid input domain.
Do not narrow a general entry point to obtain a smaller circuit; restricted variants
are separately named. Canonical witness encodings are part of this API: equivalence
is not claimed for arbitrary upstream witness bytes.

| Entry point or specialization | Preconditions and intentional limits |
| --- | --- |
| General MPT inclusion | A canonical Ethereum secure trie; a 32-byte key hash; a present account or **nonzero** storage value; canonical minimal integers with zero buffer suffixes. Embedded and hashed children are accepted. Absence proofs are outside this API. |
| Fixed or mixed capacity profiles | Every supplied node fits its selected byte capacity and the path fits the node capacity. Unused node slots are padding. Choose another profile for larger proofs; a small profile does not cover the entire general domain. A third party can push a slot past a fixed capacity: one 1-wei transfer to a ground address (about 16^(m+1) Keccak for m shared nibbles) lengthens a contract's account path for every slot, and a few sibling writes fill a branch past 135/271/407 bytes. Liveness needs a deep fallback key; see [mainnet sizing](internals.md#choosing-capacities). |
| Hash-only MPT | Every nonempty child reference in each visited node, including siblings, must be a hash. This is an explicit restriction; a hashed selected child alone is insufficient. Use general mode when any sibling is embedded. A canonical trie embeds every node whose RLP is under 32 bytes. A storage leaf at nibble depth 9 or deeper with a value of at most 0x7f is such a node. So any slot whose keccak(slot) shares 8 or more leading nibbles with yours, and that holds a small value, makes every hash-only proof of your slot fail. Large contracts contain such pairs naturally, and a third party can create one for about 2^32 Keccak evaluations (about 2^16 for any pair) and one storage write, for example an ERC-20 `approve` of 1 unit. No false value becomes provable; general mode still accepts the slot. Use general mode, or also authorise a general-mode key, for any slot whose trie neighbourhood you do not control. |
| Leaf encoders (`encoding`) | `encode_slot` and `compute_account_hash` assert a leaf nibble index of at most 64 and canonical integers with zero suffixes; `encode_slot` zeroes its output after the length. They compute encodings only and prove no inclusion. |
| Section composition (`Cursor`) | The first cursor is `new_cursor(authenticated_root)`; each later cursor is the previous section's output; all sections and the leaf use one hashed key. The fields are crate-private. `Cursor::from_authenticated_parts` rebuilds a cursor without checking anything, for resuming a path whose parts a constrained check has already bound to the root; a cursor built from prover input binds nothing. |
| Secure-trie absence | Canonical Ethereum root and 64-nibble secure keys. Matching prefix plus authenticated empty branch child or divergent compact path, or canonical empty root. Hash and embedded references are accepted. Divergent values/sibling subtrees remain opaque. See [absence](proofs.md#absence). |
| Account leaf | Nonce is at most eight bytes; balance at most 32. Zero nonce and zero balance are accepted with length zero. The nonce width follows [EIP-2681](https://eips.ethereum.org/EIPS/eip-2681). |
| Keccak (`ethereum_keccak`) | Runtime length `<= N` for an active call. All lengths including zero and 135 are accepted; bytes after the declared length are ignored. Every capacity uses the vendored noir-lang/keccak256; limb output takes the first four lanes of the same final state. A predicated assert rejects an active over-capacity length; under a disabled caller any length is accepted, because the `#[no_predicates]` helpers receive 0 instead. |
| Recursive proofs | Exact pinned Poseidon2 UltraHonk format and an application-authorized producer key. The existing API also rejects an authorized key hash of zero. This is an API policy guard, **not** a theorem that Poseidon2 cannot output zero, and nonzero alone does not establish authorization. |
| SSZ branches | Generalized indices fit `u64`, depth is at most 63, and the index has exactly the specified depth. Depth zero/index one and equal siblings are valid. The bounded API ignores unused suffix siblings. |
| Deneb anchor helper | The documented generalized indices (valid for Deneb, Electra and Fulu) and an authenticated beacon root for that schema. Capella and earlier fail closed; Gloas needs a new anchor. `verify_deneb_execution_anchor_at_slot` binds the slot and enforces a caller-supplied fork range. An EIP-4788 root read at block N anchors block N-1. This is not a consensus or finality verifier. |

The bounds used by these implementations have concrete justifications:

- A secure trie key has 64 nibbles. Each branch consumes one and each extension
  consumes at least one, so at most 64 internal nodes can precede the terminal
  leaf. A branch at nibble 63 may lead to an empty-suffix leaf. A canonical
  extension must leave a nibble for its branch; an extension followed directly
  by a leaf would be merged in a canonical trie.
- A maximum storage leaf occupies 70 bytes: 34 bytes for its encoded compact
  key, 34 for the wrapped 32-byte integer, and two for the list prefix. A maximum
  account leaf occupies 148: 108 bytes of account fields, two inner-list bytes,
  two wrapping-string bytes, 34 key bytes and two outer-list bytes. The smallest
  account leaf occupies 75 bytes, so account leaves and their ancestors cannot
  be embedded references. Ethereum uses the strict **less than 32 bytes** rule
  for embedding ([MPT reference](https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/)).
- Eight packed bytes sum to at most `2^64 - 1`. The streaming hasher keeps its
  byte offset in `0,8,...,56` and lane index in `0,...,16`. Its aligned `u64`
  branch handles offset zero separately; the other branch shifts by 8 through
  56, never 64. The existing partial limb and newly shifted word occupy disjoint
  bits. Finishing a limb resets it; finishing lane 16 permutes and resets the
  lane index. These invariants apply to both account hash word writes.
- The BN254 scalar modulus is
  `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
  Packing at most 31 bytes gives at most `2^248 - 1`, below that modulus.
  Actual address inputs use 160 bits, word halves 128 and root lanes 64. Thus
  serialization into fields is injective before hashing. Poseidon2 collision
  resistance remains a cryptographic assumption. Threshold comparisons operate
  on all 32 bytes, so equality and values above the field modulus remain valid.

## Inactive-call and composition obligations

Unused nodes may contain arbitrary padding, including out-of-range ignored lengths.
Pass zero as the Keccak hash length for unused entries before the active-node
selection. Active entries retain their parsed length and must reject overflow.
Exercise conditional paths, unused padding and `#[no_predicates]` call sites with
runtime witnesses: a test whose inputs are constants lets the compiler specialize
them and does not establish this property. The tests pass their inputs through
`std::hint::black_box` (or an unconstrained identity) for this reason. Preserve
active-node root, key and value binding when changing padding handling.

Receipt/event verification must bind the raw index, typed receipt schema, selected
log, emitter, topics, data length and digest described in
[receipts and events](proofs.md#receipts-and-events). Absence verification must preserve
terminal/root binding, reject matching present keys and accept valid exceptional
paths, including disabled callers where supported.

Root authentication, finality, producer-key authorization and replay/effect policy
remain application obligations. Correct binding to supplied policy inputs remains
a library obligation. Backend recursive arithmetic belongs to the pinned backend;
this library introduces no custom incomplete elliptic-curve formulas. Finite tests
do not establish formal completeness or replace a security audit.

## Recursive proofs

The consumer must authorize the producer verification key independently of the bundle.
The recursive verifier defers its final pairing obligation to the matching outer verifier.
Client-side rejection and witness execution do not establish rollup rejection.

**Verification-key binding is a backend premise.** Every consumer calls
`std::verify_proof_with_type(verification_key, proof, [statement], authorized_vk_hash, 6)`
(`verify_claim` in `ethereum_recursive_proofs`). The 115 verification-key fields are
a private witness; the library itself never hashes them. The only link between
the key the proof is checked against and the key the application authorized is the
`key_hash` argument. Soundness therefore rests on the pinned Barretenberg recursion
constraint computing the hash of the supplied key fields inside the circuit and
constraining it to equal `key_hash`. The bb 6.0.0 backend (Aztec 6.0.0) named in the
README's compatibility section is relied on for this; a backend that treated
`key_hash` as an unchecked label would let a prover substitute a key for a different
circuit. Recheck this premise, with a negative test that pairs a valid proof and key
with a different authorized hash, whenever the backend pin or the proof type changes.
The library's own obligations are narrower: it passes exactly one public input (the
domain-separated statement of the expected claim), it rejects an authorized hash of
zero, and the application must take `authorized_vk_hash` from a constant or
authenticated policy, never from the prover.
