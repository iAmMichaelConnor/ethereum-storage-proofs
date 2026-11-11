# Claims and Noir API

Every package is an ordinary `type = "lib"` Nargo package with constrained
functions and no Aztec runtime dependency. The packages are tested with every Noir
release from 1.0.0-rc.3 (the version Aztec 6.0.0 pins) onwards, and with nightly.
Preconditions of each entry point are in the
[accepted domains](security-model.md#accepted-input-domains-and-optimization-obligations).

## Imports

```toml
[dependencies]
# Include only the packages you use.
ethereum_proofs = { git = "https://github.com/iAmMichaelConnor/ethereum-storage-proofs", tag = "v0.1.0", directory = "noir/ethereum_proofs" }
ethereum_recursive_proofs = { git = "https://github.com/iAmMichaelConnor/ethereum-storage-proofs", tag = "v0.1.0", directory = "noir/ethereum_recursive_proofs" }
ethereum_ssz = { git = "https://github.com/iAmMichaelConnor/ethereum-storage-proofs", tag = "v0.1.0", directory = "noir/ethereum_ssz" }
```

| Package | Public surface | Dependencies |
| --- | --- | --- |
| `ethereum_proofs` | `verify_account_proof`, `verify_storage_proof`, `verify_account_and_storage_proof`; modules `proof`, `batch`, `slot_key`, `encoding`, `absence`, `receipts`, `events`, `rlp`; re-exports `keccak`, `types` | Types + `ethereum_keccak` |
| `ethereum_keccak` | `keccak256`, `keccak256_limbs`, streaming `KeccakHasher` | Pinned `keccak256` |
| `ethereum_recursive_proofs` | Claims, statements, predicates and recursive consumers; `receipts`, `absence` | Types + pinned `poseidon` |
| `ethereum_ssz` | SHA-256 branches and the Deneb execution anchor | None |
| `ethereum_types` | `Account`, `StorageSlot` and canonical numeric conversions | None |
| `ethereum_storage_proofs` | Facade re-exporting all of the above, including `recursive_proof` and `ssz` | Packages above |

`ethereum_proofs::types` re-exports the canonical types, so a direct
`ethereum_types` dependency is needed only by types-only consumers. Nargo's `git`
dependencies take a `tag`, not a commit (`rev`); authenticate the tag's commit.

## Representation

- Roots and hashes are four **little-endian u64 lanes in digest order**.
  Addresses and slot keys are ordinary byte order.
- `StorageSlot.value` is the minimal big-endian integer **left aligned** in 32
  bytes with a zero suffix; `value_length` is its byte count. Nonce and balance use
  the same convention with widths 8 and 32. Nonzero integers may not start with a
  zero byte; a zero nonce or balance has length zero. A zero storage value has no
  trie leaf and needs the [absence](#absence) APIs.
- `EncodedNode<B>` holds `bytes: [u8; B]`, `length: u32` and `is_extension: bool`.
  Path nodes are the original RLP bytes in root-to-leaf order, **excluding the
  terminal leaf**, which is reconstructed from the key and claimed value and matched
  against its hash or embedded reference. Embedded internal children also appear
  as path entries. The general verifier authenticates sibling bytes but decodes
  only their top-level item boundaries.
- `[EncodedNode<B>; D]` fixes the circuit capacity; the private runtime `count`
  selects the used prefix and must be `<= D`. Depth counts internal nodes, so
  `D = 0` supports single-leaf tries. Arrays after `count` and bytes after a node's
  `length` are ignored; value buffers instead require zero unused bytes. Capacities
  fail closed; no proof is truncated.

| Byte bound B | Keccak permutations per internal node |
| --- | ---: |
| 135 | 1 |
| 271 | 2 |
| 407 | 3 |
| 532 | 4 |

532 covers every Ethereum branch node, including embedded children. A bound of
136 already needs two permutations because of Keccak padding. Shorter actual
lengths and smaller runtime counts do not remove permutations or node circuits
from a compiled shape. Circuit selection and capacities are public even when
inputs are private; use common padded buckets if the exact shape is sensitive.

## Account and storage inclusion

```rust
use ethereum_proofs::{proof::EncodedNode, types::StorageSlot, verify_storage_proof};

fn check_slot(
    trusted_storage_root: [u64; 4],
    slot_key: [u8; 32],
    value: StorageSlot,
    nodes: [EncodedNode<532>; 8],
    count: u32,
) {
    verify_storage_proof(trusted_storage_root, slot_key, value, nodes, count);
}
```

To start from an execution **state root**, use `verify_account_and_storage_proof`,
or compose `verify_account_proof` and `verify_storage_proof` with the authenticated
account's `storage_hash`. These aliases start at a root, hash the raw slot or
address themselves and take no `Cursor`. Bind the address, slot key and value to
the application's inputs. `account_balance` and `erc20_balance` in
[ethereum_proofs/src/benchmarks.nr](../noir/ethereum_proofs/src/benchmarks.nr) are
complete consumers (the README shows both); the latter derives `balances[holder]`
at declaration slot 9, which is that example's layout, not an ERC-20 convention.

| Dimension | Interface |
| --- | --- |
| Path capacity and node bytes | `EncodedNode<B>`, `verify_storage<D,B>`, `verify_account<D,B>` |
| Separate account and storage bounds | `verify_l1_storage<AD,AB,SD,SB>` |
| Shared internal nodes across slots | `verify_storage_batch<K,P,D,B>`; `_parsed` parses each node once |
| Mixed node-byte buckets | `NodeBucket<P,B>`, `verify_storage_batch_mixed` / `_parsed` |
| Mixed capacities along one path | `Cursor`, `verify_path_section`, then a leaf verifier |
| Hash-only restriction | `_hashed` variants, `verify_hashed_path_section` |

`K` is the slot count, `P` the shared node-table capacity, `D` the internal steps
per path and `B` the node byte capacity. The batch APIs accept any positive `K`.
`_parsed` variants derive their cached node metadata in constrained code, not from
a prover hint.

Section composition, for a large prefix and smaller suffix:

```rust
let key = keccak256(slot_key, 32);
let cursor = verify_path_section(large_nodes, large_count, new_cursor(root), key);
let cursor = verify_path_section(small_nodes, small_count, cursor, key);
verify_storage_leaf(cursor, key, expected_value);
```

Section APIs take the already hashed key. Every section and the leaf use the same
key, and every cursor comes from the preceding verified section. `Cursor` fields
are crate-private; `Cursor::from_authenticated_parts` checks nothing and must never
take prover input.

General verifiers accept embedded children. `_hashed` variants reject an embedded
reference anywhere in a visited node, including siblings, so a third party can make
every hash-only proof of a slot fail; use general mode unless you accept that
(see the hash-only row of the [accepted domains](security-model.md#accepted-input-domains-and-optimization-obligations)).

The `encoding` module's leaf encoders (`encode_slot`, `compute_account_hash`) are
for advanced composition and verify no inclusion on their own.

## Slot keys and conversions

Every storage claim takes `slot_key` (batch: `slot_keys`), the 32-byte Solidity
storage position; the circuits hash it with Keccak-256 to find the trie key. The
caller derives it from the contract's
[Solidity storage layout](https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html):
a state variable uses its declared slot `p`; a mapping entry with value-type key
`k` uses `keccak256(pad32(k) || pad32(p))`, where `pad32(p)` is the 32-byte
big-endian slot and `pad32(k)` pads as Solidity stores the key in memory
(`uintN`, `address`, `bool` and enums left-padded with zeros, `intN`
sign-extended, `bytesN` right-padded).

`ethereum_proofs::slot_key` computes these positions: `value_slot`,
`mapping_slot`, `address_mapping_slot`, `nested_mapping_slot` (outer key hashed
first), `array_element_slot` and `add_offset`. Declaration slots, indices, strides
and offsets are `u32`; mapping keys are 32-byte encodings. Array indices are
multiplied by the positive whole-slot stride in `u64`, keeping the full product;
addition propagates all 256 bits of carry and rejects overflow. The helpers do not
infer packed fields, struct layouts, dynamic `bytes`/`string` key encodings or
array length bounds.

`Account::balance_as_field()` and `nonce_as_u64()` validate the selected quantity.
`StorageSlot` offers `is_zero()`, `to_field()`, `to_u128()` and `to_u128_pair()`
(returns `(high, low)` with value `high * 2^128 + low`). All require canonical
encodings as in [Representation](#representation). Field conversion accepts
32-byte integers strictly below the native modulus and rejects aliases instead of
reducing them. Conversions authenticate nothing; `is_zero()` interprets an empty
value and does not prove trie absence.

## Absence

`ethereum_proofs::absence` proves non-inclusion in the **secure account/storage
tries**: a zero slot has no leaf, and is not proved by accepting a present leaf
encoding zero. The root must describe a canonical trie; the library does not
validate unrelated subtrees or the schema of a divergent leaf's opaque value.

| Need | Noir API | Recursive consumer |
| --- | --- | --- |
| Slot is zero under a storage root | `verify_storage_zero<D,B,T>` | `verify_storage_zero_recursive_proof` |
| Address is absent under a state root | `verify_account_absent<D,B,T>` | `verify_account_absent_recursive_proof` |
| Included account has a zero slot | `verify_l1_zero<A,AB,D,B,T>` | `verify_l1_zero_recursive_proof` |
| App proves the account, user proves the zero slot | compose the above | `verify_linked_zero_recursive_proofs` |

An absent account implies empty storage at every slot; `l1_zero` requires a
present account and does not substitute an absent-account proof. There is no
shared-node zero or mixed zero/nonzero batch. The high-level APIs hash raw keys
(32 bytes) or addresses (20 bytes); `verify_absence` takes the hashed secure key
and `verify_terminal` a verified `Cursor`.

```rust
use ethereum_proofs::absence::verify_storage_zero;
use ethereum_proofs::proof::EncodedNode;
fn main(root: pub [u64; 4], slot: [u8; 32],
        nodes: [EncodedNode<135>; 2], count: u32,
        terminal: [u8; 135], terminal_length: u32, kind: u8) {
    verify_storage_zero(root, slot, nodes, count, terminal, terminal_length, kind);
}
```

`D` counts **matching internal nodes before the terminal**, `B` is each prefix
node's capacity and `T` the terminal's.

| `kind` | Terminal condition |
| --- | --- |
| `BRANCH = 0` | The authenticated branch's selected child is empty |
| `EXTENSION = 1` | At least one nibble of its canonical compact path differs |
| `LEAF = 2` | Its complete remaining secure-key suffix differs |
| `EMPTY = 3` | Root equals Keccak256(`0x80`) and the prefix count is zero |

A matching extension or leaf never proves absence. Hashed and embedded children
are supported; secure keys have 64 nibbles and path lengths and leaf endpoints are
checked. Unused node slots and suffix bytes are ignored, including out-of-range
unused lengths; for `EMPTY` the terminal fields are unused. A zero-depth shape
accepts an empty trie or a root terminal only.

## Receipts and events

`verify_receipt<D,B,N,MAX_LOGS>` proves a receipt at a **transaction index**
under a supplied **receiptsRoot**. The trie key is canonical `RLP(index)` (u64;
zero encodes as `0x80`), not hashed. The circuit checks the leaf path, the
envelope and canonical RLP, and returns receipt type, status or historical
post-state root, cumulative gas and log-list metadata in a `ReceiptView`, which is
a view into authenticated bytes (a caller-built view carries no authentication).
`ethereum_proofs::rlp::read_item`, `parse_receipt` and `parse_log` check framing
and schema only and imply no trie inclusion.

**Status.** `status` is `false` for a failed receipt and also for every
pre-Byzantium receipt (mainnet blocks before 4,370,000), which records a
post-state root and no outcome; `has_post_state` tells them apart. Use
`ReceiptView::succeeded()` / `failed()`, both false before Byzantium, or pin
`has_post_state = false` next to `status` in a `ReceiptClaim`. Never read `status`
alone.

`verify_event<D,B,N,MAX_LOGS,DATA>` also binds a **receipt-local** log index (the
ordinal within that receipt's `logs`, not JSON-RPC's block-global `logIndex`),
the emitter, the exact topic count and topics, and the exact data length and
bytes. The expected `Event` must be canonical: topics at index `topic_count` and
above and data bytes at `data_length` and above must be zero. A consumer relying
on topic j must pin `topic_count > j`. Anonymous events and empty data are
accepted. The circuit infers no ABI: the application binds topic0 and decodes
fields itself; indexed dynamic values are hashes. A transaction hash is not in
the receipt trie.

Supported domain:

- Legacy RLP receipts (pre-Byzantium 32-byte post-state root, or status 0/1) and
  typed envelopes 1, 2, 3 and 4 with the four-field payload. Other receipt types
  need a schema extension. Canonical u64 index and cumulative gas, a 256-byte
  bloom, logs with 20-byte emitters, 0 to 4 topics and bounded data.
- Path depth depends on the index and the block's receipt count. D=4 reaches
  indices below 256 in any block, and all indices only in blocks of at most 272
  receipts; D=5 reaches 256 to 511 only in blocks of at most 512 receipts; D=6
  reaches every index below 65,536. Blocks with 273 or more receipts are common,
  and a builder or spammer can push a receipt to index 256 or above. The
  `receipt_summary` and `event` producer shapes in
  [ethereum_storage_proofs/src/benchmarks.nr](../noir/ethereum_storage_proofs/src/benchmarks.nr) (D=4, leaf at most 1,024 bytes, at most 3
  logs) are too small for about 18% of recent mainnet receipts.
- `D` is the internal-node capacity, `B` bytes per node (3 to
  532), `N` the full encoded leaf, `MAX_LOGS` the total log capacity and `DATA`
  the event data capacity. A receipt shape may have zero logs; an event shape
  needs at least one log and one data byte (empty data still works).

Receipt keys are prefix-free and receipt leaves always exceed 32 bytes (the bloom
alone is 256), so hash-only traversal is complete here; the terminal leaf enforces
the variable key length. Bloom consistency, execution and consensus validity are
properties of the authenticated block and are not recomputed. Encoding follows
[EIP-2718](https://eips.ethereum.org/EIPS/eip-2718),
[EIP-658](https://eips.ethereum.org/EIPS/eip-658), the type-4 receipt of
[EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) and the
[execution receipt structures](https://raw.githubusercontent.com/ethereum/execution-specs/master/src/ethereum/forks/prague/blocks.py).

## SSZ and block identity

`ethereum_ssz::verify_branch<D>` verifies a SHA-256 branch from a 32-byte leaf or
subtree root to an SSZ root; `verify_branch_bounded<MAX>` accepts a private used
depth within a padded capacity. Both take a **generalized index** including its
leading root bit (root 1, children 2/3), `u64`, depth 0 to 63, with siblings
ordered leaf to root; zero, truncated and oversized indices reject.

```rust
use ethereum_storage_proofs::ssz::verify_branch;
verify_branch::<3>(field_root, siblings, 11, trusted_beacon_header_root);
```

Index 11 here is the beacon header's **consensus** state root, not the execution
state root: the application fixes the schema and index. SSZ integer chunks are
little-endian (`uint64_root` for a standalone uint64); packed values, list length
mix-ins and composites need their chunk or subtree roots. The module verifies
branches, not SSZ deserialization or signatures.

`verify_deneb_execution_anchor` checks, under an unsigned `BeaconBlock` /
`BeaconBlockHeader` root, the execution payload root at generalized index 201
(seven siblings), the execution state root at 34 and the block number at 38 under
that payload (five siblings each, sharing three ancestors).
`execution_root_limbs(state_root)` converts the state root to MPT lane format for
the account/storage APIs. Indices 201/34/38 hold for Deneb, Electra and Fulu (the
payload is body field 9 of at most 16; ExecutionPayload has 17 fields in 32
leaves). Capella and earlier fail closed. Gloas (EIP-7732) moves the payload: under
one draft every honest anchor is rejected, under another a genuine root can yield
`state_root = 0` and `block_number = 0`. Therefore prefer
`verify_deneb_execution_anchor_at_slot`, which also authenticates the slot
(BeaconBlock field 0, generalized index 8) and asserts `first_slot <= slot <
end_slot`. On mainnet pass `MAINNET_DENEB_FIRST_SLOT` (8,626,176) and the first
Gloas slot, or `u64::MAX` until Gloas is scheduled. Do not use either helper on a
`SignedBeaconBlock` root.

**EIP-4788 roots.** The beacon roots contract
(`0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02`) returns, for the timestamp of
execution block N, the _parent_ beacon block root, which anchors block N-1. Take
block identity from the anchor's bound `block_number`, never from where the root
was read. The contract keeps 8191 roots. How the root reaches the Aztec circuit
(for example an L1 portal sending an L1-to-L2 message) is the integrator's trust
assumption. Definitions follow consensus-specs v1.5.0
([Merkle proofs](https://github.com/ethereum/consensus-specs/blob/v1.5.0/ssz/merkle-proofs.md),
[SSZ](https://github.com/ethereum/consensus-specs/blob/v1.5.0/ssz/simple-serialize.md),
[Deneb](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/deneb/beacon-chain.md)).

## Recursive proofs

A standalone producer proves a claim; a private consumer verifies it recursively:

```rust
use ethereum_recursive_proofs::{RecursiveProof, L1Claim, verify_l1_recursive_proof};

fn consume(recursive_proof: RecursiveProof, expected: L1Claim, authorized_vk_hash: Field) {
    verify_l1_recursive_proof(recursive_proof, authorized_vk_hash, expected);
}
```

Take `expected`'s root and `authorized_vk_hash` from an authenticated policy or
constant. A nonzero key hash is not authorization, and neither is a recursive
proof export's `producer_vk_hash`, which is the prover's claim about its own key.
Every family shares one verification core (`verify_claim`); each claim has its own
Poseidon2 domain tag, so claims of one family cannot stand in for another.

| Claim | Consumer | What its statement binds |
| --- | --- | --- |
| `L1Claim` | `verify_l1_recursive_proof` | State root, address, slot, full value |
| `AccountClaim` | `verify_account_recursive_proof` | State root, address, storage root |
| `StorageClaim` | `verify_storage_recursive_proof` | Storage root, slot, full value |
| `ThresholdClaim` | `verify_threshold_recursive_proof` | Storage root, slot, minimum; the value stays private |
| `BatchStorageClaim<K>` | `verify_batch_storage_recursive_proof` | Storage root and **ordered** `K` slot/value pairs |
| `StorageZeroClaim` | `verify_storage_zero_recursive_proof` | Storage root and full raw slot key |
| `AccountAbsentClaim` | `verify_account_absent_recursive_proof` | State root and address |
| `L1ZeroClaim` | `verify_l1_zero_recursive_proof` | State root, address and raw slot key |
| `ReceiptClaim` | `verify_receipt_recursive_proof` | Receipts root, transaction index, type, `has_post_state`, status, post-state root, cumulative gas |
| `EventClaim` | `verify_event_recursive_proof` | Receipts root, transaction index, receipt-local log index, emitter, active topics and count, Keccak data digest (four u64 lanes) and length |

`verify_linked_storage`, `verify_linked_threshold`, `verify_linked_batch<K>` and
`verify_linked_zero_recursive_proofs` verify an app account proof plus a user proof
and enforce equal storage roots
(`linked_storage` and `linked_zero` in
[ethereum_recursive_proofs/src/benchmarks.nr](../noir/ethereum_recursive_proofs/src/benchmarks.nr)). The receipt producer
commits a summary, not a receipt-byte digest; `event_statement` rejects a nonzero
topic at index `topic_count` or above, so each event has one statement.

**Threshold semantics.** The threshold producer (tag `STORAGE_GE_V1`) proves
`value >= minimum`, comparing both as full 32-byte big-endian uint256 words with
no field reduction; equality passes. For `value > X` use `minimum = X + 1` (no
value exceeds `2^256 - 1`). It proves a present leaf, so a zero slot has no
threshold proof even with `minimum = 0`; with `minimum = 0` the claim means "a
nonzero value is present". Use the absence producers for zero slots. Because the
**whole word** is compared, a packed slot can pass on another field: in
`struct { uint96 balance; address delegate; }` a zero balance with a nonzero
delegate passes `minimum = 1`, and signed values compare as two's complement. For
packed or signed slots use an exact-value producer and extract the field in the
consumer, or review a new producer with its own claim domain. A recursive proof
for any new predicate needs its own claim domain and key; never reuse the
threshold or exact-value producer key as authorization for a different circuit.

**Proof format.** Poseidon2 UltraHonk ZK, proof type 6, 115 VK fields, 458 proof
fields (keep all, including the eight accumulator fields) and one statement public
input. These are protocol constants, not shape parameters.

**Deferred pairing check.** The recursive verifier checks the transcript,
sumcheck and key hash in-circuit but returns the final pairing points for Aztec's
kernel and Chonk verifier. A proof whose last opening commitment is replaced
passes `nargo execute` and local constraint checks and fails only at that pairing
check. Soundness needs an Aztec network verifier with the Goblin fixes of
aztec-packages v6.0.0 (present in the pinned backend, absent from v6.0.0-rc.6 and
earlier). Key binding is a backend premise:
[recursive proofs](security-model.md#recursive-proofs).

## Consumer obligations

A successful verification proves a fact about inputs the application supplies.
These duties apply to every route, direct or recursive.

### Authenticated inputs

- Authenticate every root before use (execution state root, an account's storage
  root, a receipts root) with its chain, block and finality policy. A state root
  does not authenticate a receipts root, and the Deneb anchor does not add that
  link. No route establishes consensus or finality.
- Choose the authorized producer key hash for each recursive route.
- Derive slot keys as in [slot keys](#slot-keys-and-conversions) and bind address,
  slot and value or fields to the application's inputs.

### Replay

No recursive consumer or direct check (`verify_storage`, `verify_l1_storage`,
`verify_account`, `verify_receipt`, `verify_event`, the absence and batch checks
and their `_hashed` and `_parsed` variants) binds a nonce, context, nullifier,
recipient or chain id. Each succeeds any number of times, in any transaction, for
any caller, on the same authenticated root.

### One-time use and nullifiers

If a fact may be used only once, emit a nullifier per fact in the consuming
private function, over a tuple that names what may be used once:

- Event: chain id, block hash or number, transaction index and receipt-local log
  index. Receipt: chain id, block hash or number and transaction index. Take the
  block from the source that supplied the receipts root. Never key on the receipts
  root alone: blocks with identical receipt lists (single-transaction blocks on a
  quiet chain or an L2) share it, so a second genuine deposit would be blocked.
- These tuples identify a deposit only on a final chain. With non-final roots a
  reorg can include the same deposit elsewhere (keyed on hash: credited twice) or
  another deposit at the same position (keyed on number: a genuine one blocked).
  Require finality and use one form per right. If the emitter assigns unique
  deposit ids, chain id, emitter and id is a simpler key.
- A storage fact can be proved again under every later root. A once-per-holder
  right (airdrop, balance-gated mint) must nullify chain id, address and slot, or
  another root-independent key; a nullifier containing the root lets the holder
  claim again under the next root. If the right depends on a balance, also pin one
  snapshot root, or the tokens can move to a new holder with a fresh slot.
- Absence and account facts are state facts: key them on what the right names and
  pin a snapshot root when the right depends on state at one time.

### Recipient, action and authority

A proof does not name who may use the fact; anyone with the public Ethereum data
can produce it. Bind the recipient and action in the consuming function: take the
recipient from the proven fact (an event field naming the Aztec recipient) or
require authorization from the holder's L1 address (a signature or an L1-to-L2
message). A caller-chosen recipient is not authority: with a once-per-holder
nullifier, the first caller claims the holder's credit.

### Linkability

These nullifiers are public and linkable: anyone can compute the nullifier of
every candidate event or slot (a mapping slot can be computed for every known
holder) and see which was consumed and when. The library provides no
unlinkability. Adding a free secret to the nullifier is not enough unless one
fact fixes one secret; otherwise the fact can be reused under a second secret.

The [storage_proofs example contract](../examples/storage_proofs/contract/src/main.nr)
deliberately permits repeats and leaves authorization, freshness, replay and
anchoring to its caller.
