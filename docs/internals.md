# Internals: capacities, Keccak and testing

## Choosing capacities

Every verifier has compile-time capacities: the number of internal nodes per path
and the bytes per node (135, 271, 407 or 532, that is 1 to 4 Keccak permutations).
A shape fits the proofs it was sized for, not every future state of a slot; each
compiled shape has its own verification key, which an application must authorize.
Capacities fail closed: a proof that does not fit is rejected, never truncated.

Mainnet paths are longer than the test fixtures, and anyone can lengthen them:

- A sample of 6,034 present mainnet accounts at block 26,259,860 had 7 to 10
  internal account nodes (median 8): an account capacity of 7 rejected about 79%
  of them, 8 about 9%. Large contracts' storage paths reached 9 nodes.
- A third party can lengthen a contract's account path by grinding an address
  whose key shares m+1 nibbles with the contract's (about 16^(m+1) Keccak
  evaluations, 2^32 for 8 nibbles) and sending it 1 wei. Every slot of the
  contract shares that path.
- Sibling writes (for example `approve(spender, 1)` with ground spenders) fill a
  branch on a slot's path. A branch with k hashed children needs 32k+17 payload
  bytes: 135 holds at most 3, 271 at most 7, 407 at most 12; only 532 holds all 16.
- The producer shapes in
  [ethereum_storage_proofs/src/benchmarks.nr](../noir/ethereum_storage_proofs/src/benchmarks.nr)
  are measurement shapes, not general producers: `storage_small` and `batch4` are
  small tailored shapes, `l1_mixed` rounds a large token contract's path up one
  bucket, and the absence shapes of depth 4 are representative.

An application that needs liveness should also authorize a deep fallback key, for
example 12 to 16 nodes of 532 bytes on both paths (16^12 = 2^48 Keccak evaluations
is cheap on a GPU; 2^64 is not), or keep its key policy upgradable.

## Keccak implementation

The permutation is the backend's `keccakf1600` black box. `keccak256` is
noir-lang/keccak256 (see the README's compatibility section for the commit), which
packs bytes into lanes and pads lanes with `0x01 .. 0x80`; a capacity below 136
bytes gets one permutation, including the 135-byte padding boundary.
`keccak256_limbs` is that package's `keccak256_lanes`, which takes the four digest
lanes from the same final state. The package is vendored in
[`vendor/keccak256`](../vendor/keccak256).
Both require `message_size <= N` and pass a zero length to their
`#[no_predicates]` kernels under a disabled caller, so an inactive call stays
satisfiable without weakening the active rejection
([disabled_caller_tests.nr](../noir/ethereum_keccak/src/disabled_caller_tests.nr)).

## Testing

The expected values come from independent references, never from the code under
test: EthereumJS trie, RLP and Keccak (pinned in `scripts/package-lock.json`),
Python `hashlib` SHA-256 for SSZ and Python integers for quantity conversions.
`scripts/generate.py` regenerates every generated test module and fixture, and
`--check` fails if a committed file is stale.

| Test module | What it covers |
| --- | --- |
| `ethereum_storage_proofs/src/fixtures_tests.nr`, `adversarial_tests.nr` | Inclusion against EthereumJS tries and a saved mainnet proof: altered roots, keys, values and siblings, malformed RLP, truncated paths, odd and even extensions, embedded references |
| `ethereum_storage_proofs/src/completeness_tests.nr` | Boundaries: empty and exact buffers, Keccak rate and padding, every streaming alignment, 31/32/33-byte references, RLP payloads of 55/56/255/256 bytes, a 64-node path, modulus aliases, equal thresholds |
| `ethereum_storage_proofs/src/ssz_tests.nr` | SSZ depth 0 and 63, equal siblings and the Deneb anchor composed with an account and storage proof |
| `ethereum_storage_proofs/src/batch_tests.nr`, `receipt_tests.nr`, `absence_tests.nr`, `empty_child_tests.nr` | The producer shapes and verifiers on real witnesses: every mutated claim field rejected, padding in unused capacity accepted; for absence, an independent EthereumJS lookup decides whether a mutated claim is still true |
| `ethereum_proofs/src/balance_tests.nr` | The README's account and token balance consumers |
| `ethereum_types/src/predicate_tests.nr`, `ethereum_keccak/src/disabled_caller_tests.nr` | Conversions, slot offsets and Keccak behind a runtime branch: no constraints leak into a disabled caller |

The 64-node path, the near-terminal fixtures and the Deneb tree are synthetic, not
known preimages or observed mainnet state. The saved mainnet proof
(`reference/aztec-node/storage_proof.json`, block 24,418,695) has its trie relation
checked; its block number is not authenticated from a header.

What the tests do not establish: they execute circuits, so they show that honest
witnesses are accepted and that the listed malformed witnesses are rejected; they
are not a proof of soundness, they generate no proofs, and they do not check the
backend's arithmetisation of each circuit. Recursive verification is exercised only
for its claim binding: no test verifies a real producer proof inside a consumer.
