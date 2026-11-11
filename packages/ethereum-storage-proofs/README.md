> **Experimental software. Unaudited. May contain bugs.**

# ethereum-storage-proofs

Host side of the Noir libraries in this repository: it validates raw Ethereum
proofs, chooses capacities, prepares witnesses, generates producer circuits and
drives the pinned compiler and backend. Install and a minimal example are in the
[repository README](../../README.md#typescript-sdk); [index.d.ts](index.d.ts) is the
complete typed API. Host checks do not authenticate the chain, finality or a root
the application chose, and proving and key generation run only on explicit calls.

## Requirements

| Task | Needs |
| --- | --- |
| Validation and witness preparation | Node.js 20+ |
| Profiles, `prepareCircuit`, proving, the CLI | Python 3.11+ (standard library only) |
| `execute: true`, proving, linking | Noir 1.0.0-rc.3, the compiler Aztec 6.0.0 pins: `scripts/bootstrap-noir.sh` installs it in `.tools/noir` (Linux x86_64), or set `NARGO_BIN` |
| Proving, linking | bb 6.0.0 as released (its SHA-256 is pinned); `bbSha256` admits another reviewed build of the same protocol |

The pins are in [toolchain.json](toolchain.json); `storage-proofs doctor` prints
them and checks the compiler. Generated circuits depend on the Noir packages by
path: in a checkout, on `noir/` at the repository root; in an installed package, on
the copy that `npm run build` (run by `npm pack`) stages in `dist/library/noir`.

## Inputs

State proofs use a saved EIP-1186 envelope `{stateRoot, proof: eth_getProof_result}`
with every field the scope needs (storage-only scopes need `storageHash` and
`storageProof`; account-only scopes no storage proofs). Preparing saved input is
offline. Fetch the header and the proof at the **same block**.

`fetchProof({rpcUrl, address, slots, block})` is the explicit live route: it
resolves the selector (`latest`, `earliest`, `safe`, `finalized` or a hex number;
not `pending`) to one block, requests all slots in one `eth_getProof`, re-reads that
block's hash and state root, validates every path and rejects a reorg or an
inconsistent response. The provider's finality label is not a consensus check, and
neither route authenticates the root.

Receipts have no standard proof RPC. `buildReceiptProof(encoded, index, {expectedReceiptsRoot, blockNumber, byzantiumBlock})`
rebuilds the receipt trie from **all** encoded receipts of the block and throws
when the root differs from `expectedReceiptsRoot` (the authenticated header root;
`null` only for a synthetic trie you authenticate yourself). With the block number
it requires a post-state root before Byzantium and a status after.
`encodeRpcReceipt` encodes an RPC receipt's consensus fields, including historical
`root`; some providers return a synthesised `status: "0x1"` instead of `root` for
pre-Byzantium receipts, and the root mismatch then reports it. The receipt input
envelope is `{receiptsRoot, transactionIndex, receipt, proof, logIndex}`, where
`receipt` is the consensus byte string including any type prefix and `logIndex` is
receipt-local.

Absence inputs reuse the EIP-1186 envelope: `storage_zero` needs `storageHash` and
the zero `storageProof` entry, `account_absent` the state root, address and account
proof, `l1_zero` both. Inspection verifies non-empty tries with EthereumJS and
compares the canonical empty root for an empty trie.

For single-slot scopes, an input with several `storageProof` entries needs
`slotIndex` (`--slot-index`); inspection, preparation and proving use that entry and
check the claim's `slot_key` against it. Option objects reject unknown keys with a
`TypeError`. Arguments go to subprocesses without a shell; use fresh output
directories. Failures throw `ToolError` with the script, exit status and output.

Host values: root limbs are four little-endian u64 lanes as decimal strings; slot
keys and claim values are 32-byte big-endian words; a threshold `minimum` is a full
uint256 `bigint`.

## API

| API | Role |
| --- | --- |
| `fetchProof` | Exact-block, multi-slot RPC fetch with local trie validation |
| `prepare`, `prepareAccount`, `prepareStorage` | Validate paths and build single-path witnesses |
| `prepareBatchStorage`, `prepareMixedBatch` | Deduplicate shared nodes; uniform or mixed batch witnesses |
| `encodeRpcReceipt`, `decodeReceipt`, `buildReceiptProof` | Consensus receipt encoding and receipt-trie reconstruction |
| `inspectReceiptProof`, `prepareReceipt`, `prepareEvent` | Verify receipt proofs and build receipt and event witnesses |
| `inspectAbsenceProof`, `prepareStorageZero`, `prepareAccountAbsent`, `prepareL1Zero` | Verify absence proofs; return `{witness, claim}` |
| `inspectProof`, `recommendProfile`, `autoProfile` | Inspect valid paths and recommend or generate a fitting profile |
| `validateProfile`, `fitsProfile`, `profileCost`, `selectProfile` | Check or select a profile from a caller-owned catalogue |
| `generateProfile` | Generate a producer circuit for an explicit typed `Profile` |
| `prepareCircuit` | Exact producer inputs; optionally compile and solve |
| `proveRecursiveProof` | Prove and natively verify a producer proof; optionally its recursive consumer too |
| `proveLinkedRecursiveProofs` | Prove and verify the composition of an app proof and a user proof |
| `checkRecursiveProofExport` | JSON shape and canonical encodings only |

## Choosing capacities

`autoProfile` validates the paths, then picks byte capacities of 135, 271, 407 or
532 (1 to 4 Keccak permutations) by a hash-capacity estimate, not a gate-minimal
search. Profiles accept 1 to 64 slots and path capacities of 0 to 64. Shared parsing
helps when paths reuse nodes and can cost more for one slot.

`recommendProfile` and `autoProfile` size a profile for the proof they inspected,
with no headroom; pass `extraDepth` (extra 532-byte positions) and `fullWidth: true`
(`--extra-depth`, `--full-width`) to add some. Mainnet paths can be lengthened by
anyone, so read [choosing capacities](../../docs/internals.md#choosing-capacities)
before fixing a shape. When a shape does not fit, the error names the path, node and
needed size, and catalogue selection says why each profile was rejected.

## Linked proofs

`proveLinkedRecursiveProofs` takes an app account proof and a user proof, made
independently, and proves the consumer in [proving/linked](proving/linked) for the
chosen mode (`storage`, `threshold`, `batch`, `storage_zero`). It requires
`appVkHash` and `userVkHash` from the caller's policy (for example `bb write_vk` over
the audited producer sources) and fails if a bundle names another key. Its outer
UltraHonk proof is for testing; inside an Aztec private function, pass the two
`bundle.recursive_proof` fields to the linked consumers of `ethereum_recursive_proofs`.

## CLI

| Command | Purpose |
| --- | --- |
| `storage-proofs fetch --rpc URL --address A [--slot K ...] [--block B] [--output F]` | Live fetch; credentials never reach output or errors |
| `storage-proofs inspect INPUT SCOPE [CATALOGUE] [--profile P] [--slot-index I]` | Inspect shapes and explain profile fit |
| `storage-proofs profile --input INPUT --scope S --output DIR` | Generate an automatically sized profile |
| `storage-proofs generate DIR --scope storage --storage-depth 8` | Single-path profile, optional per-position capacities |
| `storage-proofs generate-batch DIR --slots 16 --nodes 5 --depth 2 --bytes 271 --shared-parsing` | Batch profile (`--buckets 3,1,0,0` for mixed) |
| `storage-proofs generate-receipt DIR --scope event --depth 2 --node-bytes 135 --leaf-bytes 532 --max-logs 2 --data-bytes 56` | Receipt or event profile |
| `storage-proofs generate-absence DIR --scope storage_zero --depth 4 --node-bytes 532 --terminal-bytes 532` | Absence profile (`l1_zero` adds `--account-depth`, `--account-bytes`) |
| `storage-proofs prepare` / `convert --profile DIR --input INPUT --output OUT [--execute]` | Validate and write witness JSON and TOML; optionally solve |
| `storage-proofs prove --profile DIR --input INPUT --output OUT --bb BB [--recursive-check]` | Produce and verify a recursive proof |
| `storage-proofs link --app APP --user USER --mode batch --output OUT --bb BB [--negative-checks]` | Produce and verify the linked proof |
| `storage-proofs check-export FILE` | Structural export checks only |
| `storage-proofs doctor` | Show the pins and check the compiler |

`prove --recursive-check` also proves the recursive consumer and requires every
changed claim, key and proof (including substituted last commitments, which only
the pairing check can reject) to be rejected. Generated leaf-only profiles omit
empty array inputs (the pinned compiler rejects them in a binary ABI) and build
them inside the circuit. Compile generated circuits through these tools: nargo
otherwise picks up an enclosing `Nargo.toml`.

## Outputs and cache

| Artifact | Meaning |
| --- | --- |
| `profile.json`, `src/main.nr`, `Nargo.toml` | Generated producer shape and circuit |
| `selection.json` | Inspection, recommendation and selected catalogue entry |
| `prepared.json`, `witness.json`, `ProducerProver.toml`, `claim.json` | Validated paths, witness inputs, claim preimage |
| `circuit/*.json`, `*.gz` | Compiled circuit and solved witness (not a proof) |
| `recursive_proof.json` | Protocol and profile metadata, proof, verification key and claim |
| `RecursiveProver.toml`, `recursive.nr`; `ConsumerProver.toml`, `main.nr` | Single and linked consumer inputs and sources |
| `results.json`, logs | Checks performed, hashes and timings |

Outputs can contain private witness data. The optional `cache` stores compiled
artifacts only, keyed by sources, manifests, toolchain and binary hashes, and
revalidates transitive Noir sources on a hit; keep it under a trusted writer.
Compiler, dependency or profile changes require matching keys before reusing a
recursive proof.

## Tests

```bash
npm ci --ignore-scripts
npm run build       # stage dist/library, LICENSE and NOTICE (also run by npm pack)
npm run typecheck   # index.d.ts and tests/**/*.ts
npm test            # node --test, then the Python unit tests
```

The tests use saved or mocked data only: no network, compiler, backend, keys or
proofs. The saved inputs in `tests/fixtures` are generated with the repository's
other fixtures by `python3 scripts/generate.py` (see
[CONTRIBUTING](../../CONTRIBUTING.md#generated-files)).
