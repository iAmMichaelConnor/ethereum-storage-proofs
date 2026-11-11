> [!WARNING]
> **This code has not been audited.** It is experimental software, provided "as is", without warranty of any kind (see [LICENSE](LICENSE)). A bug can leave a circuit under-constrained, so that invalid proofs are accepted. Do not rely on it to protect real assets or sensitive data without your own independent review.

> [!NOTE]
> This is an independent project. It is not affiliated with, sponsored by or endorsed by the Ethereum Foundation or any other Ethereum organisation. Names and logos belong to their owners and are used only to say what this software works with.

<a href="https://ethereum.org/"><img src="docs/assets/ethereum.svg" width="48" alt="Ethereum"></a>

# ethereum-storage-proofs

**Prove facts about Ethereum state inside a Noir circuit, and reveal only what you
choose.** Bring L1 balances, storage and events into any Noir program or Aztec
private function, straight from `eth_getProof`.

For example, you can:

- Prove an account exists, with its balance, nonce, code hash and storage root.
- Prove an account does not exist.
- Prove a storage slot holds a particular value: an ERC-20 balance, an NFT owner, a
  registry entry.
- Prove a storage value is at least some amount, without revealing it.
- Prove a storage slot is empty.
- Prove many slots of one contract at once.
- Prove a transaction's receipt: its status, gas used and logs.
- Prove a contract emitted an exact event.
- Prove an execution state root belongs to a beacon block root.
- Verify any of these inside an Aztec private function, as a recursive proof made by
  a separate circuit.

Prove any of these against the latest block or a historical one: each proof is
checked against a state root, receipts root or beacon block root that you choose.
The claims can be composed, and programmably customised or expanded: one circuit
can combine several of them and add its own checks on the values they expose (a
balance, an address, an event's fields).

Everything is proven under a root you already trust: Merkle-Patricia proofs in the
state and receipts tries, and SSZ branches up to a beacon block root.

The libraries check the opening you give them. They do **not** establish Ethereum
consensus or finality, nor that a root belongs to the chain you intend: binding the
root to an authenticated header, and deciding which producer keys, effects and
replay rules to accept, is the application's job. Read the
[consumer obligations](docs/proofs.md#consumer-obligations) before using them.

## What is in the repository

| Package | Contents |
| --- | --- |
| [`ethereum_proofs`](noir/ethereum_proofs) | Account and storage inclusion (`proof`), shared-node batches (`batch`), absence (`absence`), receipts and events (`receipts`, `events`), RLP framing (`rlp`), Solidity slot keys (`slot_key`), leaf encoders (`encoding`) |
| [`ethereum_recursive_proofs`](noir/ethereum_recursive_proofs) | Claims, domain-separated statements and UltraHonk recursive consumers, including linked app and user proofs |
| [`ethereum_ssz`](noir/ethereum_ssz) | SHA-256 SSZ branches and the Deneb/Electra/Fulu execution-payload anchor |
| [`ethereum_keccak`](noir/ethereum_keccak) | Keccak-256 over bounded buffers, safe under a disabled caller, and a streaming `KeccakHasher` |
| [`ethereum_types`](noir/ethereum_types) | `Account`, `StorageSlot` and canonical quantity conversions |
| [`ethereum_storage_proofs`](noir/ethereum_storage_proofs) | Re-exports all of the above in one dependency |

| Claim | API (direct; recursive) | What the caller still supplies |
| --- | --- | --- |
| Account exists with given fields | `verify_account_proof`; `verify_account_recursive_proof` | Authenticated state root, intended address |
| Nonzero storage value(s) | `verify_storage_proof`, `verify_account_and_storage_proof`, `batch`; `verify_storage_recursive_proof`, `verify_l1_recursive_proof`, `verify_batch_storage_recursive_proof` | Root and account policy, [slot key](docs/proofs.md#slot-keys-and-conversions), authorized producer key |
| Storage value at least a minimum (full uint256) | `verify_threshold_recursive_proof` | Slot and minimum ([threshold semantics](docs/proofs.md#recursive-proofs)) |
| Zero slot, absent account, present account with a zero slot | `absence`; `ethereum_recursive_proofs::absence` | Root and key policy |
| Receipt or exact event log | `verify_receipt`, `verify_event`; `ethereum_recursive_proofs::receipts` | Authenticated receipts root, transaction index, receipt-local log index |
| SSZ field, execution state root under a beacon root | `ethereum_ssz::verify_branch`, `verify_deneb_execution_anchor_at_slot` | Schema, generalized index, authenticated beacon root and fork range |
| Transaction hash or body; root finality | Not implemented | A transaction-trie relation; a bridge, header or light-client policy |

Capacities (path depth and bytes per node) are compile-time and fail closed. A
shape fits the proofs it was sized for, and a third party can lengthen mainnet
paths: see [choosing capacities](docs/internals.md#choosing-capacities).

### Aztec examples

[`examples/`](examples) holds Aztec contracts that use the libraries, each with
tests of its logic:

| Example | What it does |
| --- | --- |
| [`storage_proofs`](examples/storage_proofs) | Verifies an app account proof and a user batch proof recursively, against producer keys and a state root the deployer pins |
| [`event_proof`](examples/event_proof) | Applies an effect once per Ethereum log of one kind, proven under the receipts root of a pinned block |
| [`registry_gate`](examples/registry_gate) | Admits the Aztec addresses an L1 registry mapping lists, proven under a pinned state root |

## Compatibility

The Noir packages are tested with Noir 1.0.0-rc.3, the minimum supported
version (what Aztec 6.0.0 ships), and with Noir 1.0.0, the latest release, on
every pull request, and with Noir nightly every night. Keep this in sync with
the `toolchain` matrix in `.github/workflows/test.yml`.

- `ethereum_keccak` depends on [noir-lang/keccak256](https://github.com/noir-lang/keccak256)
  at commit `cce7f909fe481dd01ef0f0501510964aef917e68`, copied to
  [`vendor/keccak256`](vendor/keccak256) because no release contains
  `keccak256_lanes` or the lane-level sponge yet (see [NOTICE](NOTICE)).
- `ethereum_recursive_proofs` depends on [noir-lang/poseidon](https://github.com/noir-lang/poseidon) v0.4.0.
- The recursive consumers verify Poseidon2 UltraHonk proofs (proof type 6) as bb
  6.0.0 produces them, and rely on bb 6.0.0 binding the verification key to its
  hash ([security model](docs/security-model.md#recursive-proofs)).
- The [example contracts](examples) are tested with Aztec 6.0.0 only: Aztec.nr
  `v6.0.0`, nargo 1.0.0-rc.3 and bb 6.0.0. Keep this in sync with `AZTEC_VERSION`
  in `.github/workflows/test.yml` and with [`examples/.aztecrc`](examples/.aztecrc).

## Installation

In your `Nargo.toml`, add the packages you use. Each lives in its own directory of
this repository:

```toml
[dependencies]
ethereum_proofs = { git = "https://github.com/iAmMichaelConnor/ethereum-storage-proofs", tag = "v0.1.0", directory = "noir/ethereum_proofs" }
ethereum_recursive_proofs = { git = "https://github.com/iAmMichaelConnor/ethereum-storage-proofs", tag = "v0.1.0", directory = "noir/ethereum_recursive_proofs" }
```

`ethereum_proofs` re-exports `ethereum_types` (as `types`) and `ethereum_keccak`
(as `keccak`).

## Usage

Roots and hashes are four little-endian `u64` lanes in digest order; quantities are
minimal big-endian bytes, left-aligned, with their length. Path nodes are the RLP
bytes from `eth_getProof`, excluding the leaf, zero-padded to the node capacity
([representation](docs/proofs.md#representation)).

An account's ETH balance and nonce, under a state root the caller trusts:

```rust
use ethereum_proofs::{proof::EncodedNode, types::Account, verify_account_proof};

fn account_balance(
    state_root: [u64; 4],
    address: [u8; 20],
    account: Account,
    account_nodes: [EncodedNode<135>; 2],
    account_count: u32,
) -> (Field, u64) {
    assert_eq(account.address, address, "proof is for a different account");
    verify_account_proof(state_root, account, account_nodes, account_count);
    (account.balance_as_field(), account.nonce_as_u64())
}
```

An ERC-20 balance, for a token whose `balances` mapping is at declaration slot 9
(a layout you must check for each token):

```rust
use ethereum_proofs::{
    proof::EncodedNode, slot_key::address_mapping_slot, types::{Account, StorageSlot},
    verify_account_proof, verify_storage_proof,
};

fn erc20_balance(
    state_root: [u64; 4],
    token: [u8; 20],
    holder: [u8; 20],
    account: Account,
    account_nodes: [EncodedNode<135>; 2],
    account_count: u32,
    value: StorageSlot,
    storage_nodes: [EncodedNode<135>; 2],
    storage_count: u32,
) -> u128 {
    assert_eq(account.address, token, "proof is for a different account");
    verify_account_proof(state_root, account, account_nodes, account_count);
    let key = address_mapping_slot(holder, 9);
    verify_storage_proof(account.storage_hash, key, value, storage_nodes, storage_count);
    value.to_u128()
}
```

Both are tested against EthereumJS tries in
[`balance_tests.nr`](noir/ethereum_proofs/src/balance_tests.nr). The
[API guide](docs/proofs.md) covers batches, absence, receipts, events, SSZ and the
recursive consumers; the producer circuits that the recursive consumers expect are
the shapes in [`ethereum_storage_proofs/src/benchmarks.nr`](noir/ethereum_storage_proofs/src/benchmarks.nr).

### TypeScript SDK

[`ethereum-storage-proofs`](packages/ethereum-storage-proofs) prepares the inputs of these
libraries from `eth_getProof` results and receipts. It validates the proofs, sizes
capacities, generates a producer circuit for the shape and writes its witness; on
request it also compiles, proves and links proofs with the pinned Noir 1.0.0-rc.3
and bb 6.0.0. It does not authenticate roots or authorize keys. It is not published
to npm: pack it in a checkout and install the tarball.

```bash
cd packages/ethereum-storage-proofs && npm ci --ignore-scripts && npm pack   # stages noir/, LICENSE and NOTICE
npm install /path/to/ethereum-storage-proofs-0.1.0.tgz                       # in your project
```

```ts
import { autoProfile, prepareCircuit } from "ethereum-storage-proofs";

// rpc.json is {stateRoot, proof}: an eth_getProof result and the state root of the same block.
const profile = await autoProfile({ input: "/abs/rpc.json", scope: "l1", output: "/abs/profile" });
await prepareCircuit({ profile: profile.directory, input: "/abs/rpc.json", output: "/abs/inputs" });
// /abs/inputs holds witness.json and ProducerProver.toml; `execute: true` also compiles and solves.
```

Profiles and circuit preparation also need Python 3.11+. The
[SDK README](packages/ethereum-storage-proofs/README.md) covers the requirements, inputs,
API, CLI and proving.

## Benchmarks

Circuit size (`bb gates` `circuit_size`) of selected `#[export]` benchmark
functions, measured with Noir 1.0.0 and bb 6.0.0 on 2026-11-11. Each count is the
whole function, including its ABI. The [benchmark workflow](.github/workflows/benchmark.yml)
reports every benchmark on pull requests and records history on the `gh-pages`
branch.

| Operation | Benchmark | Circuit size |
| --- | --- | ---: |
| Keccak-256, 135-byte capacity (one permutation) | `keccak256_135` | 40,618 |
| Keccak-256, 532-byte capacity | `keccak256_532` | 74,658 |
| Storage value, 3 nodes of 135 bytes | `storage_general_d3_b135` | 106,616 |
| Storage value, 8 nodes of 532 bytes | `storage_general_d8_b532` | 649,082 |
| Storage value, 8 nodes of 532 bytes, hash-only | `storage_hashed_d8_b532` | 635,989 |
| Account balance and nonce (README example) | `account_balance` | 101,020 |
| ERC-20 balance (README example) | `erc20_balance` | 199,979 |
| Storage producer, 4 hash-only nodes of 271 bytes | `storage_small` | 193,993 |
| Account and storage producer, 8 + 8 nodes of 532 bytes | `l1_d8` | 1,319,021 |
| Batch producer, 4 slots sharing 3 nodes of 135 bytes | `batch4` | 241,647 |
| Receipt producer, depth 4, 1,024-byte receipt | `receipt_summary` | 456,840 |
| Event producer, depth 4, 256 data bytes | `event` | 511,761 |
| Zero-slot producer, depth 4 | `storage_zero` | 409,455 |
| Deneb execution anchor | `ssz_deneb_anchor` | 118,110 |
| Recursive consumer, one producer proof | `consume_storage` | 703,174 |
| Recursive consumer, linked app and user proofs | `linked_storage` | 1,468,740 |

The recursive consumers are measured as standalone Noir programs; inside an Aztec
private function their cost is accounted differently, and they have no Brillig
form, so the Brillig report leaves them out. To generate the reports
locally:

```bash
./scripts/build-gates-report.sh
rm -rf noir/export export
for package in ethereum_keccak ethereum_ssz ethereum_proofs ethereum_storage_proofs; do
  nargo --program-dir noir export --package $package --force-brillig
done
mv noir/export export
./scripts/build-brillig-report.sh
```

## Security

If you find a vulnerability, please **do not** open a public issue. Report it
privately via [GitHub's "Report a vulnerability"](https://github.com/iAmMichaelConnor/ethereum-storage-proofs/security/advisories/new)
form instead.

The [security model](docs/security-model.md) states the accepted input domains,
the bounds and their justification, the inactive-call obligations and the backend
premises. The [API guide](docs/proofs.md#consumer-obligations) lists what an
application must still enforce. [Internals](docs/internals.md) covers capacity
sizing, the Keccak wrapper and what the tests establish.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
