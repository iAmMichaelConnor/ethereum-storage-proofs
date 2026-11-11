# Contributing

Thank you for your interest in contributing! This guide covers the
[layout](#layout), [setup](#setup), [tests](#tests), [benchmarks](#benchmarks),
[generated files](#generated-files), [vendored code](#vendored-code),
[releases](#releases) and how this repository [differs from the
noir-library-starter
template](#differences-from-the-noir-library-starter-template). Keep pull
requests focused, and open an issue first for anything substantial. Breaking
changes must update the README or the documentation. Run every command below
from the repository root.

## Layout

```
noir/                     Nargo workspace of the libraries, one package per directory
noir/<package>/src/benchmarks.nr   #[export] benchmark functions
examples/                 Nargo workspace of the Aztec example contracts (.aztecrc, noirfmt.toml)
examples/<name>/contract  an example contract
examples/<name>/tests     its tests (a sibling crate, as `aztec new` lays them out)
tests/ethereum_oracle_tests/
                          differential tests with their oracle server, outside both workspaces
packages/ethereum-storage-proofs/
                          the TypeScript SDK (npm package ethereum-storage-proofs) and its tests
scripts/                  test, benchmark and fixture-generation scripts
scripts/witness/          witness encoders the fixture generators use (EthereumJS-based)
reference/                third-party reference input for the generators (see NOTICE)
vendor/keccak256/         noir-lang/keccak256 at a pinned commit (see NOTICE)
docs/                     API guide, security model, internals
```

## Setup

- Noir: install with [noirup](https://github.com/noir-lang/noirup), e.g.
  `noirup -v 1.0.0`. Either version CI tests works (see the README).
- Node.js 22 and `npm ci --prefix scripts`, to regenerate the test fixtures,
  and `npm ci --prefix tests/ethereum_oracle_tests`, to run the oracle tests
  (EthereumJS is the independent reference). Python 3, standard library only.
- For the SDK:
  `npm ci --ignore-scripts --prefix packages/ethereum-storage-proofs`, and
  Python 3.11+ for its circuit and proving commands.
- bb, only for benchmarks:
  `curl -L https://bbup.aztec.network | bash && ~/.bb/bbup -v 6.0.0`.
- The Aztec toolchain, only for the example contracts:
  `curl -fsSL https://install.aztec-labs.com | VERSION=6.0.0 bash`.

## Tests

```bash
nargo --program-dir noir test --force-brillig --inliner-aggressiveness 0 --workspace                # all libraries, as pull requests run them
nargo --program-dir noir test --force-brillig --inliner-aggressiveness 0 --package ethereum_proofs  # one package
nargo --program-dir noir test --package ethereum_proofs --test-threads 4                            # one package constrained, as the nightly slow mode runs it
./scripts/test-examples.sh                                                                          # example contracts (Aztec toolchain)
tests/ethereum_oracle_tests/run.sh                                                                  # differential tests against EthereumJS (Node.js)
nargo --program-dir noir fmt --check
nargo --program-dir tests/ethereum_oracle_tests fmt --check
(cd examples && aztec-nargo fmt --check)
npm run build --prefix packages/ethereum-storage-proofs                                             # SDK: stage dist/library
npm run typecheck --prefix packages/ethereum-storage-proofs
npm test --prefix packages/ethereum-storage-proofs
```

`nargo test` proves nothing: it compiles each test and executes it. Run as
written (constrained), each test compiles to an ACIR circuit; with
`--force-brillig` the same test compiles to unconstrained bytecode and executes
the same assertions much faster, and `--inliner-aggressiveness 0` shortens
compiling that bytecode. Pull requests run every library with both flags; the
nightly workflow runs the same set on Noir nightly, and every package
constrained on Noir 1.0.0 (the slow mode), so the constrained tests execute
their ACIR there. Constrained tests pass their inputs through
`std::hint::black_box` (some modules use an unconstrained identity `witness()`,
to the same effect) so that the compiler cannot fold them away; several tests
depend on that to exercise a runtime-disabled branch. Memory grows with
`--test-threads` (nargo's default is one thread per core); CI passes 4, the
vCPUs of a hosted runner. Measured locally with Noir 1.0.0, as CI runs each
mode:

| Package | Tests | Per pull request: unconstrained, 4 threads | Nightly: constrained, 4 threads |
| --- | ---: | --- | --- |
| `ethereum_types` | 55 | 3 s, 0.2 GB | 4 s, 0.2 GB |
| `ethereum_keccak` | 12 | 3 s, 0.2 GB | 4 s, 0.3 GB |
| `ethereum_proofs` | 58 | 3 s, 0.3 GB | 6 s, 0.3 GB |
| `ethereum_recursive_proofs` | 20 | 2 s, 0.3 GB | 3 s, 0.4 GB |
| `ethereum_storage_proofs` | 1441 | 1 min 18 s, 1.6 GB | unmeasured (over 10 min) |

`ethereum_ssz` has no tests of its own and is not in the test matrices:
`ethereum_storage_proofs` tests its branches (`ssz_tests.nr`). The constrained
run of `ethereum_storage_proofs` has not been run to completion locally, so its
nightly job has a 120-minute timeout; the other nightly jobs have 30 minutes.
The nightly workflow also compiles the example contracts (`aztec-nargo compile
--workspace` in `examples/`), which pull requests only type-check.

The oracle tests in `tests/ethereum_oracle_tests` compare the verifiers with
EthereumJS on random cases. The crate is in neither workspace, so `nargo test`
never selects it: the tests need the server `oracle_server.mjs` beside them,
which the crate's `run.sh` starts on port 8095 and stops after running the
tests with the pull-request flags. Each test takes a random
seed, which nargo's fuzzer varies for one second. From the seed the server
builds a case with EthereumJS tries and RLP, and the test checks that the
verifier accepts it and decodes the fields the server encoded:

| Test | Random case |
| --- | --- |
| `storage_inclusion` | A stored value in a raw-key trie of one to five values whose keys share prefixes of 0 to 64 nibbles: extensions of every length, embedded leaves and, rarely, embedded branches |
| `storage_absence` | A key that leaves a stored key of such a trie at a random nibble, ending at a branch, extension or leaf |
| `account_leaf` | An account leaf at a random nibble, with nonce and balance of every length |
| `receipt_and_event` | A receipt of type 0 to 4 in a receipts trie of up to four transactions, with up to three logs of up to four topics and 256 data bytes; its decoded fields and one log as an event |

A failure prints the seed, from which the server rebuilds the same case. The
tests show that the verifiers accept valid proofs of shapes that the fixed
vectors do not enumerate. They do not show that an invalid proof is rejected:
nargo requires a fuzzed test to pass for every input (or, with `should_fail`,
to fail for every input), so rejections are left to the generated adversarial
tests. The tests are unconstrained, so they execute the verifiers' Brillig
form, not their circuits, and the cases fit the capacities in
`tests/ethereum_oracle_tests/src/lib.nr` (eight internal nodes of 532 bytes,
receipt leaves of 1024 bytes). On four cores of the local machine a run took 7 s and 0.2 GB with Noir
1.0.0-rc.3, and the fuzzer tried about 900 seeds for `account_leaf`, 300 for
each storage test and 170 for `receipt_and_event`; the server is the
bottleneck. CI runs them in the format job, on Noir 1.0.0-rc.3.

The other pull-request jobs are short too: the benchmark workflow (gate and
Brillig exports) took under 3 minutes locally, and the examples job's type-check
and tests about a minute, so expect a pull request's checks to finish in about 5
minutes.

The example tests never compile or deploy a contract: each contract function's
body is a plain function in the example's crate, and the tests call those in TXE
test contexts (`env.private_context`, `env.public_context`). `test-examples.sh`
runs them against a TXE on port `TXE_PORT` (default 8081); CI also type-checks
the contracts with `aztec-nargo check --workspace`. TXE generates no proofs, and
executing a circuit does not verify its recursive proofs. The tests take storage
slots from each contract's `storage_layout()`. What the example tests do not
cover, because only a deployed contract has them:

- The `#[only_self]` attribute on `record_event`, `admit` and
  `record_acceptance`: without it anyone could raise the counters, and anyone
  could make `admit` write any value for any beneficiary.
- That `on_event`, `claim` and `accept` enqueue their public halves, and that
  `claim` passes `admit` the beneficiary and value that `apply_claim` returns.
- That `on_event`, `claim` and `accept` read the stored terms hash or policy:
  the tests pass it to the tested function themselves.
- That the constructors store `terms.hash()` (EventProof, RegistryGate) or the
  checked policy and a zero counter (StorageProofs).
- The `count` and `membership` views.
- The soundness of the app and user proofs that StorageProofs verifies
  recursively: its test runs on placeholder proofs.

The SDK tests use saved and mocked inputs only, so they need neither nargo, bb
nor a network. They do not compile the producer circuits the SDK generates;
after a change to a Noir API those circuits use, run `prepareCircuit` with
`execute: true` (or `storage-proofs prepare --execute`) on one profile per
scope, with Noir 1.0.0-rc.3 as `NARGO_BIN`.

Every assertion that a test expects to fail has a message, and each rejection
test names it with `#[test(should_fail_with = "...")]`.

## Benchmarks

On pull requests the benchmark workflow runs only when a change can alter a
circuit (library sources, the workspace manifest, the report scripts or the
workflow itself); every push to `main` runs it.

Each library package has a `benchmarks.nr` module of `#[export]` functions;
names are unique across the workspace. See the README for the commands; the
benchmark workflow posts the gate and Brillig diffs on pull requests and records
history on the `gh-pages` branch, which must exist before the first workflow
run.

## Generated files

The large Noir test modules and the example contracts' test fixtures are
generated; do not edit them by hand. `python3 scripts/generate.py` runs every
generator in a scratch copy of the repository, formats the Noir output with
`nargo fmt` (`$NARGO`, else `nargo` on `PATH`) and copies back what changed;
with `--check` it fails if a committed file is stale (CI runs it). Expected
values come from independent references, never from the code under test.

| Generator | Writes | From |
| --- | --- | --- |
| `generate_quantity_vectors.py` | `ethereum_types/src/reference_vectors.nr` | Python integers |
| `generate_fixtures.mjs` | `ethereum_storage_proofs/src/{fixtures,adversarial}_tests.nr`, `ethereum_proofs/src/slot_key_vectors.nr` | EthereumJS tries; `reference/aztec-node/storage_proof.json` |
| `generate_ssz.py` | `ethereum_storage_proofs/src/ssz_tests.nr` | Python `hashlib` |
| `generate_completeness.mjs` | `ethereum_storage_proofs/src/completeness_tests.nr` | EthereumJS RLP and Keccak |
| `generate_abi_tests.mjs` | `ethereum_proofs/src/balance_tests.nr`, `ethereum_storage_proofs/src/{batch,receipt,absence,empty_child}_tests.nr` | EthereumJS tries and `scripts/witness` |
| `generate_example_fixtures.mjs` | `examples/{event_proof,registry_gate}/tests/src/fixture.nr` | EthereumJS tries and `scripts/witness` |
| `generate_sdk_fixtures.mjs` | `packages/ethereum-storage-proofs/tests/fixtures/**/*.json` | EthereumJS tries; `rpc.json` from `generate_fixtures.mjs` |

`generate_abi_tests.mjs` also records which check rejects each mutation; when a
change moves a rejection to another check, update the expectation there.

## Vendored code

`./scripts/vendor.sh` rebuilds `vendor/keccak256` from the noir-lang/keccak256
commit pinned in the script; with `--check` it fails if the committed copy
differs (CI runs it). To move to a new commit, change it in the script, `NOTICE`
and the README's compatibility section, and run the script. The copy is only a
path dependency of `ethereum_keccak`, not a workspace member: its own tests are
upstream's to run.

## Releases

Pull request titles follow [Conventional
Commits](https://www.conventionalcommits.org/en/v1.0.0/), which drive the
changelog and version numbers:

```
<type>[optional scope]: <description>
```

- `feat:` new functionality (appears in the changelog);
- `fix:` bug fixes (appears in the changelog);
- `chore:` everything else (omitted from the changelog unless breaking).

Mark a breaking change with `!` after the type or scope, e.g.
`feat(ethereum_proofs)!: Return the verified value`. Use the package name as the
scope when a change touches one package.

[Release Please](https://github.com/googleapis/release-please) runs on every
push to `main`. It opens or updates a release pull request with the next version
and the changelog; merging that pull request tags the release. All packages
share one version and one tag. The first release is v0.1.0.

The release workflow uses the default `GITHUB_TOKEN`, and pull requests opened
with it do not trigger CI; to run the checks on release pull requests, replace
it in `release.yml` with a personal access token stored as a repository secret.

### Publishing checklist

Before the first release:

- create an empty `gh-pages` branch, where the benchmark workflow records
  history;
- enable private vulnerability reporting in the repository's security settings,
  for the README's reporting link.

## Differences from the noir-library-starter template

- **Two workspaces, libraries under `noir/`.** The repository publishes several
  libraries, so consumers add a `directory` to the git dependency. The example
  contracts need the Aztec toolchain, which pins its own nargo, so they form a
  second workspace in `examples/`. Nargo resolves a package to the outermost
  workspace above it, so neither workspace can sit at the repository root:
  commands take `--program-dir noir`, and the benchmark workflow moves
  `noir/export` to `export` before running the template's Brillig report script.
- **Two Noir versions per pull request.** The template tests every Noir release
  from the minimum supported version, and nightly, on each pull request. This
  repository tests the two ends, 1.0.0-rc.3 (the minimum, which Aztec 6.0.0
  ships) and 1.0.0 (the latest release), per pull request, and Noir nightly in
  the nightly workflow.
- **Tests run per package, with a thread cap, unconstrained on pull requests.**
  One CI job per package and toolchain runs
  `nargo test --force-brillig --inliner-aggressiveness 0 --test-threads 4`; the
  nightly workflow runs the tests constrained, one job per package.
- **An examples job for the example contracts.** It installs Aztec 6.0.0 with
  the official installer, type-checks the contracts and runs
  `scripts/test-examples.sh` (TXE). The contracts' formatting uses Aztec.nr's
  settings (`examples/noirfmt.toml`); the libraries use `nargo fmt` defaults.
  The Noir nightly canary covers the libraries only, because Aztec.nr supports
  one nargo version per release; the nightly workflow compiles the contracts on
  Aztec 6.0.0.
- **Oracle tests in their own crate, with a plain Node.js server.** Most
  reference values are fixed vectors generated into the library tests, so
  `nargo test` needs nothing else. The template keeps its oracle tests beside
  the library code, where `nargo test` fails without a server; here they live
  in `tests/ethereum_oracle_tests`, which only its `run.sh` runs. Its server is
  one `.mjs` file on `node:http` with EthereumJS pinned in the crate's
  `package.json`, instead of TypeScript, Express and yarn. The template's oracle recomputes a
  function of the test's arguments; a trie proof cannot be drawn that way, so
  the server builds each case from a random seed. The tests are `unconstrained`
  because the fuzzer also compiles a constrained copy of each test, which for a
  constrained test would be a full verifier circuit. CI runs them once, in the
  format job, rather than on every toolchain.
- **A host job.** The TypeScript SDK in `packages/ethereum-storage-proofs` is
  installed, built, type-checked and tested in its own job; it needs no Noir
  toolchain.
- **Generated tests need Node.js.** The format job installs Node.js and the
  generator dependencies, and runs `scripts/generate.py --check`. Python's
  standard library has no Keccak-256 or trie implementation, so the
  Ethereum-specific references are EthereumJS (MPL-2.0). It is a development
  dependency of the generators and a runtime dependency of the SDK, which uses
  it unmodified from npm; no EthereumJS source is copied into this repository.
- **Producer circuits are benchmark functions.** The recursive consumers expect
  proofs from producer circuits; their reference shapes are the `#[export]`
  functions in `ethereum_storage_proofs/src/benchmarks.nr`, which the
  real-witness tests also call.
- **The Brillig report leaves out `ethereum_recursive_proofs`.** Recursive proof
  verification has no unconstrained form, so the workflow exports the other
  packages one by one with `--force-brillig`.
- **bb is installed by version.** `bbup -nv` cannot resolve Noir 1.0.0 (no entry
  in bbup's version map), so the benchmark workflow names bb 6.0.0 directly and
  measures with Noir 1.0.0 rather than the minimum version.
- **Release Please starts at 0.1.0** (`initial-version`), not at the template's
  0.0.0.
- **Workflows trigger on `main`**, not `master`, and third-party actions are
  pinned by commit.
