#!/usr/bin/env python3
"""Regenerate the committed test fixtures; with --check, fail if any is stale.

The generators build their expected values with independent references
(EthereumJS trie, RLP and Keccak; Python hashlib and integers), never with the
Noir code under test. They run in order in a scratch copy of the repository,
because later generators read intermediate files that earlier ones write under
target/fixtures/. The generated Noir is then formatted with `nargo fmt`
($NARGO, else `nargo` on PATH) and compared with the committed files. Without
--check, differing files are copied back.

Requires Node.js and the generator dependencies: `npm ci --prefix scripts`.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

# (command, files it writes that are committed). Run from the repository root.
GENERATORS = [
    (
        ["python3", "scripts/generate_quantity_vectors.py"],
        ["noir/ethereum_types/src/reference_vectors.nr"],
    ),
    (
        ["node", "scripts/generate_fixtures.mjs"],
        [
            "noir/ethereum_storage_proofs/src/fixtures_tests.nr",
            "noir/ethereum_storage_proofs/src/adversarial_tests.nr",
            "noir/ethereum_proofs/src/slot_key_vectors.nr",
        ],
    ),
    (["python3", "scripts/generate_ssz.py"], ["noir/ethereum_storage_proofs/src/ssz_tests.nr"]),
    (
        ["node", "scripts/generate_completeness.mjs"],
        ["noir/ethereum_storage_proofs/src/completeness_tests.nr"],
    ),
    (
        ["node", "scripts/generate_abi_tests.mjs"],
        [
            "noir/ethereum_proofs/src/balance_tests.nr",
            "noir/ethereum_storage_proofs/src/batch_tests.nr",
            "noir/ethereum_storage_proofs/src/receipt_tests.nr",
            "noir/ethereum_storage_proofs/src/absence_tests.nr",
            "noir/ethereum_storage_proofs/src/empty_child_tests.nr",
        ],
    ),
    (
        ["node", "scripts/generate_example_fixtures.mjs"],
        [
            "examples/event_proof/tests/src/fixture.nr",
            "examples/registry_gate/tests/src/fixture.nr",
        ],
    ),
    (
        ["node", "scripts/generate_sdk_fixtures.mjs"],
        [
            f"packages/ethereum-storage-proofs/tests/fixtures/{name}.json"
            for name in [
                "rpc",
                "batch-shared-rpc",
                "batch-inline-rpc",
                "batch-leaf-rpc",
                "absence/cases",
                "receipts/cases",
                "receipts/event",
            ]
        ],
    ),
]

# The Aztec example workspace keeps Aztec.nr's formatter settings.
AZTEC_FMT = "max_width=120\nwrap_comments=true\ncomment_width=120\n"


def nargo():
    return os.environ.get("NARGO", "nargo")


def format_noir(sources, settings):
    """Return each Noir source as `nargo fmt` formats it with `settings`."""
    if not sources:
        return []
    with tempfile.TemporaryDirectory(prefix="fmt-") as scratch:
        package = Path(scratch)
        (package / "src").mkdir()
        (package / "Nargo.toml").write_text(
            '[package]\nname = "fmt_scratch"\ntype = "lib"\nauthors = [""]\n'
        )
        if settings:
            (package / "noirfmt.toml").write_text(settings)
        lib = "".join(f"mod file_{i};\n" for i in range(len(sources)))
        (package / "src/lib.nr").write_text(lib)
        for i, source in enumerate(sources):
            (package / f"src/file_{i}.nr").write_text(source)
        subprocess.run([nargo(), "fmt"], cwd=package, check=True)
        return [(package / f"src/file_{i}.nr").read_text() for i in range(len(sources))]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if a committed file differs")
    check = parser.parse_args().check
    if not (ROOT / "scripts/node_modules/@ethereumjs/trie").is_dir():
        sys.exit("generator dependencies are missing: run `npm ci --prefix scripts`")
    outputs = [path for _, paths in GENERATORS for path in paths]
    with tempfile.TemporaryDirectory(prefix="generate-") as scratch:
        work = Path(scratch) / "repo"
        shutil.copytree(
            ROOT,
            work,
            ignore=shutil.ignore_patterns(
                ".git", "target", "export", "node_modules", "__pycache__", "dist", ".tools"
            ),
        )
        (work / "scripts/node_modules").symlink_to(ROOT / "scripts/node_modules")
        (work / "target/fixtures").mkdir(parents=True)
        for command, _ in GENERATORS:
            subprocess.run(command, cwd=work, check=True)
        generated = {path: (work / path).read_text() for path in outputs}
        for aztec in (False, True):
            group = [p for p in outputs if p.endswith(".nr") and p.startswith("examples/") == aztec]
            formatted = format_noir([generated[p] for p in group], AZTEC_FMT if aztec else None)
            generated.update(zip(group, formatted))
    stale = [p for p in outputs if not (ROOT / p).is_file() or (ROOT / p).read_text() != generated[p]]
    if check:
        if stale:
            sys.exit("stale generated files: " + ", ".join(stale))
        print(f"{len(outputs)} generated files are up to date")
        return
    for path in stale:
        (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / path).write_text(generated[path])
    print(f"updated {len(stale)} of {len(outputs)} generated files")


if __name__ == "__main__":
    main()
