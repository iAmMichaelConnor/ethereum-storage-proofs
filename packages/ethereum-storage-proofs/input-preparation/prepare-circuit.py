#!/usr/bin/env python3
"""Validate an RPC proof and write a generated producer's Noir inputs, without bb."""

import argparse
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tool_runner import NARGO, TOOLCHAIN, save, run, manifest
from witness import prepare_witness


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", type=Path, required=True)
    p.add_argument(
        "--input", type=Path, required=True, help="Saved RPC proof envelope; see README"
    )
    p.add_argument("--output", type=Path, required=True, help="Fresh output directory")
    p.add_argument(
        "--minimum",
        type=int,
        default=1,
        help="uint256 threshold, for threshold scope only",
    )
    p.add_argument(
        "--slot-index",
        type=int,
        help="storageProof entry for single-slot scopes; required if there are several",
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help="Compile and solve the witness with pinned Noir; still no bb or proof",
    )
    p.add_argument(
        "--cache",
        type=Path,
        help="Optional user-owned compiled-artifact cache; never stores witnesses or proofs",
    )
    a = p.parse_args()
    if a.output.exists():
        p.error("Choose a fresh output directory")
    if a.slot_index is not None and a.slot_index < 0:
        p.error("--slot-index must be nonnegative")
    a.output.mkdir(parents=True)
    spec, claim, witness = prepare_witness(
        a.profile, a.input, a.output, a.minimum, a.slot_index
    )
    save(a.output / "witness.json", witness)
    save(
        a.output / "preparation.json",
        dict(
            profile=spec,
            claim=claim,
            slot_index=a.slot_index,
            scope="Witness preparation only; no proof, root authentication or key authorization",
        ),
    )
    if a.execute:
        pin = json.loads(TOOLCHAIN.read_text())
        if pin["noir_commit"] not in subprocess.check_output(
            [NARGO, "--version"], text=True
        ):
            p.error("Wrong Noir compiler; run scripts/bootstrap-noir.sh")
        with tempfile.TemporaryDirectory(prefix="storage-prepare-") as tmp:
            stage = Path(tmp)
            shutil.copytree(a.profile / "src", stage / "src")
            manifest(stage, "storage_producer")
            shutil.copyfile(a.output / "ProducerProver.toml", stage / "Prover.toml")
            from artifact_cache import compile_artifact

            compile_artifact(stage, a.output.resolve(), a.cache)
            run([NARGO, "execute"], stage, a.output.resolve(), "execute")
            shutil.copytree(stage / "target", a.output / "circuit")
    print(a.output.resolve() / "ProducerProver.toml")


if __name__ == "__main__":
    main()
