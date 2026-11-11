#!/usr/bin/env python3
"""Prove app + user recursive proofs in one constrained function.

The producer key hashes are policy: pass them with --app-vk-hash and --user-vk-hash
from an audited source (for example `bb write_vk` over the audited producer
sources). A bundle's producer_vk_hash is only the prover's
claim about its own key; it is compared with the policy, never used as policy.
The claims and roots remain test policy, not an authenticated production policy.
"""

import argparse
import copy
import json
from pathlib import Path
import shutil
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tool_runner import (
    ROOT,
    NARGO,
    TOOLCHAIN,
    run,
    save,
    sha,
    manifest,
    write_witness,
    gate_report,
)

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--app", type=Path, required=True)
p.add_argument("--user", type=Path, required=True)
p.add_argument(
    "--mode",
    choices=["storage", "threshold", "batch", "storage_zero"],
    default="threshold",
)
p.add_argument(
    "--app-vk-hash", required=True, help="Authorised app producer key hash (policy)"
)
p.add_argument(
    "--user-vk-hash", required=True, help="Authorised user producer key hash (policy)"
)
p.add_argument("--bb", type=Path, required=True)
p.add_argument("--bb-sha256")
p.add_argument("--output", type=Path, required=True)
p.add_argument(
    "--negative-checks",
    action="store_true",
    help="Also prove an intentionally mismatched root and require rejection",
)
a = p.parse_args()
MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# Consumer programs linking an app account proof to a user proof, one per mode.
LINKED = ROOT / "proving/linked"


def policy_hash(flag, value, bundle):
    if not value.isdigit() or not 0 < int(value) < MODULUS or str(int(value)) != value:
        p.error(f"{flag} must be a canonical nonzero decimal field element")
    claimed = bundle.get("producer_vk_hash")
    if bundle.get("format_version") != 2 or claimed is None:
        p.error(f"{flag}: recursive_proof export is not format_version 2")
    if claimed != value:
        p.error(f"{flag}: recursive_proof producer key {claimed} is not the authorised key")
    return value


app = json.loads(a.app.read_text())
user = json.loads(a.user.read_text())
app_vk_hash = policy_hash("--app-vk-hash", a.app_vk_hash, app)
user_vk_hash = policy_hash("--user-vk-hash", a.user_vk_hash, user)
bb, out = a.bb.resolve(), a.output.resolve()
pin = json.loads(TOOLCHAIN.read_text())
# Default to the released v6.0.0 backend; --bb-sha256 selects another audited build.
if sha(bb) != (a.bb_sha256 or pin["released_bb_linux_x86_64_sha256"]):
    p.error("Unexpected backend checksum")
if pin["noir_commit"] not in __import__("subprocess").check_output(
    [NARGO, "--version"], text=True
):
    p.error("Unexpected Noir compiler")
if out.exists():
    p.error("Choose a fresh output directory")
if app["expected"]["storage_root"] != user["expected"]["storage_root"]:
    p.error("RecursiveProofs refer to different storage roots")
if a.mode == "batch":
    slots = len(user["expected"]["slot_keys"])
    if not 1 <= slots <= 64 or len(user["expected"]["values"]) != slots:
        p.error("Invalid batch shape")
    source = (
        (LINKED / "batch4.nr")
        .read_text()
        .replace("global BATCH_SIZE: u32 = 4;", f"global BATCH_SIZE: u32 = {slots};")
    )
    claim_args = dict(
        slot_keys=user["expected"]["slot_keys"], values=user["expected"]["values"]
    )
elif a.mode == "storage_zero":
    source = (LINKED / "zero.nr").read_text()
    claim_args = dict(slot_key=user["expected"]["slot_key"])
else:
    name = "minimum" if a.mode == "threshold" else "value"
    source = (LINKED / (a.mode + ".nr")).read_text()
    claim_args = dict(
        slot_key=user["expected"]["slot_key"], **{name: user["expected"][name]}
    )
witness = dict(
    app_recursive_proof=app["certificate"],
    user_recursive_proof=user["certificate"],
    app_vk_hash=app_vk_hash,
    user_vk_hash=user_vk_hash,
    expected_account=app["expected"],
    **claim_args,
)
out.mkdir(parents=True)
result = dict(
    mode=a.mode,
    backend_sha256=sha(bb),
    scope="Standalone two-recursive_proof check; no authenticated block or Aztec transaction",
    app_recursive_proof_sha256=sha(a.app),
    user_recursive_proof_sha256=sha(a.user),
    app_vk_hash=witness["app_vk_hash"],
    user_vk_hash=witness["user_vk_hash"],
)
(out / "main.nr").write_text(source)
write_witness(out / "ConsumerProver.toml", witness)
with tempfile.TemporaryDirectory(prefix="storage-linked-") as tmp:
    stage = Path(tmp)
    (stage / "src").mkdir()
    (stage / "src/main.nr").write_text(source)
    manifest(stage, "linked_consumer")
    write_witness(stage / "Prover.toml", witness)
    run([NARGO, "compile", "--deny-warnings"], stage, out, "compile")
    run([NARGO, "execute"], stage, out, "execute")
    shutil.copytree(stage / "target", out / "consumer")
    ca = out / "consumer/linked_consumer.json"
    cw = out / "consumer/linked_consumer.gz"
    run(
        [bb, "gates", "-b", ca, "--verifier_target", "noir-recursive"],
        ROOT,
        out,
        "gates",
    )
    result["ultra_gates"] = gate_report(out / "gates.log")
    result["prove"] = run(
        [
            bb,
            "prove",
            "-b",
            ca,
            "-w",
            cw,
            "-o",
            out / "proof",
            "--verifier_target",
            "noir-recursive",
            "--write_vk",
            "--verify",
        ],
        ROOT,
        out,
        "prove",
    )
    result["recursive_proof_verified"] = True
    result["proof_sha256"] = sha(out / "proof/proof")
    save(out / "results.json", result)
    if a.negative_checks:
        changed = copy.deepcopy(witness)
        changed["expected_account"]["storage_root"][0] = str(
            int(changed["expected_account"]["storage_root"][0]) ^ 1
        )
        write_witness(stage / "Prover.toml", changed)
        run([NARGO, "execute"], stage, out, "mismatch-execute")
        run(
            [
                bb,
                "prove",
                "-b",
                ca,
                "-w",
                stage / "target/linked_consumer.gz",
                "-o",
                out / "mismatch-proof",
                "--verifier_target",
                "noir-recursive",
                "--write_vk",
                "--verify",
            ],
            ROOT,
            out,
            "mismatch",
            negative=True,
        )
        if not any(
            x in (out / "mismatch.log").read_text().lower()
            for x in ["failed", "failure", "mismatch"]
        ):
            raise RuntimeError("Missing cryptographic failure evidence")
        result["mismatched_storage_root_rejected"] = True
        save(out / "results.json", result)

print(out)
