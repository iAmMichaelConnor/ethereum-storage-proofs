#!/usr/bin/env python3
"""Compile, prove and export a v6 Poseidon2 UltraHonk storage recursive_proof."""

import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tool_runner import (
    ROOT,
    NARGO,
    MODULUS,
    TOOLCHAIN,
    fields,
    gate_report,
    manifest,
    run,
    save,
    sha,
    source_hashes,
    write_witness,
)
from profile_common import RECURSIVE_PROOF, RECURSIVE_PROOF_ABSENCE, RECURSIVE_PROOF_RECEIPTS
from witness import prepare_witness
from honk_proof import pairing_only_mutations

PAIRING_FAILURE = "verification failed at pairing check"
U32_LEAVES = {"log_index", "data_length"}
CRYPTOGRAPHIC = {"verification", "pairing"}


def recursive_source(scope, slots=None):
    if scope in ["storage_zero", "account_absent", "l1_zero"]:
        claim = {
            "storage_zero": "StorageZeroClaim",
            "account_absent": "AccountAbsentClaim",
            "l1_zero": "L1ZeroClaim",
        }[scope]
        return f"""use {RECURSIVE_PROOF}::RecursiveProof;
use {RECURSIVE_PROOF_ABSENCE}::{{{claim}, verify_{scope}_recursive_proof, {scope}_statement}};
fn main(recursive_proof:RecursiveProof,authorized_vk_hash:pub Field,expected:{claim})->pub Field{{
 verify_{scope}_recursive_proof(recursive_proof,authorized_vk_hash,expected);{scope}_statement(expected)
}}
"""
    if scope in ["receipt", "event"]:
        claim = "ReceiptClaim" if scope == "receipt" else "EventClaim"
        return f"""use {RECURSIVE_PROOF}::RecursiveProof;
use {RECURSIVE_PROOF_RECEIPTS}::{{{claim}, verify_{scope}_recursive_proof, {scope}_statement}};
fn main(recursive_proof:RecursiveProof, expected:{claim}, authorized_vk_hash:pub Field)->pub Field {{
 verify_{scope}_recursive_proof(recursive_proof,authorized_vk_hash,expected);{scope}_statement(expected)
}}
"""
    if scope == "batch":
        return f"""use {RECURSIVE_PROOF}::{{RecursiveProof, BatchStorageClaim, verify_batch_storage_recursive_proof, batch_storage_statement}};
fn main(recursive_proof:RecursiveProof,expected:BatchStorageClaim<{slots}>,authorized_vk_hash:pub Field)->pub Field {{
 verify_batch_storage_recursive_proof(recursive_proof,authorized_vk_hash,expected);batch_storage_statement(expected)
}}
"""
    claim = {
        "l1": "L1Claim",
        "storage": "StorageClaim",
        "account": "AccountClaim",
        "threshold": "ThresholdClaim",
    }[scope]
    return f"""use {RECURSIVE_PROOF}::{{RecursiveProof, {claim}, verify_{scope}_recursive_proof, {scope}_statement}};
// In a real private function the caller supplies an authorized constant or
// authenticated policy value. Making it public here exposes the test policy.
fn main(recursive_proof: RecursiveProof, expected: {claim}, authorized_vk_hash: pub Field) -> pub Field {{
    verify_{scope}_recursive_proof(recursive_proof, authorized_vk_hash, expected);
    {scope}_statement(expected)
}}
"""


def sampled(n):
    """First, middle and last index: each mutation costs one recursive prove."""
    return sorted({0, n // 2, n - 1})


def leaf_mutations(claim):
    """Yield (name, changed claim) for sampled leaves of every claim component.

    Every array dimension is sampled at its first, middle and last index. Each
    sampled leaf has its low bit flipped; the first and last sampled leaves also
    have the high bit of their type flipped. Values stay inside their Noir types,
    so witness generation succeeds and only the recursive_proof binding can reject.
    Event topics beyond topic_count are ignored by event_statement and skipped.
    """

    def positions(value, component, prefix=()):
        if not isinstance(value, list):
            yield prefix
            return
        n = len(value)
        if component == "topics" and not prefix:
            n = claim.get("topic_count", n)
        if n == 0:
            return
        for i in sampled(n):
            yield from positions(value[i], component, prefix + (i,))

    def high_bit(component, leaf):
        if isinstance(leaf, str):
            return 63
        return 31 if component in U32_LEAVES else 7

    for component, value in claim.items():
        if component == "topic_count":
            changed = copy.deepcopy(claim)
            changed[component] = (int(value) + 1) % 5  # event_statement: <= 4
            yield "changed-topic_count", changed
            continue
        paths = list(positions(value, component))
        for index, path in enumerate(paths):
            bits = [0]
            if index in (0, len(paths) - 1):
                bits.append(None)  # the high bit of the leaf type
            for bit in bits:
                changed = copy.deepcopy(claim)
                parent, key = changed, component
                for i in path:
                    parent, key = parent[key], i
                leaf = parent[key]
                if isinstance(leaf, bool):
                    if bit is None:
                        continue  # a bool has one bit
                    parent[key] = not leaf
                else:
                    shift = high_bit(component, leaf) if bit is None else bit
                    flipped = int(leaf) ^ (1 << shift)
                    parent[key] = str(flipped) if isinstance(leaf, str) else flipped
                where = "".join(f"[{i}]" for i in path)
                label = "high" if bit is None else "low"
                yield f"changed-{component}{where}-{label}", changed


def recursive_mutations(outer, claim, key_hash):
    """Return {name: (consumer witness, set of accepted rejection stages)}."""
    mutations = {}
    # A failed outer witness still yields a proof whose self-verification fails
    # (bbapi_ultra_honk.cpp), so claim, key and scalar changes must be rejected
    # cryptographically, not by a builder assertion.
    for name, changed_claim in leaf_mutations(claim):
        changed = copy.deepcopy(outer)
        changed["expected"] = changed_claim
        mutations[name] = (changed, CRYPTOGRAPHIC)
    changed = copy.deepcopy(outer)
    changed["authorized_vk_hash"] = str((int(key_hash) + 1) % MODULUS)
    mutations["wrong-key-hash"] = (changed, CRYPTOGRAPHIC)
    proof = outer["recursive_proof"]["proof"]
    changed = copy.deepcopy(outer)
    # proof[457] is the y_hi limb of KZG:W: the point leaves the curve, so the
    # backend rejects it while building the circuit, not cryptographically.
    changed["recursive_proof"]["proof"][-1] = str((int(proof[-1]) + 1) % MODULUS)
    mutations["off-curve-kzg-w"] = (changed, CRYPTOGRAPHIC | {"circuit construction"})
    changed = copy.deepcopy(outer)
    # Field 100 lies in the sumcheck scalar evaluations, not a point.
    changed["recursive_proof"]["proof"][100] = str((int(proof[100]) + 1) % MODULUS)
    mutations["corrupt-sumcheck-scalar"] = (changed, CRYPTOGRAPHIC)
    # Another curve point in place of an opening commitment passes every check of
    # the recursive verifier; only the deferred pairing check can reject it.
    for name, values in pairing_only_mutations(proof).items():
        changed = copy.deepcopy(outer)
        changed["recursive_proof"]["proof"] = list(map(str, values))
        mutations["substitute-" + name] = (changed, {"pairing"})
    return mutations


def rejection_stage(log):
    """Classify a failed `bb prove --verify` log; None if no failure is shown."""
    text = log.lower()
    if PAIRING_FAILURE in text:
        return "pairing"
    if any(
        x in text
        for x in ["failed to verify the generated proof", "proof verification failed"]
    ):
        return "verification"
    if any(x in text for x in ["assertion failed", "not on the curve", "abort"]):
        return "circuit construction"
    return None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profile", type=Path, required=True)
    p.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Saved {stateRoot, proof: EIP1186 result}",
    )
    p.add_argument("--bb", type=Path, required=True)
    p.add_argument(
        "--bb-sha256", help="Expected backend SHA256 for another audited exact-v6 build"
    )
    p.add_argument(
        "--aztec-tag",
        help="Aztec release tag of the --bb-sha256 build; required when that build is not recorded in toolchain.json",
    )
    p.add_argument("--output", type=Path, required=True, help="Fresh output directory")
    p.add_argument(
        "--minimum",
        type=int,
        default=1,
        help="uint256 lower bound for a threshold profile",
    )
    p.add_argument(
        "--recursive-check",
        action="store_true",
        help="Generate and verify an outer UltraHonk proof; test changed statements/key/proof",
    )
    p.add_argument(
        "--cache",
        type=Path,
        help="Optional user-owned compiled-artifact cache; never stores witnesses or proofs",
    )
    p.add_argument(
        "--slot-index",
        type=int,
        help="storageProof entry for single-slot scopes; required if there are several",
    )
    a = p.parse_args()
    if a.slot_index is not None and a.slot_index < 0:
        p.error("--slot-index must be nonnegative")
    profile, out, bb = a.profile.resolve(), a.output.resolve(), a.bb.resolve()
    pin = json.loads(TOOLCHAIN.read_text())
    if pin["noir_commit"] not in subprocess.check_output(
        [NARGO, "--version"], text=True
    ):
        p.error("Wrong Noir compiler; run scripts/bootstrap-noir.sh")
    # Bind the proof protocol tag to the exact released backend identity.
    recorded_backends = {
        pin["released_bb_linux_x86_64_sha256"]: pin["aztec_tag"],
    }
    expected_bb = a.bb_sha256 or pin["released_bb_linux_x86_64_sha256"]
    if sha(bb) != expected_bb:
        p.error(
            "Backend differs from toolchain.json; use the released v6.0.0 backend or pass --bb-sha256"
        )
    if expected_bb in recorded_backends:
        if a.aztec_tag and a.aztec_tag != recorded_backends[expected_bb]:
            p.error("--aztec-tag contradicts the recorded release of this backend")
        aztec_tag = recorded_backends[expected_bb]
    elif a.aztec_tag:
        aztec_tag = a.aztec_tag
    else:
        p.error("Unrecorded backend: pass --aztec-tag naming its Aztec release")
    if out.exists():
        p.error(
            "Output directory already exists; choose a fresh path to retain previous evidence"
        )
    out.mkdir(parents=True)
    spec, claim, witness = prepare_witness(
        profile, a.input, out, a.minimum, a.slot_index
    )
    scope = spec["scope"]
    result = dict(
        profile=spec,
        slot_index=a.slot_index,
        compiler_commit=pin["noir_commit"],
        backend_sha256=sha(bb),
        transcript="Poseidon2",
        proof_type=6,
        root_authentication="caller responsibility",
        source_sha256=source_hashes(),
        producer_source_sha256=sha(profile / "src/main.nr"),
        steps={},
    )
    save(out / "results.json", result)
    with tempfile.TemporaryDirectory(prefix="storage-recursive_proof-") as tmp:
        stage = Path(tmp)
        shutil.copytree(profile / "src", stage / "src")
        manifest(stage, "storage_producer")
        write_witness(stage / "Prover.toml", witness)
        from artifact_cache import compile_artifact

        compile_artifact(stage, out, a.cache, bb)
        run([NARGO, "execute"], stage, out, "execute")
        shutil.copytree(stage / "target", out / "producer")
        artifact = out / "producer/storage_producer.json"
        solved = out / "producer/storage_producer.gz"
        run(
            [bb, "gates", "-b", artifact, "--verifier_target", "noir-recursive"],
            ROOT,
            out,
            "producer-gates",
        )
        result["producer_gates"] = gate_report(out / "producer-gates.log")
        result["steps"]["prove"] = run(
            [
                bb,
                "prove",
                "-b",
                artifact,
                "-w",
                solved,
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
        cert = dict(
            verification_key=fields(out / "proof/vk", 115),
            proof=fields(out / "proof/proof", 458),
        )
        key_hash = fields(out / "proof/vk_hash", 1)[0]
        statement = fields(out / "proof/public_inputs", 1)[0]
        save(
            out / "recursive_proof.json",
            dict(
                format_version=2,
                protocol=dict(
                    aztec_tag=aztec_tag,
                    noir_commit=pin["noir_commit"],
                    transcript="Poseidon2",
                    proof_type=6,
                ),
                profile=spec,
                certificate=cert,
                expected=claim,
                # bb's hash of the key just generated. It identifies the
                # producer; it is not an authorisation. A consumer takes its
                # authorised key hash from its own policy, never from a bundle.
                producer_vk_hash=key_hash,
                statement=statement,
            ),
        )
        result.update(
            vk_hash=key_hash,
            statement=statement,
            proof_sha256=sha(out / "proof/proof"),
            vk_sha256=sha(out / "proof/vk"),
            artifact_sha256=sha(artifact),
            native_proof_verified=True,
        )
        save(out / "results.json", result)
        # The test consumer authorises the key that this run compiled from the
        # profile source above; a deployed consumer uses its own policy value.
        outer = dict(recursive_proof=cert, expected=claim, authorized_vk_hash=key_hash)
        write_witness(out / "RecursiveProver.toml", outer)
        (out / "recursive.nr").write_text(
            recursive_source(spec["scope"], spec.get("slots"))
        )
        if a.recursive_check:
            shutil.rmtree(stage / "target")
            (stage / "src/main.nr").write_text(
                recursive_source(spec["scope"], spec.get("slots"))
            )
            manifest(stage, "storage_consumer")
            write_witness(stage / "Prover.toml", outer)
            run([NARGO, "compile", "--deny-warnings"], stage, out, "consumer-compile")
            run([NARGO, "execute"], stage, out, "consumer-execute")
            shutil.copytree(stage / "target", out / "consumer")
            ca = out / "consumer/storage_consumer.json"
            cw = out / "consumer/storage_consumer.gz"
            run(
                [bb, "gates", "-b", ca, "--verifier_target", "noir-recursive"],
                ROOT,
                out,
                "consumer-gates",
            )
            result["consumer_ultra_gates"] = gate_report(out / "consumer-gates.log")
            result["steps"]["recursive_prove"] = run(
                [
                    bb,
                    "prove",
                    "-b",
                    ca,
                    "-w",
                    cw,
                    "-o",
                    out / "recursive-proof",
                    "--verifier_target",
                    "noir-recursive",
                    "--write_vk",
                    "--verify",
                ],
                ROOT,
                out,
                "recursive-prove",
            )
            result["recursive_proof_verified"] = True
            save(out / "results.json", result)
            mutations = recursive_mutations(outer, claim, key_hash)
            result["rejected_mutations"] = []
            result["rejection_stages"] = {}
            for name, (changed, accepted) in mutations.items():
                write_witness(stage / "Prover.toml", changed)
                # Noir execution does not validate recursive cryptography.
                run([NARGO, "execute"], stage, out, name + "-execute")
                run(
                    [
                        bb,
                        "prove",
                        "-b",
                        ca,
                        "-w",
                        stage / "target/storage_consumer.gz",
                        "-o",
                        out / ("negative-" + name),
                        "--verifier_target",
                        "noir-recursive",
                        "--write_vk",
                        "--verify",
                    ],
                    ROOT,
                    out,
                    name,
                    negative=True,
                )
                rejected_at = rejection_stage((out / (name + ".log")).read_text())
                if rejected_at not in accepted:
                    raise RuntimeError(
                        f"Negative test {name}: rejection stage {rejected_at}, "
                        f"accepted {sorted(accepted)}"
                    )
                result["rejected_mutations"].append(name)
                # Only "verification" and "pairing" are cryptographic rejections.
                result["rejection_stages"][name] = rejected_at
                save(out / "results.json", result)
    save(out / "results.json", result)
    print(f"RecursiveProof and evidence: {out}")


if __name__ == "__main__":
    main()
