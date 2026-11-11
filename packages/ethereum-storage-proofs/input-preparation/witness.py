"""Prepare producer witnesses and bind the caller-selected storage slot; no proving."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from tool_runner import ROOT, run, save, write_witness

SINGLE_SLOT_SCOPES = ["l1", "storage", "threshold", "storage_zero", "l1_zero"]


def check_slot_key(input_path, slot_index, claim):
    """The claim must name the requested storageProof entry (or the only one)."""
    entries = json.loads(Path(input_path).read_text())["proof"]["storageProof"]
    expected = int(entries[slot_index or 0]["key"], 16).to_bytes(32, "big")
    if bytes(int(x) for x in claim["slot_key"]) != expected:
        raise ValueError("Prepared claim does not name the selected storage slot")


def prepare_witness(profile, input_path, out, minimum=1, slot_index=None):
    """Validate RPC paths and produce the exact producer witness, without Noir or bb.

    profile is a generated profile directory; out is an existing output directory.
    slot_index selects the storageProof entry for single-slot storage scopes; it is
    required when the input holds several entries.
    Returns (profile specification, public claim preimage, Noir witness mapping).
    This authenticates relations to supplied roots, not root or key policy.
    """
    profile, out = Path(profile).resolve(), Path(out).resolve()
    spec = json.loads((profile / "profile.json").read_text())
    if slot_index is not None:
        if spec["scope"] not in SINGLE_SLOT_SCOPES:
            raise ValueError("A slot index applies only to single-slot storage scopes")
        if not (isinstance(slot_index, int) and slot_index >= 0):
            raise ValueError("Invalid slot index")
    slot_arg = [] if slot_index is None else [slot_index]
    if spec["scope"] in ["storage_zero", "account_absent", "l1_zero"]:
        run(
            [
                "node",
                ROOT / "scripts/prepare-absence.mjs",
                Path(input_path).resolve(),
                profile / "profile.json",
                out / "prepared.json",
                *slot_arg,
            ],
            ROOT,
            out,
            "prepare",
        )
        prepared = json.loads((out / "prepared.json").read_text())
        witness = prepared["witness"]
        claim = prepared["claim"]
        if spec["scope"] != "account_absent":
            check_slot_key(input_path, slot_index, claim)
        if not spec["depth"]:
            witness.pop("nodes")
        if spec["scope"] == "l1_zero" and not spec["account_depth"]:
            witness.pop("account_nodes")
        witness["claim"] = claim
        write_witness(out / "ProducerProver.toml", witness)
        save(out / "claim.json", claim)
        return spec, claim, witness
    if spec["scope"] in ["receipt", "event"]:
        run(
            [
                "node",
                ROOT / "scripts/prepare-receipt.mjs",
                Path(input_path).resolve(),
                profile / "profile.json",
                out / "prepared.json",
            ],
            ROOT,
            out,
            "prepare",
        )
        prepared = json.loads((out / "prepared.json").read_text())
        w = prepared["witness"]
        claim = prepared["claim"]
        witness = dict(
            claim=claim, count=w["count"], leaf=w["leaf"], leaf_length=w["leaf_length"]
        )
        if spec["depth"]:
            witness["nodes"] = w["nodes"]
        if spec["scope"] == "event":
            witness["data"] = w["expected"]["data"]
        write_witness(out / "ProducerProver.toml", witness)
        save(out / "claim.json", claim)
        return spec, claim, witness
    if spec["scope"] == "batch":
        mixed = spec.get("layout") == "mixed"
        if mixed:
            run(
                [
                    "node",
                    ROOT / "scripts/prepare-mixed.mjs",
                    Path(input_path).resolve(),
                    out / "prepared.json",
                    spec["slots"],
                    ",".join(map(str, spec["buckets"])),
                    spec["depth"],
                ],
                ROOT,
                out,
                "prepare",
            )
        else:
            run(
                [
                    "node",
                    ROOT / "scripts/prepare-batch.mjs",
                    Path(input_path).resolve(),
                    out / "prepared.json",
                    spec["slots"],
                    spec["nodes"],
                    spec["depth"],
                    spec["bytes"],
                ],
                ROOT,
                out,
                "prepare",
            )
        w = json.loads((out / "prepared.json").read_text())
        words = [
            [0] * (32 - v["value_length"]) + v["value"][: v["value_length"]]
            for v in w["values"]
        ]
        claim = dict(storage_root=w["root"], slot_keys=w["slot_keys"], values=words)
        witness = dict(claim=claim, values=w["values"])
        if mixed:
            for name, n in zip(["small", "medium", "large", "full"], spec["buckets"]):
                if n:
                    witness[name] = w[name]
        else:
            witness["node_count"] = w["node_count"]
            if spec["nodes"]:
                witness["nodes"] = w["nodes"]
        if spec["depth"]:
            witness["paths"] = w["paths"]
        write_witness(out / "ProducerProver.toml", witness)
        save(out / "claim.json", claim)
        return spec, claim, witness
    ac, sc = spec["account"], spec["storage"]
    scope = spec["scope"]
    if not 0 <= minimum < 2**256:
        raise ValueError("Minimum must fit uint256")
    # Each party supplies only its own path; full producers validate both.
    run(
        [
            "node",
            ROOT / "scripts/prepare-proof.mjs",
            Path(input_path).resolve(),
            out / "prepared.json",
            len(ac) if scope in ["l1", "account"] else 64,
            max(ac, default=532),
            len(sc) if scope != "account" else 64,
            max(sc, default=532),
            *slot_arg,
            *(
                ["--account-only"]
                if scope == "account"
                else ["--storage-only"]
                if scope in ["storage", "threshold"]
                else []
            ),
        ],
        ROOT,
        out,
        "prepare",
    )
    w = json.loads((out / "prepared.json").read_text())
    minimal = (
        w["value"]["value"][: w["value"]["value_length"]] if scope != "account" else []
    )
    if scope == "account":
        claim = dict(
            state_root=w["state_root"],
            address=w["account"]["address"],
            storage_root=w["account"]["storage_hash"],
        )
        witness = dict(
            claim=claim, account=w["account"], account_count=w["account_count"]
        )
    else:
        claim = dict(slot_key=w["slot_key"])
        if scope == "threshold":
            claim["minimum"] = list(minimum.to_bytes(32, "big"))
        else:
            claim["value"] = [0] * (32 - len(minimal)) + minimal
        if scope == "l1":
            claim.update(state_root=w["state_root"], address=w["account"]["address"])
        else:
            claim.update(storage_root=w["storage_root"])
        check_slot_key(input_path, slot_index, claim)
        witness = dict(claim=claim, value=w["value"], storage_count=w["storage_count"])
        if scope == "l1":
            witness.update(account=w["account"], account_count=w["account_count"])
    for prefix, caps in [("account", ac), ("storage", sc)]:
        for i, capacity in enumerate(caps):
            node = w[prefix + "_nodes"][i]
            if node["length"] > capacity:
                raise ValueError(
                    f"{prefix} node {i} needs {node['length']} bytes, capacity {capacity}"
                )
            witness[f"{prefix}_node{i}"] = dict(node, bytes=node["bytes"][:capacity])
    write_witness(out / "ProducerProver.toml", witness)
    save(out / "claim.json", claim)
    return spec, claim, witness
