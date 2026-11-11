#!/usr/bin/env python3
"""Generate standalone bounded recursive_proof producers. No Aztec runtime dependency."""

import argparse
import json
from pathlib import Path

from profile_common import RECURSIVE_PROOF, KECCAK, PROOF, TYPES, write_profile


def capacities(text, depth, size):
    result = [int(x) for x in text.split(",")] if text else [size] * depth
    if not 0 <= len(result) <= 64 or any(not 3 <= b <= 532 for b in result):
        raise ValueError("Use 0..64 internal nodes and 3..532 bytes per node")
    return result


def path_steps(prefix, caps, entry):
    """Emit heterogeneous node types through the generic section verifier."""
    source = f" assert({prefix}_count <= {len(caps)});\n"
    for i in range(len(caps)):
        source += f" {prefix}_cursor = {entry}([{prefix}_node{i}], if {prefix}_count > {i} {{ 1 }} else {{ 0 }}, {prefix}_cursor, {prefix}_key);\n"
    return source


def generate(folder, scope="l1", mode="general", account=None, storage=None):
    account = [532] * 8 if account is None else account
    storage = [532] * 8 if storage is None else storage
    if scope in ["storage", "threshold"]:
        account = []
    if scope == "account":
        storage = []
    spec = dict(version=1, scope=scope, mode=mode, account=account, storage=storage)
    has_account = scope in ["l1", "account"]
    has_storage = scope != "account"
    claim_type = {
        "l1": "L1Claim",
        "storage": "StorageClaim",
        "account": "AccountClaim",
        "threshold": "ThresholdClaim",
    }[scope]
    imports = ["new_cursor"]
    if account or storage:
        imports += ["EncodedNode"]
    if has_account:
        imports += ["verify_account_leaf"]
    if has_storage:
        imports += ["verify_storage_leaf"]
    if account or (mode == "hashed" and storage):
        imports += ["verify_hashed_path_section"]
    if mode == "general" and storage:
        imports += ["verify_path_section"]
    params = [f"claim: {claim_type}"]
    types = []
    cert_imports = [claim_type, f"{scope}_statement"]
    if has_storage:
        params += ["value: StorageSlot"]
        types += ["StorageSlot"]
        cert_imports += ["value_word"]
    if scope == "threshold":
        cert_imports += ["assert_value_at_least"]
    if has_account:
        params += ["account: Account", "account_count: u32"]
        types += ["Account"]
    if has_storage:
        params += ["storage_count: u32"]
    for prefix, caps in [("account", account), ("storage", storage)]:
        params += [f"{prefix}_node{i}: EncodedNode<{b}>" for i, b in enumerate(caps)]
    source = f"use {RECURSIVE_PROOF}::{{" + ", ".join(cert_imports) + "};\n"
    source += f"use {TYPES}::{{" + ", ".join(types) + "};\n"
    if account or has_storage:
        source += f"use {KECCAK}::keccak256;\n"
    source += f"use {PROOF}::{{" + ", ".join(dict.fromkeys(imports)) + "};\n"
    source += "fn main(\n    " + ",\n    ".join(params) + "\n) -> pub Field {\n"
    if has_storage:
        if scope == "threshold":
            source += " assert_value_at_least(value_word(value), claim.minimum);\n"
        else:
            source += " assert_eq(value_word(value), claim.value);\n"
    if has_account:
        source += " assert_eq(account.address, claim.address);\n let mut account_cursor = new_cursor(claim.state_root);\n"
        if scope == "account":
            source += " assert_eq(account.storage_hash, claim.storage_root);\n"
        if account:
            source += " let account_key = keccak256(claim.address, 20);\n"
        source += path_steps("account", account, "verify_hashed_path_section")
        source += " verify_account_leaf(account_cursor, account);\n"
    if has_storage:
        source += (
            " let storage_key = keccak256(claim.slot_key, 32);\n let mut storage_cursor = new_cursor("
            + ("account.storage_hash" if scope == "l1" else "claim.storage_root")
            + ");\n"
        )
        entry = (
            "verify_hashed_path_section" if mode == "hashed" else "verify_path_section"
        )
        source += path_steps("storage", storage, entry)
        source += " verify_storage_leaf(storage_cursor, storage_key, value);\n"
    source += f" {scope}_statement(claim)\n}}\n"
    if not account:
        source = source.replace("mut account_cursor", "account_cursor")
    if not storage:
        source = source.replace("mut storage_cursor", "storage_cursor")
    return write_profile(folder, spec, source)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument(
        "--scope", choices=["l1", "storage", "account", "threshold"], default="l1"
    )
    p.add_argument("--mode", choices=["general", "hashed"], default="general")
    for path in ["account", "storage"]:
        p.add_argument("--" + path + "-depth", type=int, default=8)
        p.add_argument("--" + path + "-bytes", type=int, default=532)
        p.add_argument(
            "--" + path + "-capacities",
            help="Per-node byte capacities, comma separated; overrides depth/bytes",
        )
    a = p.parse_args()
    try:
        spec = generate(
            a.output,
            a.scope,
            a.mode,
            capacities(a.account_capacities, a.account_depth, a.account_bytes),
            capacities(a.storage_capacities, a.storage_depth, a.storage_bytes),
        )
        print(json.dumps(spec))
    except (ValueError, FileExistsError) as e:
        p.error(str(e))
