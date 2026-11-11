#!/usr/bin/env python3
"""Generate generic zero-storage or absent-account recursive_proof producers."""

import argparse, json
from pathlib import Path
from profile_common import ABSENCE, RECURSIVE_PROOF_ABSENCE, PROOF, TYPES, write_profile

SCOPES = {
    "storage_zero": "StorageZeroClaim",
    "account_absent": "AccountAbsentClaim",
    "l1_zero": "L1ZeroClaim",
}


def generate(
    folder,
    scope="storage_zero",
    depth=4,
    node_bytes=532,
    terminal_bytes=532,
    account_depth=8,
    account_bytes=532,
):
    if scope not in SCOPES:
        raise ValueError("Unknown absence scope")
    for n, lo, hi in [
        (depth, 0, 64),
        (account_depth, 0, 64),
        (node_bytes, 3, 532),
        (terminal_bytes, 3, 532),
        (account_bytes, 3, 532),
    ]:
        if not isinstance(n, int) or isinstance(n, bool) or not lo <= n <= hi:
            raise ValueError("Invalid absence capacity")
    spec = dict(
        version=1,
        scope=scope,
        depth=depth,
        node_bytes=node_bytes,
        terminal_bytes=terminal_bytes,
    )
    if scope == "l1_zero":
        spec.update(account_depth=account_depth, account_bytes=account_bytes)
    args = f"claim:{SCOPES[scope]},count:u32,terminal:[u8;{terminal_bytes}],terminal_length:u32,kind:u8"
    if depth:
        args += f",nodes:[{PROOF}::EncodedNode<{node_bytes}>;{depth}]"
    if scope == "l1_zero":
        args += f",account:{TYPES}::Account,account_count:u32"
        if account_depth:
            args += f",account_nodes:[{PROOF}::EncodedNode<{account_bytes}>;{account_depth}]"
    source = f"use {RECURSIVE_PROOF_ABSENCE}::{{{SCOPES[scope]},{scope}_statement}};\nfn main({args})->pub Field{{\n"
    if not depth:
        source += f"let nodes:[{PROOF}::EncodedNode<{node_bytes}>;0]=[];\n"
    root = "claim.storage_root"
    key = "claim.slot_key"
    fn = "verify_storage_zero"
    if scope == "account_absent":
        root = "claim.state_root"
        key = "claim.address"
        fn = "verify_account_absent"
    if scope == "l1_zero":
        if not account_depth:
            source += (
                f"let account_nodes:[{PROOF}::EncodedNode<{account_bytes}>;0]=[];\n"
            )
        source += f"assert_eq(account.address,claim.address);\n{PROOF}::verify_account(claim.state_root,account,account_nodes,account_count);\n"
        root = "account.storage_hash"
    source += f"{ABSENCE}::{fn}({root},{key},nodes,count,terminal,terminal_length,kind);\n{scope}_statement(claim)\n}}\n"
    return write_profile(folder, spec, source)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("--scope", choices=SCOPES, default="storage_zero")
    for name, default in [
        ("depth", 4),
        ("node-bytes", 532),
        ("terminal-bytes", 532),
        ("account-depth", 8),
        ("account-bytes", 532),
    ]:
        p.add_argument("--" + name, type=int, default=default)
    a = p.parse_args()
    try:
        print(
            json.dumps(
                generate(
                    a.output,
                    a.scope,
                    a.depth,
                    a.node_bytes,
                    a.terminal_bytes,
                    a.account_depth,
                    a.account_bytes,
                )
            )
        )
    except (ValueError, FileExistsError) as e:
        p.error(str(e))
