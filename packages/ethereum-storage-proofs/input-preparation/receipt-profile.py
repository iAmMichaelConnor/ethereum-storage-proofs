#!/usr/bin/env python3
"""Generate receipt-summary or event recursive_proof producers from shared Noir generics."""

import argparse, json
from pathlib import Path
from profile_common import (
    RECURSIVE_PROOF_RECEIPTS,
    EVENTS,
    KECCAK,
    PROOF,
    RECEIPTS,
    write_profile,
)


def generate(
    folder,
    scope="event",
    depth=4,
    node_bytes=532,
    leaf_bytes=1024,
    max_logs=8,
    data_bytes=256,
):
    if scope not in ["receipt", "event"] or not all(
        isinstance(n, int) and not isinstance(n, bool)
        for n in [depth, node_bytes, leaf_bytes, max_logs, data_bytes]
    ):
        raise ValueError("Invalid receipt profile")
    if not (
        0 <= depth <= 18
        and 3 <= node_bytes <= 532
        and 3 <= leaf_bytes < 2**32
        and 0 <= max_logs < 2**32
        and 1 <= data_bytes < 2**32
    ):
        raise ValueError("Invalid receipt capacities")
    if scope == "event" and max_logs == 0:
        raise ValueError("Event profiles need at least one log")
    spec = dict(
        version=1,
        scope=scope,
        depth=depth,
        node_bytes=node_bytes,
        leaf_bytes=leaf_bytes,
        max_logs=max_logs,
    )
    if scope == "event":
        spec["data_bytes"] = data_bytes
    claim = "ReceiptClaim" if scope == "receipt" else "EventClaim"
    args = f"claim:{claim},count:u32,leaf:[u8;{leaf_bytes}],leaf_length:u32"
    if depth:
        args += f",nodes:[{PROOF}::EncodedNode<{node_bytes}>;{depth}]"
    if scope == "event":
        args += f",data:[u8;{data_bytes}]"
    source = f"use {RECURSIVE_PROOF_RECEIPTS}::{{{claim},{scope}_statement}};\nfn main({args})->pub Field{{\n"
    if not depth:
        source += f"let nodes:[{PROOF}::EncodedNode<{node_bytes}>;0]=[];\n"
    if scope == "receipt":
        source += f"let view={RECEIPTS}::verify_receipt::<{depth},{node_bytes},{leaf_bytes},{max_logs}>(claim.receipts_root,claim.transaction_index,nodes,count,leaf,leaf_length);\n"
        for field in [
            "receipt_type",
            "has_post_state",
            "status",
            "post_state",
            "cumulative_gas_used",
        ]:
            source += f"assert_eq(view.{field},claim.{field});\n"
    else:
        source += f"""let expected={EVENTS}::Event {{emitter:claim.emitter,topics:claim.topics,topic_count:claim.topic_count,data,data_length:claim.data_length}};
let _ = {EVENTS}::verify_event::<{depth},{node_bytes},{leaf_bytes},{max_logs},{data_bytes}>(claim.receipts_root,claim.transaction_index,nodes,count,leaf,leaf_length,claim.log_index,expected);
assert(claim.data_length <= {data_bytes});
let hash_length=if claim.data_length <= {data_bytes} {{claim.data_length}} else {{0}};
assert_eq({KECCAK}::keccak256_limbs(data,hash_length),claim.data_hash);
"""
    source += f"{scope}_statement(claim)\n}}\n"
    return write_profile(folder, spec, source)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("--scope", choices=["receipt", "event"], default="event")
    p.add_argument("--depth", type=int, default=4)
    p.add_argument("--node-bytes", type=int, default=532)
    p.add_argument("--leaf-bytes", type=int, default=1024)
    p.add_argument("--max-logs", type=int, default=8)
    p.add_argument("--data-bytes", type=int, default=256)
    a = p.parse_args()
    try:
        print(
            json.dumps(
                generate(
                    a.output,
                    a.scope,
                    a.depth,
                    a.node_bytes,
                    a.leaf_bytes,
                    a.max_logs,
                    a.data_bytes,
                )
            )
        )
    except (ValueError, FileExistsError) as error:
        p.error(str(error))
