#!/usr/bin/env python3
"""Generate a shared-node batch recursive_proof producer, compatible with prove.py."""

import argparse, json
from pathlib import Path
from profile_common import BATCH, RECURSIVE_PROOF, PROOF, TYPES, write_profile


def generate(folder, slots=4, nodes=8, depth=8, size=532, parsed=False):
    if not (
        1 <= slots <= 64
        and 0 <= nodes <= 64 * slots
        and 0 <= depth <= 64
        and 3 <= size <= 532
    ):
        raise ValueError(
            "Use 1..64 slots, 0..64*slots nodes, 0..64 depth, 3..532 bytes"
        )
    spec = dict(
        version=1, scope="batch", slots=slots, nodes=nodes, depth=depth, bytes=size
    )
    params = (
        f"claim:BatchStorageClaim<{slots}>,values:[StorageSlot;{slots}],node_count:u32"
    )
    imports = ""
    if nodes:
        params += f",nodes:[EncodedNode<{size}>;{nodes}]"
        imports += f"use {PROOF}::EncodedNode;\n"
    if depth:
        params += f",paths:[IndexedPath<{depth}>;{slots}]"
    source = f"""use {BATCH}::{{IndexedPath,verify_storage_batch}};
use {TYPES}::StorageSlot;
use {RECURSIVE_PROOF}::{{BatchStorageClaim,batch_storage_statement,value_word}};
{imports}fn main({params})->pub Field{{
"""
    if not nodes:
        source += f"let nodes:[{PROOF}::EncodedNode<{size}>;0]=[];\n"
    if not depth:
        source += f"let paths=[IndexedPath {{indices:[],count:0}};{slots}];\n"
    source += f"for i in 0..{slots}{{assert_eq(value_word(values[i]),claim.values[i]);}}\nverify_storage_batch(claim.storage_root,claim.slot_keys,values,nodes,node_count,paths);\nbatch_storage_statement(claim)\n}}\n"
    if parsed:
        spec["parsing"] = "shared"
        source = source.replace("verify_storage_batch", "verify_storage_batch_parsed")
    return write_profile(folder, spec, source)


def generate_mixed(folder, slots=4, buckets=(3, 0, 0, 0), depth=8, parsed=False):
    if not (
        1 <= slots <= 64
        and 0 <= depth <= 64
        and len(buckets) == 4
        and all(isinstance(n, int) and 0 <= n <= 64 * slots for n in buckets)
    ):
        raise ValueError("Invalid mixed batch capacities")
    spec = dict(
        version=1,
        scope="batch",
        layout="mixed",
        slots=slots,
        buckets=list(buckets),
        depth=depth,
    )
    params = [f"claim:BatchStorageClaim<{slots}>", f"values:[StorageSlot;{slots}]"]
    locals = []
    for name, count, size in zip(
        ["small", "medium", "large", "full"], buckets, [135, 271, 407, 532]
    ):
        if count:
            params.append(f"{name}:NodeBucket<{count},{size}>")
        else:
            locals.append(
                f"let {name}:NodeBucket<0,{size}> = NodeBucket {{nodes:[],count:0}};"
            )
    if depth:
        params.append(f"paths:[IndexedPath<{depth}>;{slots}]")
    else:
        locals.append(f"let paths=[IndexedPath {{indices:[],count:0}};{slots}];")
    source = f"use {BATCH}::{{NodeBucket,IndexedPath,verify_storage_batch_mixed}};\nuse {TYPES}::StorageSlot;\nuse {RECURSIVE_PROOF}::{{BatchStorageClaim,batch_storage_statement,value_word}};\n"
    source += (
        "fn main(" + ",".join(params) + ")->pub Field{\n" + "\n".join(locals) + "\n"
    )
    source += (
        f"for i in 0..{slots}{{assert_eq(value_word(values[i]),claim.values[i]);}}\n"
    )
    source += "verify_storage_batch_mixed(claim.storage_root,claim.slot_keys,values,small,medium,large,full,paths);\nbatch_storage_statement(claim)\n}\n"
    if parsed:
        spec["parsing"] = "shared"
        source = source.replace(
            "verify_storage_batch_mixed", "verify_storage_batch_mixed_parsed"
        )
    return write_profile(folder, spec, source)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    for name, value in [("slots", 4), ("nodes", 8), ("depth", 8), ("bytes", 532)]:
        p.add_argument("--" + name, type=int, default=value)
    p.add_argument(
        "--buckets", help="Mixed table capacities for 135,271,407,532-byte buckets"
    )
    p.add_argument(
        "--shared-parsing",
        action="store_true",
        help="Cache referenced node structure once",
    )
    a = p.parse_args()
    try:
        print(
            json.dumps(
                generate_mixed(
                    a.output,
                    a.slots,
                    list(map(int, a.buckets.split(","))),
                    a.depth,
                    a.shared_parsing,
                )
                if a.buckets
                else generate(
                    a.output, a.slots, a.nodes, a.depth, a.bytes, a.shared_parsing
                )
            )
        )
    except (ValueError, FileExistsError) as e:
        p.error(str(e))
