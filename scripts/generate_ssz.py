#!/usr/bin/env python3
"""Independent hashlib SSZ fixtures. Synthetic field-root trees, not chain attestations."""

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def h(a, b):
    return hashlib.sha256(bytes(a) + bytes(b)).digest()


def tree(leaves):
    n = 1 << (len(leaves) - 1).bit_length()
    nodes = [bytes(32)] * n + list(leaves) + [bytes(32)] * (n - len(leaves))
    for i in range(n - 1, 0, -1):
        nodes[i] = h(nodes[2 * i], nodes[2 * i + 1])
    return nodes


def branch(nodes, index):
    siblings = []
    while index > 1:
        siblings.append(nodes[index ^ 1])
        index //= 2
    return siblings


def nr(value):
    if isinstance(value, (bytes, list)):
        return "[" + ", ".join(nr(v) for v in value) + "]"
    return str(value)


# Every rejection test is pinned with should_fail_with to the message of the
# assert it must hit.
REJECTION_MESSAGES = {
    "bounded_overflow": "Depth exceeds branch capacity",
    "bounded_wrong_depth": "Index has wrong depth",
    "rejects_composed_storage_under_other_root": "Node hash differs from its parent reference",
    "rejects_deep_index": "Index has wrong depth",
    "rejects_deneb_anchor_after_fork": "Slot is after the anchor's fork range",
    "rejects_deneb_anchor_before_fork": "Slot is before the anchor's fork range",
    "rejects_deneb_anchor_pre_deneb_slot": "Slot is before the anchor's fork range",
    "rejects_deneb_anchor_unbound_slot": "Slot is not bound to the beacon root",
    "rejects_deneb_anchor_wrong_slot": "Slot is not bound to the beacon root",
    "rejects_deneb_wrong_number": "State branch disagrees with the block number",
    "rejects_deneb_wrong_state": "Number branch disagrees with the state root",
    "rejects_shallow_index": "Index has wrong depth",
    "rejects_wrong_index": "Branch does not reach the root",
    "rejects_wrong_leaf": "Branch does not reach the root",
    "rejects_wrong_root": "Branch does not reach the root",
    "rejects_wrong_sibling": "Branch does not reach the root",
    "rejects_zero_index": "Index has wrong depth",
}


def add(name, body, negative=False):
    global tests
    if "unsafe" in body:
        body = (
            "// Safety: Test witnesses are checked by the constrained SSZ verifier below.\n"
            + body
        )
    tests += (
        "\n#[test"
        + (
            ""
            if not negative
            else f'(should_fail_with = "{REJECTION_MESSAGES[name]}")'
        )
        + f"]\nfn {name}() {{\n{body}\n}}\n"
    )


tests = """// Generated independently with Python hashlib by scripts/generate_ssz.py.
use crate::ssz::{hash_pair, verify_branch, verify_branch_bounded, uint64_root, execution_root_limbs, verify_deneb_execution_anchor, verify_deneb_execution_anchor_at_slot, MAINNET_DENEB_FIRST_SLOT};
use crate::proof::{EncodedNode, verify_l1_storage};
use crate::types::{Account, StorageSlot};
unconstrained fn witness<T>(x: T) -> T { x }
"""
left, right = bytes(range(32)), bytes(range(32, 64))
add(
    "hash_pair_matches_hashlib",
    f"let (left, right) = unsafe {{ witness(({nr(left)}, {nr(right)})) }};\n assert_eq(hash_pair(left, right), {nr(h(left, right))});",
)
leaves = [hashlib.sha256(bytes([i])).digest() for i in range(8)]
t = tree(leaves)
for i in range(8):
    add(
        f"branch_direction_{i}",
        f"let (leaf, siblings, index, root) = unsafe {{ witness(({nr(leaves[i])}, {nr(branch(t, 8 + i))}, {8 + i}_u64, {nr(t[1])})) }};\n verify_branch(leaf, siblings, index, root);",
    )
add(
    "root_only",
    "let root = unsafe { witness([42; 32]) }; verify_branch::<0>(root, [], 1, root);",
)
base = f"let (leaf, siblings, index, root) = unsafe {{ witness(({nr(leaves[3])}, {nr(branch(t, 11))}, 11_u64, {nr(t[1])})) }};"
for name, expr in [
    ("wrong_leaf", "verify_branch([0; 32], siblings, index, root);"),
    (
        "wrong_sibling",
        "let mut changed = siblings; changed[1][0] ^= 1; verify_branch(leaf, changed, index, root);",
    ),
    ("wrong_root", "verify_branch(leaf, siblings, index, [0; 32]);"),
    ("wrong_index", "verify_branch(leaf, siblings, 10, root);"),
    ("zero_index", "verify_branch(leaf, siblings, 0, root);"),
    ("shallow_index", "verify_branch(leaf, siblings, 3, root);"),
    ("deep_index", "verify_branch(leaf, siblings, 27, root);"),
]:
    # Bind only needed tuple fields to avoid compiler unused-variable warnings.
    body = base
    for var in ["leaf", "siblings", "index", "root"]:
        if var not in expr:
            body = body.replace(var, "_" + var)
    add("rejects_" + name, body + "\n" + expr, True)
add(
    "bounded_prefix",
    f"let (leaf, siblings, root) = unsafe {{ witness(({nr(leaves[3])}, {nr(branch(t, 11) + [bytes([255] * 32)] * 2)}, {nr(t[1])})) }}; verify_branch_bounded(leaf, siblings, 3, 11, root);",
)
add(
    "bounded_overflow",
    "verify_branch_bounded([0;32], [[0;32];3], 4, 16, [0;32]);",
    True,
)
add(
    "bounded_wrong_depth",
    "verify_branch_bounded([0;32], [[0;32];3], 2, 8, [0;32]);",
    True,
)
index = (1 << 63) + 0x123456789ABCDEF
siblings = [hashlib.sha256(f"sibling{i}".encode()).digest() for i in range(63)]
node, cursor = leaves[0], index
for sibling in siblings:
    node = h(sibling, node) if cursor & 1 else h(node, sibling)
    cursor >>= 1
add(
    "maximum_u64_depth",
    f"let (leaf, siblings, index, root) = unsafe {{ witness(({nr(leaves[0])}, {nr(siblings)}, {index}_u64, {nr(node)})) }}; verify_branch(leaf, siblings, index, root);",
)
add(
    "ssz_uint64_little_endian",
    f"let value = unsafe {{ witness(0x0102030405060708_u64) }}; assert_eq(uint64_root(value), {nr(bytes.fromhex('0807060504030201') + bytes(24))});",
)
# Deneb: 17 payload fields, 12 body fields, 5 unsigned block/header fields.
# Use the storage fixtures' state root to demonstrate SSZ -> execution MPT format.
rpc = json.loads((ROOT / "target/fixtures/rpc.json").read_text())
state = bytes.fromhex(rpc["stateRoot"][2:])
number = 24418695
payload_fields = [
    hashlib.sha256(f"payload field {i}".encode()).digest() for i in range(17)
]
payload_fields[2] = state
payload_fields[6] = number.to_bytes(8, "little") + bytes(24)
payload = tree(payload_fields)
body_fields = [hashlib.sha256(f"body field {i}".encode()).digest() for i in range(12)]
body_fields[9] = payload[1]
body = tree(body_fields)
block_fields = [hashlib.sha256(f"block field {i}".encode()).digest() for i in range(5)]
block_fields[4] = body[1]
block = tree(block_fields)
w = dict(
    beacon_root=list(block[1]),
    payload_root=list(payload[1]),
    payload_branch=list(map(list, branch(body, 25) + branch(block, 12))),
    state_root=list(state),
    state_branch=list(map(list, branch(payload, 34))),
    block_number=number,
    number_branch=list(map(list, branch(payload, 38))),
)
body = (
    "let (beacon_root, payload_root, payload_branch, state_root, state_branch, block_number, number_branch) = unsafe { witness(("
    + ", ".join(nr(v) + ("_u64" if k == "block_number" else "") for k, v in w.items())
    + ")) };\n"
)
call = "verify_deneb_execution_anchor(beacon_root, payload_root, payload_branch, state_root, state_branch, block_number, number_branch);"
add("deneb_execution_anchor", body + call)
add(
    "rejects_deneb_wrong_number",
    body + call.replace("block_number,", "block_number + 1,"),
    True,
)
add(
    "rejects_deneb_wrong_state",
    body.replace("state_root, state_branch", "_state_root, state_branch")
    + call.replace("state_root, state_branch", "[0; 32], state_branch"),
    True,
)
add(
    "state_root_lane_bridge",
    f"let root = unsafe {{ witness({nr(state)}) }}; assert_eq(execution_root_limbs(root), {nr([int.from_bytes(state[i : i + 8], 'little') for i in range(0, 32, 8)])});",
)
# Slot-bound anchor: a second synthetic block whose field 0 is the slot root.
slot = 11649024  # first Electra slot on mainnet; the Deneb layout still holds
slot_block_fields = list(block_fields)
slot_block_fields[0] = slot.to_bytes(8, "little") + bytes(24)
slot_block = tree(slot_block_fields)
ws = dict(
    beacon_root=list(slot_block[1]),
    slot=slot,
    slot_branch=list(map(list, branch(slot_block, 8)[:2])),
    first_slot=8626176,
    end_slot=(1 << 64) - 1,
    payload_root=w["payload_root"],
    payload_branch=list(
        map(list, branch(tree(body_fields), 25) + branch(slot_block, 12))
    ),
    state_root=w["state_root"],
    state_branch=w["state_branch"],
    block_number=number,
    number_branch=w["number_branch"],
)
assert ws["payload_branch"][6] == list(slot_block[2])
u64_names = {"block_number", "slot", "first_slot", "end_slot"}
slot_body = (
    "let ("
    + ", ".join(ws)
    + ") = unsafe { witness(("
    + ", ".join(nr(v) + ("_u64" if k in u64_names else "") for k, v in ws.items())
    + ")) };\n"
)
slot_call = "verify_deneb_execution_anchor_at_slot(" + ", ".join(ws) + ");"
add("deneb_anchor_at_slot", slot_body + slot_call)
add(
    "deneb_anchor_mainnet_first_slot_constant",
    "// DENEB_FORK_EPOCH = 269568 in the mainnet consensus config; 32 slots per epoch.\nassert_eq(MAINNET_DENEB_FIRST_SLOT, 269568 * 32);",
)
for name, old, new in [
    ("wrong_slot", "slot, slot_branch,", "slot + 1, slot_branch,"),
    ("before_fork", "first_slot, end_slot,", "slot + 1, end_slot,"),
    ("after_fork", "first_slot, end_slot,", "first_slot, slot,"),
    (
        "pre_deneb_slot",
        "slot, slot_branch, first_slot,",
        "MAINNET_DENEB_FIRST_SLOT - 1, slot_branch, first_slot,",
    ),
]:
    expr = slot_call.replace(old, new)
    pattern = slot_body
    for var in ws:
        if not re.search(r"\b%s\b" % var, expr):
            pattern = re.sub(r"\b%s\b(?=[,)])" % var, "_" + var, pattern, count=1)
    add("rejects_deneb_anchor_" + name, pattern + expr, True)
# The original fixture's block field 0 is not a slot root: its slot proof must fail.
add(
    "rejects_deneb_anchor_unbound_slot",
    body
    + "verify_deneb_execution_anchor_at_slot(beacon_root, "
    + str(slot)
    + "_u64, "
    + nr(ws["slot_branch"])
    + ", 0, "
    + str((1 << 64) - 1)
    + "_u64, payload_root, payload_branch, state_root, state_branch, block_number, number_branch);",
    True,
)
# Composition: beacon root -> execution state root -> account -> storage slot.
# The anchor's state root is target/fixtures/rpc.json's, which also roots encoded-mainnet.json.
mainnet = json.loads((ROOT / "target/fixtures/encoded-mainnet.json").read_text())
assert mainnet["root"] == [
    str(int.from_bytes(state[i : i + 8], "little")) for i in range(0, 32, 8)
]


def nodes(entries, depth=8, size=532):
    out = []
    for i in range(depth):
        if i < len(entries):
            b = [int(x) for x in entries[i]["bytes"]]
            out.append(
                (
                    (b + [0] * (size - len(b)))[:size],
                    int(entries[i]["length"]),
                    entries[i]["is_extension"],
                )
            )
        else:
            out.append(([0] * size, 0, False))
    return (
        "["
        + ", ".join(
            "EncodedNode { bytes: %s, length: %d, is_extension: %s }"
            % (nr(b), l, "true" if e else "false")
            for b, l, e in out
        )
        + "]"
    )


acc = mainnet["account"]
account = (
    "Account { nonce: %s, balance: %s, address: %s, nonce_length: %s, balance_length: %s, storage_hash: %s, code_hash: %s }"
    % tuple(
        nr([int(x) for x in acc[k]]) if isinstance(acc[k], list) else str(acc[k])
        for k in [
            "nonce",
            "balance",
            "address",
            "nonce_length",
            "balance_length",
            "storage_hash",
            "code_hash",
        ]
    )
)
value = "StorageSlot { value: %s, value_length: %s }" % (
    nr([int(x) for x in mainnet["slot"]["value"]]),
    mainnet["slot"]["value_length"],
)
composed = (
    body
    + "// Safety: Test witnesses are checked by the constrained MPT verifier below.\n"
    + "let (account, account_nodes, account_count, slot_key, value, storage_nodes, storage_count) = unsafe { witness(("
    + ", ".join(
        [
            account,
            nodes(mainnet["account_nodes"]),
            str(len(mainnet["account_nodes"])) + "_u32",
            nr([int(x) for x in mainnet["slot_key"]]),
            value,
            nodes(mainnet["storage_nodes"]),
            str(len(mainnet["storage_nodes"])) + "_u32",
        ]
    )
    + ")) };\n"
    + call
    + "\nverify_l1_storage::<8, 532, 8, 532>(execution_root_limbs(STATE), account, account_nodes, account_count, slot_key, value, storage_nodes, storage_count);"
)
add("deneb_anchor_composes_with_l1_storage", composed.replace("STATE", "state_root"))
# The MPT proof must not accept a root other than the anchored one.
add(
    "rejects_composed_storage_under_other_root",
    composed.replace(
        "execution_root_limbs(STATE)",
        "execution_root_limbs({ let mut r = state_root; r[0] ^= 1; r })",
    ),
    True,
)
(ROOT / "noir/ethereum_storage_proofs/src/ssz_tests.nr").write_text(tests)
print("Generated independent SSZ fixtures")
