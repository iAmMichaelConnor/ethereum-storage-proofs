/** Secure account/storage absence witnesses. Roots are caller-authenticated. */
import assert from "node:assert/strict";
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { prepareAccount, selectSlotIndex } from "./prepare.mjs";
const hex = (b) => Buffer.from(b).toString("hex");
const bytes = (h) => {
  assert(
    typeof h === "string" && /^0x(?:[0-9a-f]{2})*$/i.test(h),
    "Expected byte-aligned hex",
  );
  return Uint8Array.from(Buffer.from(h.slice(2), "hex"));
};
const pad = (b, n) => {
  assert(b.length <= n, `Capacity ${n} too small for ${b.length}`);
  return [...b, ...Array(n - b.length).fill(0)];
};
const limbs = (b) =>
  Array.from({ length: 4 }, (_, i) =>
    Buffer.from(b)
      .readBigUInt64LE(i * 8)
      .toString(),
  );
const nibs = (b) => Array.from(b).flatMap((x) => [x >> 4, x & 15]);
export const EMPTY_TRIE_ROOT = "0x" + hex(keccak256(Uint8Array.of(128)));

async function trace(root, rawKey, proof) {
  assert.equal(root.length, 32);
  assert(Array.isArray(proof));
  if ("0x" + hex(root) === EMPTY_TRIE_ROOT) {
    assert(
      proof.length === 0 || proof.every((p) => hex(p) === "80"),
      "Unexpected nodes for empty trie",
    );
    return { nodes: [], terminal: new Uint8Array(), kind: 3 };
  }
  assert.equal(
    await new Trie({ useKeyHashing: true }).verifyProof(root, rawKey, proof),
    null,
    "Key is present",
  );
  const byHash = new Map(proof.map((p) => [hex(keccak256(p)), p]));
  let node = byHash.get(hex(root)),
    index = 0;
  const key = nibs(keccak256(rawKey)),
    nodes = [];
  for (let step = 0; step <= 64; step++) {
    assert(node, "Missing authenticated proof node");
    const fields = RLP.decode(node);
    assert(Array.isArray(fields));
    let child;
    if (fields.length === 17) {
      assert(index < 64);
      child = fields[key[index++]];
      if (child instanceof Uint8Array && child.length === 0)
        return { nodes, terminal: node, kind: 0 };
    } else {
      assert.equal(fields.length, 2);
      const path = fields[0];
      assert(path instanceof Uint8Array && path.length > 0);
      const flag = path[0] >> 4;
      assert(flag < 4);
      if (flag % 2 === 0) assert.equal(path[0] & 15, 0);
      const suffix = nibs(path).slice(flag % 2 ? 1 : 2);
      assert(index + suffix.length <= 64);
      if (flag >= 2) assert.equal(index + suffix.length, 64);
      else assert(suffix.length > 0 && index + suffix.length < 64);
      if (suffix.some((n, i) => n !== key[index + i]))
        return { nodes, terminal: node, kind: flag >= 2 ? 2 : 1 };
      assert(flag < 2, "Matching leaf cannot prove absence");
      index += suffix.length;
      child = fields[1];
    }
    nodes.push({
      bytes: [...node],
      length: node.length,
      is_extension: fields.length === 2,
    });
    if (Array.isArray(child)) {
      node = RLP.encode(child);
      assert(node.length < 32);
    } else {
      assert.equal(child.length, 32);
      node = byHash.get(hex(child));
    }
  }
  throw new Error("Path exceeds 64 nibbles");
}
async function prepareAbsence(
  root,
  key,
  proof,
  { depth = 8, nodeBytes = 532, terminalBytes = 532 } = {},
  label = "trie",
) {
  assert(
    Number.isSafeInteger(depth) && depth >= 0 && depth <= 64,
    "Invalid depth",
  );
  for (const n of [nodeBytes, terminalBytes])
    assert(
      Number.isSafeInteger(n) && n >= 3 && n <= 532,
      "Invalid node capacity",
    );
  const t = await trace(root, key, proof);
  assert(
    t.nodes.length <= depth,
    `Depth capacity exceeded: ${label} absence path has ${t.nodes.length} prefix nodes, capacity ${depth}`,
  );
  t.nodes.forEach((n, i) =>
    assert(
      n.length <= nodeBytes,
      `Capacity exceeded: ${label} node ${i} needs ${n.length} bytes, capacity ${nodeBytes}`,
    ),
  );
  assert(
    t.terminal.length <= terminalBytes,
    `Capacity exceeded: ${label} terminal needs ${t.terminal.length} bytes, capacity ${terminalBytes}`,
  );
  const nodes = t.nodes.map((n) => ({ ...n, bytes: pad(n.bytes, nodeBytes) }));
  while (nodes.length < depth)
    nodes.push({
      bytes: Array(nodeBytes).fill(0),
      length: 0,
      is_extension: false,
    });
  return {
    nodes,
    count: t.nodes.length,
    terminal: pad(t.terminal, terminalBytes),
    terminal_length: t.terminal.length,
    kind: t.kind,
  };
}
export async function prepareStorageZero(input, options = {}) {
  const p = input.proof;
  assert(p, "Expected proof");
  const s = p.storageProof[selectSlotIndex(p.storageProof, options.slotIndex)];
  assert(BigInt(s.value) === 0n, "Expected zero storage");
  const k = BigInt(s.key);
  assert(k >= 0n && k < 1n << 256n);
  const key = bytes("0x" + k.toString(16).padStart(64, "0")),
    root = bytes(p.storageHash);
  return {
    witness: await prepareAbsence(
      root,
      key,
      s.proof.map(bytes),
      options,
      "storage",
    ),
    claim: { storage_root: limbs(root), slot_key: [...key] },
  };
}
export async function prepareAccountAbsent(input, options = {}) {
  const p = input.proof;
  assert(p && input.stateRoot, "Expected stateRoot and proof");
  const key = bytes(p.address);
  assert.equal(key.length, 20);
  const root = bytes(input.stateRoot);
  return {
    witness: await prepareAbsence(
      root,
      key,
      p.accountProof.map(bytes),
      options,
      "account",
    ),
    claim: { state_root: limbs(root), address: [...key] },
  };
}
/** Included account + absent storage slot. For an absent account use prepareAccountAbsent. */
export async function prepareL1Zero(input, options = {}) {
  const [a, s] = await Promise.all([
    prepareAccount(input, options),
    prepareStorageZero(input, options),
  ]);
  return {
    witness: {
      ...s.witness,
      account: a.account,
      account_nodes: a.account_nodes,
      account_count: a.account_count,
    },
    claim: {
      state_root: a.state_root,
      address: a.account.address,
      slot_key: s.claim.slot_key,
    },
  };
}
/** Validate a proof independently, then recommend uniform capacities. Does not authorize the new key. */
export async function inspectAbsenceProof(
  input,
  { scope = "storage_zero", slotIndex } = {},
) {
  const fn = {
    storage_zero: prepareStorageZero,
    account_absent: prepareAccountAbsent,
    l1_zero: prepareL1Zero,
  }[scope];
  assert(fn, "Unknown absence scope");
  assert(
    slotIndex === undefined || scope !== "account_absent",
    "slotIndex applies only to storage absence scopes",
  );
  const { witness: w } = await fn(input, {
    depth: 64,
    nodeBytes: 532,
    terminalBytes: 532,
    accountDepth: 64,
    accountBytes: 532,
    slotIndex,
  });
  const capacity = (n) => [135, 271, 407, 532].find((b) => b >= n);
  const profile = {
    version: 1,
    scope,
    depth: w.count,
    node_bytes: capacity(
      Math.max(0, ...w.nodes.slice(0, w.count).map((n) => n.length)),
    ),
    terminal_bytes: capacity(w.terminal_length),
  };
  if (scope === "l1_zero")
    Object.assign(profile, {
      account_depth: w.account_count,
      account_bytes: capacity(
        Math.max(
          0,
          ...w.account_nodes.slice(0, w.account_count).map((n) => n.length),
        ),
      ),
    });
  return profile;
}
