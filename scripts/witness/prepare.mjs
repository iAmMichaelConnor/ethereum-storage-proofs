// Convert a saved eth_getProof result to the standalone library's JSON witness.
// Input: {stateRoot: "0x...", proof: <EIP-1186 response>}. Root authenticity is the caller's responsibility.
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import assert from "node:assert/strict";

const fromHex = (h) => {
  assert(/^0x(?:[a-fA-F0-9]{2})*$/.test(h), "Expected byte-aligned hex");
  return Uint8Array.from(Buffer.from(h.slice(2), "hex"));
};
const hex = (b) => Buffer.from(b).toString("hex");
const pad = (a, n) => {
  assert(a.length <= n, `Capacity ${n} is too small for ${a.length}`);
  return [...a, ...Array(n - a.length).fill(0)];
};
const word = (h) => {
  const n = BigInt(h);
  assert(n >= 0n && n < 1n << 256n);
  return fromHex("0x" + n.toString(16).padStart(64, "0"));
};
const integer = (h, n) => {
  const x = BigInt(h);
  assert(x >= 0n);
  let s = x.toString(16);
  if (s.length % 2) s = "0" + s;
  const a = x === 0n ? [] : Array.from(fromHex("0x" + s));
  return [pad(a, n), a.length];
};
const limbs = (b) => {
  assert.equal(b.length, 32);
  return Array.from({ length: 4 }, (_, i) =>
    Array.from(b.slice(i * 8, i * 8 + 8))
      .reduce((v, b, j) => v + (BigInt(b) << BigInt(8 * j)), 0n)
      .toString(),
  );
};

/**
 * Choose one entry of an EIP-1186 storageProof. Without an explicit slotIndex the
 * input must hold exactly one entry, so a single-slot proof never silently uses
 * entry 0 of several.
 */
export function selectSlotIndex(entries, slotIndex) {
  assert(
    Array.isArray(entries) && entries.length > 0,
    "Expected nonempty storageProof",
  );
  if (slotIndex === undefined) {
    assert(
      entries.length === 1,
      `Input has ${entries.length} storage proofs; choose one with slotIndex`,
    );
    return 0;
  }
  assert(
    Number.isSafeInteger(slotIndex) && slotIndex >= 0,
    "Invalid slot index",
  );
  assert(
    slotIndex < entries.length,
    `Slot index ${slotIndex} is out of range: input has ${entries.length} storage proofs`,
  );
  return slotIndex;
}

/** `label` names the path ("account" or "storage") in capacity errors. */
export function encodePath(proof, key, B, D, label = "trie") {
  const byHash = new Map(proof.map((b) => [hex(keccak256(b)), b]));
  let node = proof[0],
    index = 0;
  const nibs = Array.from(key).flatMap((b) => [b >> 4, b & 15]),
    nodes = [];
  for (let steps = 0; steps <= 64; steps++) {
    assert(node, "Missing proof node");
    const fields = RLP.decode(node);
    assert(Array.isArray(fields));
    let child;
    if (fields.length === 17) {
      assert(index < 64);
      child = fields[nibs[index++]];
    } else {
      assert.equal(fields.length, 2);
      const path = fields[0];
      assert(path instanceof Uint8Array && path.length > 0);
      const flag = path[0] >> 4;
      assert(flag < 4);
      const pathNibs = Array.from(path)
        .flatMap((b) => [b >> 4, b & 15])
        .slice(flag % 2 ? 1 : 2);
      if (flag % 2 === 0) assert.equal(path[0] & 15, 0);
      assert.deepEqual(pathNibs, nibs.slice(index, index + pathNibs.length));
      index += pathNibs.length;
      if (flag >= 2) {
        assert.equal(index, 64);
        assert(
          nodes.length <= D,
          `Depth capacity exceeded: ${label} path has ${nodes.length} internal nodes, capacity ${D}`,
        );
        return {
          nodes: pad(nodes, D).map((n) =>
            n === 0
              ? { bytes: Array(B).fill(0), length: 0, is_extension: false }
              : n,
          ),
          count: nodes.length,
        };
      }
      assert(pathNibs.length > 0);
      child = fields[1];
    }
    assert(
      node.length <= B,
      `Capacity exceeded: ${label} node ${nodes.length} needs ${node.length} bytes, capacity ${B}`,
    );
    nodes.push({
      bytes: pad(Array.from(node), B),
      length: node.length,
      is_extension: fields.length === 2,
    });
    if (Array.isArray(child)) {
      node = RLP.encode(child);
      assert(node.length < 32);
    } else {
      assert.equal(child.length, 32, "Missing child or malformed reference");
      node = byHash.get(hex(child));
    }
  }
  throw new Error("Path exceeds 64 nibbles");
}

export async function prepareAccount(
  input,
  { accountDepth = 8, accountBytes = 532 } = {},
) {
  const p = input.proof;
  assert(p && input.stateRoot, "Expected {stateRoot, proof}");
  const address = fromHex(p.address);
  assert.equal(address.length, 20);
  const stateRoot = fromHex(input.stateRoot),
    storageRoot = fromHex(p.storageHash),
    codeHash = fromHex(p.codeHash);
  assert.equal(stateRoot.length, 32);
  assert.equal(storageRoot.length, 32);
  assert.equal(codeHash.length, 32);
  const [nonce, nonce_length] = integer(p.nonce, 8),
    [balance, balance_length] = integer(p.balance, 32);
  const accountValue = RLP.encode([
    Uint8Array.from(nonce.slice(0, nonce_length)),
    Uint8Array.from(balance.slice(0, balance_length)),
    storageRoot,
    codeHash,
  ]);
  const trie = new Trie({ useKeyHashing: true });
  const ap = p.accountProof.map(fromHex);
  assert.deepEqual(
    await trie.verifyProof(stateRoot, address, ap),
    accountValue,
    "Account fields do not match proof",
  );
  const acc = encodePath(
    ap,
    keccak256(address),
    accountBytes,
    accountDepth,
    "account",
  );
  return {
    state_root: limbs(stateRoot),
    account: {
      address: Array.from(address),
      nonce,
      nonce_length,
      balance,
      balance_length,
      storage_hash: limbs(storageRoot),
      code_hash: limbs(codeHash),
    },
    account_nodes: acc.nodes,
    account_count: acc.count,
  };
}

export async function prepareStorage(
  input,
  { storageDepth = 8, storageBytes = 532, slotIndex } = {},
) {
  const p = input.proof;
  assert(p, "Expected {proof: {storageHash, storageProof}}");
  const storageRoot = fromHex(p.storageHash);
  assert.equal(storageRoot.length, 32);
  const selected = p.storageProof[selectSlotIndex(p.storageProof, slotIndex)];
  const key = word(selected.key);
  const [value, value_length] = integer(selected.value, 32);
  assert(value_length > 0, "Zero/non-membership proofs are not supported");
  const trie = new Trie({ useKeyHashing: true });
  const sp = selected.proof.map(fromHex);
  assert.deepEqual(
    await trie.verifyProof(storageRoot, key, sp),
    RLP.encode(Uint8Array.from(value.slice(0, value_length))),
    "Storage value does not match proof",
  );
  const storage = encodePath(
    sp,
    keccak256(key),
    storageBytes,
    storageDepth,
    "storage",
  );
  return {
    storage_root: limbs(storageRoot),
    slot_key: Array.from(key),
    value: { value, value_length },
    storage_nodes: storage.nodes,
    storage_count: storage.count,
  };
}

export async function prepare(input, opts = {}) {
  const [account, storage] = await Promise.all([
    prepareAccount(input, opts),
    prepareStorage(input, opts),
  ]);
  return { ...account, ...storage };
}
