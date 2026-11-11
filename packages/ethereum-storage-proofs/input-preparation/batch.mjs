// Independent path verification and table deduplication; root authenticity is external.
import assert from "node:assert/strict";
import { prepareStorage } from "./prepare.mjs";
export async function prepareBatchStorage(
  input,
  { slots, nodeCapacity = 16, pathDepth = 8, nodeBytes = 532 } = {},
) {
  const entries = input.proof?.storageProof;
  assert(
    Array.isArray(entries) && entries.length > 0,
    "Expected nonempty storageProof",
  );
  if (slots !== undefined)
    assert.equal(entries.length, slots, "Slot count does not match profile");
  for (const [name, n] of Object.entries({
    nodeCapacity,
    pathDepth,
    nodeBytes,
  }))
    assert(Number.isSafeInteger(n) && n >= 0, `Invalid ${name}`);
  assert(
    pathDepth <= 64 && nodeBytes >= 3 && nodeBytes <= 532,
    "Invalid path or byte capacity",
  );
  const unique = [],
    byBytes = new Map(),
    paths = [],
    slot_keys = [],
    values = [];
  let root;
  for (let i = 0; i < entries.length; i++) {
    const w = await prepareStorage(input, {
      slotIndex: i,
      storageDepth: pathDepth,
      storageBytes: nodeBytes,
    });
    root = w.storage_root;
    slot_keys.push(w.slot_key);
    values.push(w.value);
    const indices = [];
    for (const n of w.storage_nodes.slice(0, w.storage_count)) {
      const key = Buffer.from(n.bytes.slice(0, n.length)).toString("hex");
      if (!byBytes.has(key)) {
        byBytes.set(key, unique.length);
        unique.push(n);
      }
      indices.push(byBytes.get(key));
    }
    paths.push({
      indices: [...indices, ...Array(pathDepth - indices.length).fill(0)],
      count: indices.length,
    });
  }
  assert(
    unique.length <= nodeCapacity,
    `Shared node capacity ${nodeCapacity} too small: need ${unique.length}`,
  );
  const node_count = unique.length;
  while (unique.length < nodeCapacity)
    unique.push({
      bytes: Array(nodeBytes).fill(0),
      length: 0,
      is_extension: false,
    });
  return { root, slot_keys, values, nodes: unique, node_count, paths };
}
