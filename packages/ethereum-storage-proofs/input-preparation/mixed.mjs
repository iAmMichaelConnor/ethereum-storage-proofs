import assert from "node:assert/strict";
import { prepareBatchStorage } from "./batch.mjs";
import { BYTE_CAPACITIES } from "./profiles.mjs";

export async function prepareMixedBatch(
  input,
  { slots, buckets, pathDepth = 8 } = {},
) {
  const k = input.proof?.storageProof?.length;
  assert(Number.isSafeInteger(k) && k > 0 && k <= 64, "Expected 1..64 claims");
  assert(
    Array.isArray(buckets) &&
      buckets.length === 4 &&
      buckets.every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 64 * k),
    "Invalid bucket capacities",
  );
  const w = await prepareBatchStorage(input, {
    slots,
    nodeCapacity: 64 * k,
    pathDepth,
    nodeBytes: 532,
  });
  const nodes = [[], [], [], []],
    remap = [];
  const offsets = buckets.map((_, i) =>
    buckets.slice(0, i).reduce((a, b) => a + b, 0),
  );
  for (const [i, node] of [...w.nodes.slice(0, w.node_count).entries()].sort(
    (a, b) => b[1].length - a[1].length || a[0] - b[0],
  )) {
    const b = BYTE_CAPACITIES.findIndex(
      (n, j) => node.length <= n && nodes[j].length < buckets[j],
    );
    assert(b >= 0, "Bucket capacities cannot fit all nodes");
    remap[i] = offsets[b] + nodes[b].length;
    nodes[b].push({ ...node, bytes: node.bytes.slice(0, BYTE_CAPACITIES[b]) });
  }
  const groups = nodes.map((xs, i) => {
    assert(
      xs.length <= buckets[i],
      `Bucket ${BYTE_CAPACITIES[i]} too small: need ${xs.length}`,
    );
    const count = xs.length;
    while (xs.length < buckets[i])
      xs.push({
        bytes: Array(BYTE_CAPACITIES[i]).fill(0),
        length: 0,
        is_extension: false,
      });
    return { nodes: xs, count };
  });
  return {
    root: w.root,
    slot_keys: w.slot_keys,
    values: w.values,
    small: groups[0],
    medium: groups[1],
    large: groups[2],
    full: groups[3],
    paths: w.paths.map((p) => ({
      count: p.count,
      indices: p.indices.map((n, i) => (i < p.count ? remap[n] : 0)),
    })),
  };
}
