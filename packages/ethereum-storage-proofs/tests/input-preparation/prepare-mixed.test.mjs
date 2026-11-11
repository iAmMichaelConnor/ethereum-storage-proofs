import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { prepareMixedBatch } from "../../input-preparation/mixed.mjs";
const fixture = (n) =>
  JSON.parse(readFileSync(new URL(`../fixtures/${n}.json`, import.meta.url)));
test("mixed bucket indices include unused capacity gaps", async () => {
  const w = await prepareMixedBatch(fixture("rpc"), {
    slots: 1,
    buckets: [2, 2, 2, 6],
    pathDepth: 8,
  });
  assert.deepEqual(
    [w.small.count, w.medium.count, w.large.count, w.full.count],
    [0, 1, 1, 5],
  );
  assert.deepEqual(w.paths[0].indices.slice(0, 7), [6, 7, 8, 9, 10, 4, 2]);
});
test("small nodes may spill into larger bucket capacity", async () => {
  const w = await prepareMixedBatch(fixture("batch-shared-rpc"), {
    slots: 4,
    buckets: [0, 3, 0, 0],
    pathDepth: 2,
  });
  assert.equal(w.medium.count, 3);
  assert.equal(w.medium.nodes[0].bytes.length, 271);
});
test("mixed preparation rejects insufficient capacity", async () => {
  await assert.rejects(
    prepareMixedBatch(fixture("rpc"), {
      slots: 1,
      buckets: [0, 1, 1, 4],
      pathDepth: 8,
    }),
    /cannot fit/,
  );
});
