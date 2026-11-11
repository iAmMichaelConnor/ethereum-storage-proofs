import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { prepareBatchStorage } from "../../input-preparation/batch.mjs";
const input = () =>
  JSON.parse(
    readFileSync(new URL("../fixtures/batch-shared-rpc.json", import.meta.url)),
  );
const opts = { slots: 4, nodeCapacity: 3, pathDepth: 2, nodeBytes: 135 };
test("four verified slots share three internal nodes", async () => {
  const w = await prepareBatchStorage(input(), opts);
  assert.equal(w.node_count, 3);
  assert.equal(
    w.paths.reduce((n, p) => n + p.count, 0),
    8,
  );
});
test("duplicate slots retain ordered claims", async () => {
  const x = input();
  x.proof.storageProof[1] = structuredClone(x.proof.storageProof[0]);
  const w = await prepareBatchStorage(x, opts);
  assert.deepEqual(w.slot_keys[0], w.slot_keys[1]);
  assert.deepEqual(w.paths[0], w.paths[1]);
});
test("reject understated node capacity", async () => {
  await assert.rejects(
    prepareBatchStorage(input(), { ...opts, nodeCapacity: 2 }),
    /too small/,
  );
});
test("reject mismatched batch size", async () => {
  await assert.rejects(
    prepareBatchStorage(input(), { ...opts, slots: 3 }),
    /Slot count/,
  );
});
test("reject tampered RPC value", async () => {
  const x = input();
  x.proof.storageProof[2].value = "0x1";
  await assert.rejects(prepareBatchStorage(x, opts), /does not match/);
});
test("reject insufficient per-path depth", async () => {
  await assert.rejects(
    prepareBatchStorage(input(), { ...opts, pathDepth: 1 }),
    /Depth capacity/,
  );
});
