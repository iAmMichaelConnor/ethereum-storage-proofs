import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  inspectProof,
  recommendProfile,
  selectProfile,
  fitsProfile,
  profileCost,
} from "../../input-preparation/profiles.mjs";
const fixture = (name) =>
  JSON.parse(
    readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url)),
  );
test("verified four-slot shape counts shared nodes only once", async () => {
  const s = await inspectProof(fixture("batch-shared-rpc"), { scope: "batch" });
  assert.deepEqual(recommendProfile(s), {
    version: 1,
    scope: "batch",
    slots: 4,
    nodes: 3,
    depth: 2,
    bytes: 135,
  });
  assert.equal(
    s.storage.reduce((n, p) => n + p.lengths.length, 0),
    8,
  );
});
test("leaf-only recommends zero nodes and preserves duplicates", async () => {
  const s = await inspectProof(fixture("batch-leaf-rpc"), { scope: "batch" });
  assert.equal(recommendProfile(s).nodes, 0);
  assert.equal(recommendProfile(s).slots, 2);
});
test("smallest fitting primary wins and fallback is retained", async () => {
  const s = await inspectProof(fixture("batch-shared-rpc"), { scope: "batch" }),
    p = recommendProfile(s);
  const catalogue = {
    version: 1,
    profiles: [
      { id: "large", profile: { ...p, nodes: 8 } },
      { id: "small", profile: p },
      {
        id: "fallback",
        profile: { ...p, nodes: 16, depth: 8 },
        fallback: true,
      },
    ],
  };
  assert.equal(selectProfile(s, catalogue).id, "small");
  catalogue.profiles = catalogue.profiles.filter((e) => e.fallback);
  assert.equal(selectProfile(s, catalogue).id, "fallback");
});
test("undersized catalogue fails without truncation", async () => {
  const s = await inspectProof(fixture("batch-shared-rpc"), { scope: "batch" }),
    p = recommendProfile(s);
  assert.throws(
    () =>
      selectProfile(s, {
        version: 1,
        profiles: [{ id: "too-small", profile: { ...p, nodes: 2 } }],
      }),
    /No catalogue/,
  );
});
test("hashed profile cannot accept embedded siblings", () => {
  const s = {
    scope: "storage",
    account: { lengths: [] },
    storage: [{ lengths: [25], hasEmbedded: true }],
  };
  assert.equal(
    fitsProfile(s, {
      version: 1,
      scope: "storage",
      mode: "hashed",
      account: [],
      storage: [135],
    }),
    false,
  );
});
test("mixed capacities fit by position and score permutations", () => {
  const s = {
    scope: "storage",
    account: { lengths: [] },
    storage: [{ lengths: [272, 20], hasEmbedded: false }],
  };
  const p = {
    version: 1,
    scope: "storage",
    mode: "general",
    account: [],
    storage: [407, 135],
  };
  assert(fitsProfile(s, p));
  assert(!fitsProfile(s, { ...p, storage: [135, 407] }));
  assert.equal(profileCost(p).nodeHashPermutations, 4);
});
test("inspection rejects an altered value before recommending a circuit", async () => {
  const x = fixture("batch-shared-rpc");
  x.proof.storageProof[0].value = "0x01";
  await assert.rejects(inspectProof(x, { scope: "batch" }), /does not match/);
});
test("invalid capacities and duplicate catalogue ids reject", () => {
  assert.throws(() =>
    profileCost({
      version: 1,
      scope: "batch",
      slots: 4,
      nodes: -1,
      depth: 2,
      bytes: 135,
    }),
  );
  const p = {
    version: 1,
    scope: "batch",
    slots: 4,
    nodes: 3,
    depth: 2,
    bytes: 135,
  };
  assert.throws(
    () =>
      selectProfile(
        {},
        {
          version: 1,
          profiles: [
            { id: "x", profile: p },
            { id: "x", profile: p },
          ],
        },
      ),
    /duplicate/,
  );
});
test("mixed recommendation saves permutations on the seven-node fixture", async () => {
  const info = await inspectProof(fixture("rpc"), { scope: "batch" }),
    p = recommendProfile(info);
  assert.equal(p.layout, "mixed");
  assert.deepEqual(p.buckets, [0, 1, 1, 5]);
  assert(fitsProfile(info, p));
  assert.equal(profileCost(p).nodeHashPermutations, 25);
  assert(fitsProfile(info, { ...p, buckets: [0, 0, 0, 7] }));
  assert(!fitsProfile(info, { ...p, buckets: [7, 0, 0, 0] }));
});
