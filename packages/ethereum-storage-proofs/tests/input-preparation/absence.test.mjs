import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  prepareStorageZero,
  prepareAccountAbsent,
  prepareL1Zero,
  validateProfile,
  profileCost,
} from "../../input-preparation/index.mjs";
const cases = JSON.parse(
  await readFile(new URL("../fixtures/absence/cases.json", import.meta.url)),
);
const byName = (name) => cases.find((c) => c.name === name).input;
for (const [name, kind] of [
  ["empty", 3],
  ["leaf", 2],
  ["extension", 1],
  ["extension-branch", 0],
  ["branch", 0],
])
  test(`prepare zero ${name}`, async () => {
    const p = await prepareStorageZero(byName(name), { depth: 4 });
    assert.equal(p.witness.kind, kind);
    const l1 = await prepareL1Zero(byName(name), { depth: 4, accountDepth: 0 });
    assert.deepEqual(l1.claim.slot_key, p.claim.slot_key);
    assert.deepEqual(l1.witness.account.storage_hash, p.claim.storage_root);
  });
for (const name of ["account-empty", "account-leaf"])
  test(name, async () => {
    assert.equal(
      (await prepareAccountAbsent(byName(name))).witness.kind,
      name === "account-empty" ? 3 : 2,
    );
  });
test("reject present, forged zero metadata, wrong root and insufficient capacity", async () => {
  await assert.rejects(prepareStorageZero(byName("present")));
  const forged = structuredClone(byName("present"));
  forged.proof.storageProof[0].value = "0x0";
  await assert.rejects(prepareStorageZero(forged), /Key is present/);
  const wrong = structuredClone(byName("leaf"));
  wrong.proof.storageHash = "0x" + "11".repeat(32);
  await assert.rejects(prepareStorageZero(wrong));
  await assert.rejects(
    prepareStorageZero(byName("extension-branch"), { depth: 0 }),
  );
  await assert.rejects(
    prepareStorageZero(byName("leaf"), { terminalBytes: 3 }),
  );
  await assert.rejects(prepareAccountAbsent(byName("leaf")), /Key is present/);
});
test("absence profiles validate capacities and cost", () => {
  const p = validateProfile({
    version: 1,
    scope: "l1_zero",
    depth: 2,
    node_bytes: 135,
    terminal_bytes: 271,
    account_depth: 1,
    account_bytes: 532,
  });
  assert.equal(profileCost(p).nodeHashPermutations, 8);
  assert.throws(() => validateProfile({ ...p, terminal_bytes: 0 }));
});
test("inspection recommends fitting capacities for all scopes", async () => {
  const { inspectAbsenceProof, generateProfile, prepareCircuit } = await import(
    "../../input-preparation/index.mjs"
  );
  const { mkdtemp, rm, writeFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const dir = await mkdtemp(tmpdir() + "/absence-sdk-");
  try {
    for (const [scope, name] of [
      ["storage_zero", "extension-branch"],
      ["account_absent", "account-leaf"],
      ["l1_zero", "empty"],
    ]) {
      const input = byName(name),
        p = await inspectAbsenceProof(input, { scope });
      validateProfile(p);
      await writeFile(`${dir}/${scope}.json`, JSON.stringify(input));
      const generated = await generateProfile(p, `${dir}/${scope}`);
      const prepared = await prepareCircuit({
        profile: generated.directory,
        input: `${dir}/${scope}.json`,
        output: `${dir}/${scope}-prepared`,
      });
      assert(prepared.claim);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
