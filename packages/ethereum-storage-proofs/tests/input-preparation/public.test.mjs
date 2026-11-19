import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  packPublicNode,
  preparePublicAccount,
  preparePublicStorage,
} from "../../input-preparation/public.mjs";

const fixture = (name) =>
  JSON.parse(readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url)));

// public.json is packed by scripts/generate_public_fixtures.mjs, an independent packer
// whose output the Noir verifier accepts.
test("packed mainnet account and storage match the Noir fixtures", async () => {
  const expected = fixture("public");
  const account = await preparePublicAccount(fixture("rpc"));
  assert.deepEqual(account.account, expected.account);
  assert.deepEqual(account.accountNodes.slice(0, account.accountCount), expected.accountNodes);
  assert.equal(account.accountNodes.length, 10);
  const storage = await preparePublicStorage(fixture("rpc"));
  assert.deepEqual(storage.storageNodes.slice(0, storage.storageCount), expected.storageNodes);
  assert.equal(storage.valueHigh, expected.valueHigh);
  assert.equal(storage.valueLow, expected.valueLow);
});

test("reject a path longer than the depth", async () => {
  await assert.rejects(preparePublicStorage(fixture("rpc"), { storageDepth: 6 }));
});

test("reject a node beyond the packed capacity", () => {
  assert.throws(() => packPublicNode(new Uint8Array(544)), /Node exceeds capacity/);
});
