import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  prepare,
  prepareAccount,
  prepareStorage,
  encodePath,
} from "../../input-preparation/prepare.mjs";
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
const rpc = () =>
  JSON.parse(readFileSync(new URL("../fixtures/rpc.json", import.meta.url)));
test("prepare and pad independently verified EIP-1186 fixture", async () => {
  const p = await prepare(rpc());
  assert.equal(p.account_count, 7);
  assert.equal(p.storage_count, 7);
  assert.equal(p.storage_nodes.length, 8);
  assert.equal(p.value.value_length, 7);
});
test("reject undersized depth", async () => {
  await assert.rejects(prepare(rpc(), { storageDepth: 6 }));
});
test("reject undersized bytes", async () => {
  await assert.rejects(prepare(rpc(), { storageBytes: 531 }));
});
test("reject wrong root", async () => {
  const p = rpc();
  p.stateRoot = "0x" + "00".repeat(32);
  await assert.rejects(prepare(p));
});
test("reject wrong claimed value", async () => {
  const p = rpc();
  p.proof.storageProof[0].value = "0x1";
  await assert.rejects(prepare(p));
});
test("reject zero/nonmembership", async () => {
  const p = rpc();
  p.proof.storageProof[0].value = "0x0";
  await assert.rejects(prepare(p));
});
test("expand embedded nodes even when not supplied separately", async () => {
  const t = new Trie();
  const a = new Uint8Array(32),
    b = new Uint8Array(32);
  b[31] = 1;
  await t.put(a, RLP.encode(new Uint8Array([1])));
  await t.put(b, RLP.encode(new Uint8Array([2])));
  const proof = await t.createProof(a);
  const encoded = encodePath(
    proof.filter((p, i) => i === 0 || p.length >= 32),
    a,
    135,
    3,
  );
  assert.equal(encoded.count, 2);
  assert.equal(encoded.nodes[1].is_extension, false);
  assert(encoded.nodes[1].length < 32);
});

test("app can prepare an account recursive_proof without any user storage proof", async () => {
  const input = rpc();
  delete input.proof.storageProof;
  const p = await prepareAccount(input);
  assert.equal(p.account_count, 7);
  assert(!("slot_key" in p));
});
test("user can prepare storage without app account proof or state root", async () => {
  const {
    proof: { storageHash, storageProof },
  } = rpc();
  const p = await prepareStorage({ proof: { storageHash, storageProof } });
  assert.equal(p.storage_count, 7);
  assert(!("account" in p));
});
test("app preparation rejects a changed storage root in account", async () => {
  const input = rpc();
  delete input.proof.storageProof;
  input.proof.storageHash = "0x" + "00".repeat(32);
  await assert.rejects(prepareAccount(input));
});
