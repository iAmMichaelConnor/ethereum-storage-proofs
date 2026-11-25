import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Trie } from "@ethereumjs/trie";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { prepareAccount, prepareStorage } from "../../input-preparation/prepare.mjs";
import {
  packPublicAccount,
  packPublicNode,
  preparePublicAccount,
  preparePublicStorage,
  preparePublicStorageBatch,
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

test("reject a valid proof with an embedded internal node in public preparation", async () => {
  // Build a synthetic trie directly from hashed keys, which share 63 nibbles.
  const slot = new Uint8Array(32);
  const key = keccak256(slot);
  const neighbor = key.slice();
  neighbor[31] ^= 1;
  const trie = new Trie();
  await trie.put(key, Uint8Array.of(1));
  await trie.put(neighbor, Uint8Array.of(2));
  const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
  const proof = (await trie.createProof(key)).map(hex);
  const input = {
    proof: {
      storageHash: hex(trie.root()),
      storageProof: [{ key: hex(slot), value: "0x1", proof }],
    },
  };
  const witness = await prepareStorage(input);
  assert.equal(witness.storage_count, 2);
  assert(witness.storage_nodes[1].length < 32);
  await assert.rejects(preparePublicStorage(input), /Embedded internal nodes are not supported/);
  await assert.rejects(preparePublicStorageBatch(input), /Embedded internal nodes are not supported/);
});

test("prepare public batch in request order and share the storage root node", async () => {
  const input = fixture("batch-shared-rpc");
  const slotCount = input.proof.storageProof.length;
  await assert.rejects(preparePublicStorageBatch(input), /Slot capacity 2 exceeded/);
  const batch = await preparePublicStorageBatch(input, { slotCapacity: slotCount + 1 });
  assert.equal(batch.proofCount, slotCount);
  assert.equal(batch.proofs.length, slotCount + 1);
  assert.equal(batch.proofs[slotCount].count, 0);
  for (const [i, proof] of batch.proofs.slice(0, slotCount).entries()) {
    const single = await preparePublicStorage(input, { slotIndex: i });
    assert.deepEqual(batch.storageRoot, single.storageRoot);
    assert.deepEqual(proof.slotKey, single.slotKey);
    assert.equal(proof.valueHigh, single.valueHigh);
    assert.equal(proof.valueLow, single.valueLow);
    assert.equal(proof.count, single.storageCount);
    const nodes = proof.nodeIndices.slice(0, proof.count).map((index) => batch.storageNodes[index]);
    assert.deepEqual(nodes, single.storageNodes.slice(0, single.storageCount));
    assert.equal(proof.nodeIndices[0], 0);
  }
  assert(batch.nodeCount < batch.proofs.reduce((sum, proof) => sum + proof.count, 0));
});

test("reject a node beyond the packed capacity", () => {
  assert.throws(() => packPublicNode(new Uint8Array(544)), /Node exceeds capacity/);
});

test("public packers reject invalid bytes, lengths and lanes", async () => {
  assert.throws(() => packPublicNode([0xc1, 256]), /Node must contain bytes/);
  const { account } = await prepareAccount(fixture("rpc"));
  assert.throws(() => packPublicAccount({ ...account, nonce_length: -1 }), /Invalid quantity length/);
  const storage_hash = [...account.storage_hash];
  storage_hash[0] = "-1";
  assert.throws(
    () => packPublicAccount({ ...account, storage_hash }),
    /Hash lane must be an unsigned 64-bit integer/,
  );
});
