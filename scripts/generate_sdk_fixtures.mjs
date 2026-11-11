// Saved RPC envelopes for the ethereum-storage-proofs SDK tests, from independent EthereumJS tries:
// shared-prefix, inline and leaf-only storage batches, storage and account absence, and
// receipts. rpc.json is the upstream mainnet proof that generate_fixtures.mjs rebuilds.
// Run through scripts/generate.py, after generate_fixtures.mjs.
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { prepareBatchStorage } from "./witness/batch.mjs";
import { receiptCases } from "./witness/receipt_cases.mjs";

const OUT = "packages/ethereum-storage-proofs/tests/fixtures";
const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const word = (n) => Uint8Array.from(Buffer.from(BigInt(n).toString(16).padStart(64, "0"), "hex"));
const save = (name, data) => {
  mkdirSync(`${OUT}/${name}`.replace(/\/[^/]*$/, ""), { recursive: true });
  writeFileSync(`${OUT}/${name}.json`, JSON.stringify(data, null, 2) + "\n");
};

copyFileSync("target/fixtures/rpc.json", `${OUT}/rpc.json`);

// --- batches: one account whose storage trie holds the batch keys ---
async function batchEnvelope(t, keys, values) {
  const address = new Uint8Array(20).fill(0x42),
    code = keccak256(new Uint8Array()),
    accounts = new Trie({ useKeyHashing: true });
  await accounts.put(address, RLP.encode([Uint8Array.of(1), new Uint8Array(), t.root(), code]));
  return {
    stateRoot: hex(accounts.root()),
    proof: {
      address: hex(address),
      nonce: "0x1",
      balance: "0x0",
      storageHash: hex(t.root()),
      codeHash: hex(code),
      accountProof: (await accounts.createProof(address)).map(hex),
      storageProof: await Promise.all(
        keys.map(async (k, i) => ({
          key: hex(k),
          value: hex(values[i]),
          proof: (await t.createProof(keccak256(k))).map(hex),
        })),
      ),
    },
  };
}
// Four keys in two groups of two that share their first nibble: three shared nodes.
const groups = [[], []];
for (let n = 0; groups.some((g) => g.length < 2); n++) {
  const k = word(n), h = keccak256(k), g = h[0] >> 4;
  if (g < 2 && groups[g].length < 2 && !groups[g].some((x) => (keccak256(x)[0] & 15) === (h[0] & 15)))
    groups[g].push(k);
}
const keys = groups.flat(),
  values = keys.map((_, i) => new Uint8Array(32).fill(i + 1)),
  shared = new Trie();
for (let i = 0; i < keys.length; i++) await shared.put(keccak256(keys[i]), RLP.encode(values[i]));
const sharedInput = await batchEnvelope(shared, keys, values);
const w = await prepareBatchStorage(sharedInput, { slots: 4, nodeCapacity: 3, pathDepth: 2, nodeBytes: 135 });
assert(w.node_count === 3 && w.paths.every((p) => p.count === 2), "expected three shared nodes");
save("batch-shared-rpc", sharedInput);
// Two keys whose leaves are embedded in their branch, each queried twice.
const inline = new Trie(), ik = [word(0), word(1)], iv = [Uint8Array.of(1), Uint8Array.of(128)];
for (let i = 0; i < 2; i++) {
  const h = keccak256(ik[i]);
  await inline.put(h, RLP.encode(iv[i]));
  const sibling = Uint8Array.from(h);
  sibling[31] ^= 1;
  await inline.put(sibling, RLP.encode(Uint8Array.of(2)));
}
save("batch-inline-rpc", await batchEnvelope(inline, [...ik, ...ik], [...iv, ...iv]));
// A storage trie that is one leaf, queried twice.
const leaf = new Trie(), lk = word(99), lv = new Uint8Array(32).fill(255);
await leaf.put(keccak256(lk), RLP.encode(lv));
save("batch-leaf-rpc", await batchEnvelope(leaf, [lk, lk], [lv, lv]));

// --- absence: a zero or missing slot, an absent account, and a present control ---
const absence = [];
{
  const address = Uint8Array.from({ length: 20 }, (_, i) => i + 1), codeHash = keccak256(new Uint8Array());
  async function make(name, slots, query) {
    const storage = new Trie({ useKeyHashing: true });
    for (const k of slots) await storage.put(word(k), RLP.encode(Uint8Array.of(1)));
    const state = new Trie({ useKeyHashing: true });
    await state.put(address, RLP.encode([new Uint8Array(), new Uint8Array(), storage.root(), codeHash]));
    absence.push({
      name,
      input: {
        stateRoot: hex(state.root()),
        proof: {
          address: hex(address),
          nonce: "0x0",
          balance: "0x0",
          storageHash: hex(storage.root()),
          codeHash: hex(codeHash),
          accountProof: (await state.createProof(address)).map(hex),
          storageProof: [
            {
              key: hex(word(query)),
              value: slots.includes(query) ? "0x1" : "0x0",
              proof: (await storage.createProof(word(query))).map(hex),
            },
          ],
        },
      },
    });
  }
  await make("empty", [], 0);
  await make("leaf", [1], 0);
  await make("present", [1], 1);
  const hashes = Array.from({ length: 4000 }, (_, i) => Buffer.from(keccak256(word(i))).toString("hex"));
  const k0 = 0, k1 = hashes.findIndex((s, i) => i > 0 && s.slice(0, 2) === hashes[0].slice(0, 2) && s[2] !== hashes[0][2]);
  await make("extension", [k0, k1], hashes.findIndex((s) => s[0] === hashes[0][0] && s[1] !== hashes[0][1]));
  await make("extension-branch", [k0, k1], hashes.findIndex((s) => s.slice(0, 2) === hashes[0].slice(0, 2) && s[2] !== hashes[k0][2] && s[2] !== hashes[k1][2]));
  const other = hashes.findIndex((s) => s[0] !== hashes[0][0]);
  await make("branch", [k0, other], hashes.findIndex((s) => s[0] !== hashes[0][0] && s[0] !== hashes[other][0]));
  const state = new Trie({ useKeyHashing: true });
  absence.push({ name: "account-empty", input: { stateRoot: hex(state.root()), proof: { address: hex(address), accountProof: [] } } });
  await state.put(address, RLP.encode([new Uint8Array(), new Uint8Array(), new Trie().root(), codeHash]));
  const absent = Uint8Array.from(address);
  absent[0] ^= 1;
  absence.push({ name: "account-leaf", input: { stateRoot: hex(state.root()), proof: { address: hex(absent), accountProof: (await state.createProof(absent)).map(hex) } } });
}
save("absence/cases", absence);

// --- receipts: the cases the Noir receipt tests use, named for the SDK tests ---
const receipts = (await receiptCases()).map(({ name, input }) => ({ name: name.replaceAll("_", "-"), input }));
save("receipts/cases", receipts);
save("receipts/event", receipts.find((c) => c.name === "typed-2").input);

console.log("Generated the ethereum-storage-proofs SDK fixtures");
