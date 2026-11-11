// Slot selection and unknown options, capacity errors that name the path, the
// hash-only rejection reason, headroom, and D=4 shapes rejecting real paths.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import {
  autoProfile,
  buildReceiptProof,
  encodeRpcReceipt,
  generateProfile,
  inspectAbsenceProof,
  inspectProof,
  prepareAccount,
  prepareCircuit,
  prepareEvent,
  prepareReceipt,
  prepareStorage,
  prepareStorageZero,
  profileMisfit,
  recommendProfile,
  selectProfile,
  ToolError,
} from "ethereum-storage-proofs";

const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const word = (n) =>
  Uint8Array.from(Buffer.from(BigInt(n).toString(16).padStart(64, "0"), "hex"));
const minimal = (n) => {
  let s = BigInt(n).toString(16);
  if (s.length % 2) s = "0" + s;
  return Uint8Array.from(Buffer.from(s, "hex"));
};
// A secure storage trie holding `values`; storageProof entries for `slots`.
async function storageInput(values, slots) {
  const trie = new Trie({ useKeyHashing: true });
  for (const [k, v] of values) await trie.put(word(k), RLP.encode(minimal(v)));
  const storageProof = [];
  for (const k of slots)
    storageProof.push({
      key: hex(word(k)),
      value: "0x" + BigInt(values.get(k) ?? 0).toString(16),
      proof: (await trie.createProof(word(k))).map(hex),
    });
  return { proof: { storageHash: hex(trie.root()), storageProof } };
}
const rpc = JSON.parse(
  await readFile(new URL("../fixtures/rpc.json", import.meta.url), "utf8"),
);

test("orchestration rejects unknown and misspelt option keys", async () => {
  const base = { profile: "/unused", input: "/unused", output: "/unused" };
  await assert.rejects(
    prepareCircuit({ ...base, exceute: true }),
    /Unknown prepareCircuit option: exceute/,
  );
  await assert.rejects(
    autoProfile({ input: "/unused", output: "/unused", slot: 1 }),
    /Unknown autoProfile option: slot/,
  );
  await assert.rejects(
    generateProfile({ version: 1 }, "/unused", { pyhton: "python3" }),
    /Unknown generateProfile option: pyhton/,
  );
  await assert.rejects(
    prepareCircuit({ ...base, slotIndex: -1 }),
    /slotIndex must be a nonnegative safe integer/,
  );
  await assert.rejects(
    prepareCircuit({ ...base, execute: "yes" }),
    /execute must be a boolean/,
  );
});

test("a multi-entry storage input needs an explicit slotIndex", async () => {
  const input = await storageInput(
    new Map([
      [7, 1],
      [9, 0xffee],
    ]),
    [7, 9],
  );
  await assert.rejects(
    inspectProof(input, { scope: "storage" }),
    /Input has 2 storage proofs; choose one with slotIndex/,
  );
  await assert.rejects(prepareStorage(input), /choose one with slotIndex/);
  await assert.rejects(
    prepareStorage(input, { slotIndex: 2 }),
    /Slot index 2 is out of range/,
  );
  await assert.rejects(
    inspectProof(input, { scope: "account", slotIndex: 0 }),
    /slotIndex applies only to single-slot storage scopes/,
  );
  const second = await prepareStorage(input, { slotIndex: 1 });
  assert.deepEqual(second.slot_key, [...word(9)]);
  const single = {
    proof: { ...input.proof, storageProof: [input.proof.storageProof[0]] },
  };
  assert.deepEqual((await prepareStorage(single)).slot_key, [...word(7)]);

  const tmp = await mkdtemp(join(tmpdir(), "storage-slot-"));
  try {
    const path = join(tmp, "input.json");
    await writeFile(path, JSON.stringify(input));
    const auto = await autoProfile({
      input: path,
      output: join(tmp, "profile"),
      scope: "storage",
      slotIndex: 1,
    });
    assert.equal(auto.selection.slotIndex, 1);
    // Headroom applies to a recommended profile; with a catalogue it was ignored.
    await assert.rejects(
      autoProfile({
        input: path,
        output: join(tmp, "headroom"),
        scope: "storage",
        slotIndex: 1,
        catalogue: path,
        extraDepth: 1,
      }),
      /Headroom options apply to a recommended profile/,
    );
    await assert.rejects(
      autoProfile({
        input: path,
        output: join(tmp, "other"),
        scope: "storage",
      }),
      ToolError,
    );
    // Without the check this silently prepares a claim for entry 0 (slot 7).
    const prepared = await prepareCircuit({
      profile: auto.directory,
      input: path,
      output: join(tmp, "prepared"),
      slotIndex: 1,
    });
    assert.deepEqual(prepared.claim.slot_key, [...word(9)]);
    assert.equal(prepared.preparation.slot_index, 1);
    await assert.rejects(
      prepareCircuit({
        profile: auto.directory,
        input: path,
        output: join(tmp, "unnamed"),
      }),
      /choose one with slotIndex/,
    );
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test("the absence pipeline proves the slot that slotIndex names", async () => {
  const values = new Map([1, 2, 3, 4, 5].map((i) => [i, i]));
  const input = await storageInput(values, [7, 9]);
  await assert.rejects(prepareStorageZero(input), /choose one with slotIndex/);
  const second = await prepareStorageZero(input, { slotIndex: 1 });
  assert.deepEqual(second.claim.slot_key, [...word(9)]);
  const tmp = await mkdtemp(join(tmpdir(), "storage-zero-slot-"));
  try {
    const path = join(tmp, "input.json");
    await writeFile(path, JSON.stringify(input));
    const profile = await generateProfile(
      await inspectAbsenceProof(input, { scope: "storage_zero", slotIndex: 1 }),
      join(tmp, "profile"),
    );
    // Without a slot index, prepare-absence.mjs would prove entry 0.
    const prepared = await prepareCircuit({
      profile: profile.directory,
      input: path,
      output: join(tmp, "prepared"),
      slotIndex: 1,
    });
    assert.deepEqual(prepared.claim.slot_key, [...word(9)]);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});

test("capacity errors name the path, the need and the capacity", async () => {
  await assert.rejects(
    prepareAccount(rpc, { accountDepth: 4 }),
    /Depth capacity exceeded: account path has 7 internal nodes, capacity 4/,
  );
  await assert.rejects(
    prepareStorage(rpc, { storageDepth: 3 }),
    /Depth capacity exceeded: storage path has 7 internal nodes, capacity 3/,
  );
  await assert.rejects(
    prepareStorage(rpc, { storageBytes: 271 }),
    /Capacity exceeded: storage node 0 needs 532 bytes, capacity 271/,
  );
  const rc = (logs, i) =>
    encodeRpcReceipt({
      type: "0x2",
      status: "0x1",
      cumulativeGasUsed: "0x" + (21000 * (i + 1)).toString(16),
      logsBloom: "0x" + "00".repeat(256),
      logs,
    });
  const log = (n) => ({
    address: "0x" + "ab".repeat(20),
    topics: ["0x" + "cd".repeat(32)],
    data: "0x" + "ee".repeat(n),
  });
  const p = await buildReceiptProof([rc([], 0), rc([log(300)], 1)], 1n, {
    expectedReceiptsRoot: null,
  });
  await assert.rejects(
    prepareReceipt(p, { leafBytes: 300 }),
    /Capacity exceeded: receipt leaf needs \d+ bytes, capacity 300/,
  );
  await assert.rejects(
    prepareEvent(p, { dataBytes: 256 }),
    /Capacity exceeded: event data needs 300 bytes, capacity 256/,
  );
  await assert.rejects(
    prepareReceipt(p, { maxLogs: 0 }),
    /Log capacity exceeded: receipt has 1 logs, capacity 0/,
  );
});

test("D=4 receipt producers cannot reach index 256 in a 273-receipt block", async () => {
  const receipts = Array.from({ length: 273 }, (_, i) =>
    encodeRpcReceipt({
      type: "0x2",
      status: "0x1",
      cumulativeGasUsed: "0x" + (21000 * (i + 1)).toString(16),
      logsBloom: "0x" + "00".repeat(256),
      logs: [],
    }),
  );
  const options = { expectedReceiptsRoot: null };
  const deep = await buildReceiptProof(receipts, 256n, options);
  await assert.rejects(
    prepareReceipt(deep, { depth: 4 }),
    /Path capacity exceeded: receipt 256 path has 5 internal nodes, capacity 4/,
  );
  await prepareReceipt(deep, { depth: 5 });
  await prepareReceipt(await buildReceiptProof(receipts, 255n, options), {
    depth: 4,
  });
});

test("catalogue selection reports why each profile was rejected", async () => {
  // keccak(word(50541)) and keccak(word(125299)) share their first 8 nibbles, so the
  // small value at 50541 is a 31-byte leaf embedded in the depth-8 branch.
  assert.equal(
    hex(keccak256(word(50541))).slice(0, 10),
    hex(keccak256(word(125299))).slice(0, 10),
  );
  const input = await storageInput(
    new Map([
      [50541, 1],
      [125299, 0x1234567890abcdefn << 64n],
    ]),
    [125299],
  );
  const info = await inspectProof(input, { scope: "storage" });
  assert.equal(info.storage[0].hasEmbedded, true);
  const general = recommendProfile(info);
  const hashed = { ...general, mode: "hashed" };
  assert.equal(profileMisfit(info, general), null);
  assert.match(profileMisfit(info, hashed), /hash-only mode/);
  const shallow = { ...general, storage: general.storage.slice(1) };
  const catalogue = {
    version: 1,
    profiles: [
      { id: "hashed", profile: hashed },
      { id: "shallow", profile: shallow },
    ],
  };
  assert.throws(
    () => selectProfile(info, catalogue),
    new RegExp(
      "No catalogue profile fits.*hashed: hash-only mode, but a storage path node has an embedded child; shallow: storage path has 2 internal nodes, capacity 1",
    ),
  );
  catalogue.profiles.push({ id: "general", profile: general, fallback: true });
  assert.equal(selectProfile(info, catalogue).id, "general");
});

test("recommendProfile adds headroom only when asked", async () => {
  const info = await inspectProof(rpc, { scope: "l1" });
  const exact = recommendProfile(info);
  assert.equal(exact.account.length, 7);
  const deeper = recommendProfile(info, { extraDepth: 3 });
  assert.deepEqual(deeper.account, [...exact.account, 532, 532, 532]);
  assert.deepEqual(deeper.storage, [...exact.storage, 532, 532, 532]);
  const wide = recommendProfile(info, { fullWidth: true });
  assert(wide.storage.every((n) => n === 532));
  assert.equal(wide.storage.length, exact.storage.length);
  const storageOnly = recommendProfile(
    await inspectProof(rpc, { scope: "storage" }),
    { extraDepth: 1 },
  );
  assert.deepEqual(storageOnly.account, []);
  assert.throws(
    () =>
      recommendProfile(
        { scope: "batch", storage: [], shared: {} },
        { extraDepth: 1 },
      ),
    /single-path scopes/,
  );
  assert.throws(() => recommendProfile(info, { extraDepth: -1 }), /extraDepth/);
});
