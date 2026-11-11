import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  decodeReceipt,
  encodeRpcReceipt,
  prepareReceipt,
  prepareEvent,
  inspectReceiptProof,
  buildReceiptProof,
  MAINNET_BYZANTIUM_BLOCK,
  generateProfile,
  prepareCircuit,
} from "ethereum-storage-proofs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
const cases = JSON.parse(
  await readFile(
    new URL("../fixtures/receipts/cases.json", import.meta.url),
    "utf8",
  ),
);
for (const { name, input } of cases)
  test("receipt host: " + name, async () => {
    const shape = await inspectReceiptProof(input);
    const options = {
      depth: shape.depth,
      nodeBytes: shape.nodeBytes,
      leafBytes: shape.leafBytes,
      maxLogs: shape.maxLogs,
    };
    const p = await prepareReceipt(input, options);
    assert.equal(p.witness.leaf_length, shape.leafBytes);
    assert.equal(p.claim.transaction_index, input.transactionIndex);
    const d = decodeReceipt(input.receipt);
    if (d.logs.length) {
      const e = await prepareEvent(input, {
        ...options,
        dataBytes: shape.dataBytes,
        logIndex: input.logIndex,
      });
      assert.equal(e.claim.log_index, input.logIndex);
    }
    const bad = structuredClone(input);
    bad.transactionIndex = (BigInt(input.transactionIndex) ^ 1n).toString();
    await assert.rejects(prepareReceipt(bad, options));
  });
test("receipt builder preserves raw index keys and encodes RPC receipts", async () => {
  const encoded = encodeRpcReceipt({
    type: "0x2",
    status: "0x1",
    cumulativeGasUsed: "0x5208",
    logsBloom: "0x" + "00".repeat(256),
    logs: [],
  });
  assert.equal(decodeReceipt(encoded).cumulativeGasUsed, "21000");
  const input = await buildReceiptProof([encoded, encoded], 1n, {
    expectedReceiptsRoot: null,
  });
  await prepareReceipt(input);
  assert.throws(() =>
    encodeRpcReceipt({
      status: "0x2",
      cumulativeGasUsed: "0x0",
      logsBloom: "0x" + "00".repeat(256),
      logs: [],
    }),
  );
});
test("event host rejects altered value, insufficient capacities and bad local index", async () => {
  const input = cases.find((c) => c.name === "typed-2").input;
  await assert.rejects(prepareEvent(input, { logIndex: 99 }));
  await assert.rejects(prepareEvent(input, { logIndex: 1, dataBytes: 55 }));
  await assert.rejects(prepareEvent(input, { maxLogs: 1 }));
  const bad = structuredClone(input);
  bad.receipt = bad.receipt.slice(0, -2) + "01";
  await assert.rejects(prepareReceipt(bad));
});
test("typed profile SDK generates and prepares both receipt scopes", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "receipt-sdk-"));
  try {
    for (const scope of ["receipt", "event"]) {
      const profile = {
        version: 1,
        scope,
        depth: 4,
        node_bytes: 532,
        leaf_bytes: 1024,
        max_logs: 3,
        ...(scope === "event" ? { data_bytes: 256 } : {}),
      };
      const p = await generateProfile(profile, join(tmp, scope));
      const prepared = await prepareCircuit({
        profile: p.directory,
        input: fileURLToPath(
          new URL("../fixtures/receipts/event.json", import.meta.url),
        ),
        output: join(tmp, scope + "-inputs"),
      });
      assert.equal(prepared.preparation.profile.scope, scope);
      assert.equal(prepared.claim.transaction_index, "1");
    }
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});
// Some providers serve pre-Byzantium receipts with a synthesised status and no
// root. The rebuilt trie then has a root that is not the header's. The builder must
// say so instead of returning that root silently.
const legacy = (outcome) => ({
  cumulativeGasUsed: "0x5208",
  logsBloom: "0x" + "00".repeat(256),
  logs: [],
  ...outcome,
});
const historicalRoot = "0x" + "07".repeat(32);
test("receipt builder requires an explicit expected root", async () => {
  const encoded = [encodeRpcReceipt(legacy({ status: "0x1" }))];
  await assert.rejects(buildReceiptProof(encoded, 0), TypeError);
  await assert.rejects(buildReceiptProof(encoded, 0, {}), TypeError);
  await assert.rejects(
    buildReceiptProof(encoded, 0, { expectedReceiptsRoot: null, extra: 1 }),
    /Unknown buildReceiptProof option: extra/,
  );
  await assert.rejects(
    buildReceiptProof(encoded, 0, {
      expectedReceiptsRoot: null,
      blockNumber: 1,
    }),
    /together/,
  );
});
test("receipt builder rejects a synthesised pre-Byzantium status", async () => {
  const consensus = [encodeRpcReceipt(legacy({ root: historicalRoot }))];
  const synthesised = [encodeRpcReceipt(legacy({ status: "0x1" }))];
  const header = (
    await buildReceiptProof(consensus, 0, { expectedReceiptsRoot: null })
  ).receiptsRoot;
  const fork = {
    blockNumber: 4000000n,
    byzantiumBlock: MAINNET_BYZANTIUM_BLOCK,
  };
  const good = await buildReceiptProof(consensus, 0, {
    expectedReceiptsRoot: header,
    ...fork,
  });
  assert.equal(good.receiptsRoot, header);
  const { claim } = await prepareReceipt(good);
  assert.equal(claim.has_post_state, true);
  assert.equal(claim.status, false);
  await assert.rejects(
    buildReceiptProof(synthesised, 0, { expectedReceiptsRoot: header }),
    /does not match the expected root.*synthesised status for a pre-Byzantium block/,
  );
  await assert.rejects(
    buildReceiptProof(synthesised, 0, { expectedReceiptsRoot: null, ...fork }),
    /Receipt 0 has a status but block 4000000 is before Byzantium/,
  );
  await assert.rejects(
    buildReceiptProof(consensus, 0, {
      expectedReceiptsRoot: header,
      blockNumber: MAINNET_BYZANTIUM_BLOCK,
      byzantiumBlock: MAINNET_BYZANTIUM_BLOCK,
    }),
    /has a post-state root but block 4370000 is not before Byzantium/,
  );
  // A wrong root without legacy status receipts names the other usual cause.
  await assert.rejects(
    buildReceiptProof(consensus, 0, {
      expectedReceiptsRoot: "0x" + "00".repeat(32),
    }),
    /every receipt of the block/,
  );
});
