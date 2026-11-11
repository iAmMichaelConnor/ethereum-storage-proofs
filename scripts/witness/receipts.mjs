/** Ethereum receipt/log witnesses. All roots and block/fork policy are caller-owned. */
import assert from "node:assert/strict";
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
import { keccak256 } from "ethereum-cryptography/keccak.js";
const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const bytes = (h) => {
  assert(
    typeof h === "string" && /^0x(?:[\da-f]{2})*$/i.test(h),
    "Expected byte-aligned hex",
  );
  return Uint8Array.from(Buffer.from(h.slice(2), "hex"));
};
const fixed = (h, n) => {
  const b = bytes(h);
  assert.equal(b.length, n);
  return b;
};
const pad = (b, n, what) => {
  assert(Number.isSafeInteger(n) && n >= 0, "Invalid capacity");
  assert(
    b.length <= n,
    `Capacity exceeded: ${what} needs ${b.length} bytes, capacity ${n}`,
  );
  return [...b, ...Array(n - b.length).fill(0)];
};
const uint = (n) => {
  n = BigInt(n);
  assert(n >= 0n && n < 1n << 64n, "Expected uint64");
  if (n === 0n) return new Uint8Array();
  let h = n.toString(16);
  if (h.length % 2) h = "0" + h;
  return bytes("0x" + h);
};
const limbs = (b) =>
  Array.from({ length: 4 }, (_, i) =>
    Array.from(b.slice(8 * i, 8 * i + 8))
      .reduce((a, v, j) => a + (BigInt(v) << BigInt(8 * j)), 0n)
      .toString(),
  );
const scalar = (b) => {
  assert(
    b instanceof Uint8Array && b.length <= 8 && (!b.length || b[0] !== 0),
    "Noncanonical uint64",
  );
  return b.reduce((a, v) => (a << 8n) + BigInt(v), 0n);
};
const equal = (a, b) => assert.deepEqual(a, b);
export function encodeRpcReceipt(receipt) {
  const type = Number(BigInt(receipt.type ?? "0x0"));
  assert(
    Number.isInteger(type) && type >= 0 && type <= 4,
    "Unsupported receipt type",
  );
  assert(
    (receipt.root !== undefined) !== (receipt.status !== undefined),
    "Supply status or historical root",
  );
  let outcome;
  if (receipt.root !== undefined) {
    assert.equal(type, 0);
    outcome = fixed(receipt.root, 32);
  } else {
    const status = BigInt(receipt.status);
    assert(status === 0n || status === 1n);
    outcome = uint(status);
  }
  assert(Array.isArray(receipt.logs));
  const logs = receipt.logs.map((log) => {
    assert(Array.isArray(log.topics) && log.topics.length <= 4);
    return [
      fixed(log.address, 20),
      log.topics.map((t) => fixed(t, 32)),
      bytes(log.data),
    ];
  });
  const payload = RLP.encode([
    outcome,
    uint(receipt.cumulativeGasUsed),
    fixed(receipt.logsBloom, 256),
    logs,
  ]);
  return hex(type ? Uint8Array.from([type, ...payload]) : payload);
}
export function decodeReceipt(encoded) {
  const raw = bytes(encoded);
  assert(raw.length > 0);
  const type = raw[0] < 0x80 ? raw[0] : 0;
  assert(
    raw[0] >= 0x80 || (type >= 1 && type <= 4),
    "Unsupported receipt type",
  );
  const payload = type ? raw.slice(1) : raw,
    parts = RLP.decode(payload);
  equal(RLP.encode(parts), payload);
  assert(Array.isArray(parts) && parts.length === 4);
  const [outcome, gas, bloom, logs] = parts;
  assert(outcome instanceof Uint8Array);
  const hasPostState = outcome.length === 32;
  let status = false;
  if (hasPostState) assert.equal(type, 0);
  else {
    const code = scalar(outcome);
    assert(code <= 1n);
    status = code === 1n;
  }
  assert(bloom instanceof Uint8Array && bloom.length === 256);
  assert(Array.isArray(logs));
  return {
    receiptType: type,
    hasPostState,
    status,
    postState: hasPostState ? hex(outcome) : hex(new Uint8Array(32)),
    cumulativeGasUsed: scalar(gas).toString(),
    logs: logs.map((log) => {
      assert(Array.isArray(log) && log.length === 3);
      const [address, topics, data] = log;
      assert(address instanceof Uint8Array && address.length === 20);
      assert(Array.isArray(topics) && topics.length <= 4);
      for (const t of topics)
        assert(t instanceof Uint8Array && t.length === 32);
      assert(data instanceof Uint8Array);
      return {
        address: hex(address),
        topics: topics.map(hex),
        data: hex(data),
      };
    }),
  };
}
/** First Byzantium block on Ethereum mainnet (EIP-658 status replaces the root). */
export const MAINNET_BYZANTIUM_BLOCK = 4370000n;
const SYNTHETIC_STATUS_HINT =
  "the provider may have returned non-consensus receipts, for example a synthesised status for a pre-Byzantium block";
/**
 * Build a proof from every encoded receipt in transaction-index order.
 * `options.expectedReceiptsRoot` is required: pass the authenticated header's
 * receiptsRoot, or null to opt out for a synthetic trie whose root the caller
 * authenticates itself. Optional `blockNumber` and `byzantiumBlock` check that
 * pre-Byzantium receipts carry a post-state root and later ones a status.
 */
export async function buildReceiptProof(receipts, transactionIndex, options) {
  if (options === null || typeof options !== "object" || Array.isArray(options))
    throw new TypeError(
      "buildReceiptProof needs options { expectedReceiptsRoot }: pass the authenticated header receiptsRoot, or null for a synthetic trie",
    );
  const allowed = new Set([
    "expectedReceiptsRoot",
    "blockNumber",
    "byzantiumBlock",
  ]);
  for (const key of Object.keys(options))
    if (!allowed.has(key))
      throw new TypeError(`Unknown buildReceiptProof option: ${key}`);
  if (!("expectedReceiptsRoot" in options))
    throw new TypeError(
      "buildReceiptProof needs expectedReceiptsRoot (the authenticated header receiptsRoot, or null)",
    );
  const expected =
    options.expectedReceiptsRoot === null
      ? null
      : hex(fixed(options.expectedReceiptsRoot, 32));
  if (
    (options.blockNumber === undefined) !==
    (options.byzantiumBlock === undefined)
  )
    throw new TypeError("Pass blockNumber and byzantiumBlock together");
  const index = BigInt(transactionIndex);
  uint(index);
  assert(Array.isArray(receipts), "Expected an array of encoded receipts");
  assert(index < BigInt(receipts.length), "Missing transaction index");
  const decoded = receipts.map(decodeReceipt);
  if (options.blockNumber !== undefined) {
    const historical =
      BigInt(options.blockNumber) < BigInt(options.byzantiumBlock);
    decoded.forEach((d, i) =>
      assert(
        d.hasPostState === historical,
        historical
          ? `Receipt ${i} has a status but block ${options.blockNumber} is before Byzantium; ${SYNTHETIC_STATUS_HINT}`
          : `Receipt ${i} has a post-state root but block ${options.blockNumber} is not before Byzantium`,
      ),
    );
  }
  const trie = new Trie({ useKeyHashing: false });
  for (let i = 0; i < receipts.length; i++)
    await trie.put(RLP.encode(uint(i)), bytes(receipts[i]));
  const root = hex(trie.root());
  if (expected !== null && root !== expected) {
    // With a fork context the Byzantium check above already passed, so a
    // synthesised status is ruled out; without one it is only a possibility.
    const legacyStatus =
      options.blockNumber === undefined &&
      decoded.some((d) => d.receiptType === 0 && !d.hasPostState);
    throw new Error(
      `Reconstructed receipts root ${root} does not match the expected root ${expected}; check that every receipt of the block is supplied in transaction order` +
        (legacyStatus
          ? `. If the block is before Byzantium, ${SYNTHETIC_STATUS_HINT} (pass blockNumber and byzantiumBlock to check)`
          : ""),
    );
  }
  return {
    receiptsRoot: root,
    transactionIndex: index.toString(),
    receipt: receipts[Number(index)],
    proof: (await trie.createProof(RLP.encode(uint(index)))).map(hex),
  };
}
async function inspect(input) {
  const root = fixed(input.receiptsRoot, 32),
    key = RLP.encode(uint(input.transactionIndex)),
    receipt = bytes(input.receipt);
  const decoded = decodeReceipt(input.receipt),
    proof = input.proof.map(bytes);
  const trie = new Trie({ useKeyHashing: false });
  equal(await trie.verifyProof(root, key, proof), receipt);
  const map = new Map(proof.map((n) => [hex(keccak256(n)), n]));
  const nibbles = Array.from(key).flatMap((x) => [x >> 4, x & 15]);
  let hash = root,
    pos = 0;
  const nodes = [];
  for (let step = 0; step <= nibbles.length; step++) {
    const node = map.get(hex(hash));
    assert(node, "Missing proof node");
    const fields = RLP.decode(node);
    equal(RLP.encode(fields), node);
    assert(Array.isArray(fields));
    let child;
    if (fields.length === 17) {
      assert(pos < nibbles.length);
      assert(fields[16] instanceof Uint8Array && fields[16].length === 0);
      child = fields[nibbles[pos++]];
    } else {
      assert.equal(fields.length, 2);
      const compact = fields[0];
      assert(compact instanceof Uint8Array && compact.length > 0);
      const flag = compact[0] >> 4;
      assert(flag < 4);
      if (!(flag & 1)) assert.equal(compact[0] & 15, 0);
      const path = Array.from(compact)
        .flatMap((x) => [x >> 4, x & 15])
        .slice(flag & 1 ? 1 : 2);
      equal(path, nibbles.slice(pos, pos + path.length));
      pos += path.length;
      if (flag >= 2) {
        assert.equal(pos, nibbles.length);
        equal(fields[1], receipt);
        return { root, key, decoded, nodes, leaf: node };
      }
      assert(path.length > 0);
      child = fields[1];
    }
    assert(
      child instanceof Uint8Array && child.length === 32,
      "Receipt child must be a hash",
    );
    nodes.push({
      bytes: Array.from(node),
      length: node.length,
      is_extension: fields.length === 2,
    });
    hash = child;
  }
  throw new Error("Receipt path did not terminate");
}
export async function inspectReceiptProof(input) {
  const p = await inspect(input);
  return {
    depth: p.nodes.length,
    nodeBytes: Math.max(3, ...p.nodes.map((n) => n.length)),
    leafBytes: p.leaf.length,
    maxLogs: p.decoded.logs.length,
    dataBytes: Math.max(1, ...p.decoded.logs.map((l) => bytes(l.data).length)),
  };
}
export async function prepareReceipt(
  input,
  { depth = 8, nodeBytes = 532, leafBytes = 2048, maxLogs = 16 } = {},
) {
  for (const n of [depth, nodeBytes, leafBytes, maxLogs])
    assert(Number.isSafeInteger(n) && n >= 0, "Invalid capacity");
  assert(depth <= 18 && nodeBytes >= 3 && nodeBytes <= 532 && leafBytes > 0);
  const p = await inspect(input);
  assert(
    p.decoded.logs.length <= maxLogs,
    `Log capacity exceeded: receipt has ${p.decoded.logs.length} logs, capacity ${maxLogs}`,
  );
  // Index keys are RLP(index): indices >= 256 need depth 5 in blocks with 273 or
  // more receipts and depth 6 in blocks with 513 or more.
  assert(
    p.nodes.length <= depth,
    `Path capacity exceeded: receipt ${input.transactionIndex} path has ${p.nodes.length} internal nodes, capacity ${depth}`,
  );
  const nodes = p.nodes.map((n, i) => ({
    ...n,
    bytes: pad(n.bytes, nodeBytes, `receipt path node ${i}`),
  }));
  const witness = {
    receipts_root: limbs(p.root),
    transaction_index: BigInt(input.transactionIndex).toString(),
    nodes: [
      ...nodes,
      ...Array.from({ length: depth - nodes.length }, () => ({
        bytes: Array(nodeBytes).fill(0),
        length: 0,
        is_extension: false,
      })),
    ],
    count: nodes.length,
    leaf: pad(p.leaf, leafBytes, "receipt leaf"),
    leaf_length: p.leaf.length,
  };
  const d = p.decoded;
  const claim = {
    receipts_root: witness.receipts_root,
    transaction_index: witness.transaction_index,
    receipt_type: d.receiptType,
    has_post_state: d.hasPostState,
    status: d.status,
    post_state: Array.from(bytes(d.postState)),
    cumulative_gas_used: d.cumulativeGasUsed,
  };
  return { witness, claim };
}
export async function prepareEvent(input, options = {}) {
  const { logIndex = 0, dataBytes = 256, ...receiptOptions } = options;
  assert(Number.isSafeInteger(logIndex) && logIndex >= 0);
  assert(Number.isSafeInteger(dataBytes) && dataBytes >= 1);
  const prepared = await prepareReceipt(input, receiptOptions),
    log = decodeReceipt(input.receipt).logs[logIndex];
  assert(log, "Missing receipt-local log");
  const data = bytes(log.data),
    topics = log.topics.map((t) => Array.from(bytes(t)));
  const expected = {
    emitter: Array.from(bytes(log.address)),
    topics: [
      ...topics,
      ...Array.from({ length: 4 - topics.length }, () => Array(32).fill(0)),
    ],
    topic_count: topics.length,
    data: pad(data, dataBytes, "event data"),
    data_length: data.length,
  };
  return {
    witness: { ...prepared.witness, log_index: logIndex, expected },
    claim: {
      receipts_root: prepared.witness.receipts_root,
      transaction_index: prepared.witness.transaction_index,
      log_index: logIndex,
      emitter: expected.emitter,
      topics: expected.topics,
      topic_count: topics.length,
      data_hash: limbs(keccak256(data)),
      data_length: data.length,
    },
  };
}
