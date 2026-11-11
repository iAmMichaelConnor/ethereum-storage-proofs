// JSON-RPC oracle for the differential tests in this package: answers nargo's
// resolve_foreign_call. Each case is drawn from a Keccak stream seeded by the
// test's random argument and built with EthereumJS (trie, RLP) and
// ethereum-cryptography (Keccak), so the seed nargo prints for a failure
// reproduces the case exactly.
//
//   node tests/ethereum_oracle_tests/oracle_server.mjs [port]     (default 8095)
import { createServer } from "node:http";
import assert from "node:assert/strict";
import { Trie } from "@ethereumjs/trie";
import { RLP } from "@ethereumjs/rlp";
import { keccak256 } from "ethereum-cryptography/keccak.js";

// Capacities of the Noir tests: internal nodes, bytes per node, receipt leaf
// bytes, logs per receipt and event data bytes.
const D = 8,
  B = 532,
  LEAF = 1024,
  MAX_LOGS = 3,
  DATA = 256;
// Terminal kinds of ethereum_proofs::absence.
const BRANCH = 0,
  EXTENSION = 1,
  LEAF_KIND = 2;

const pad = (b, n) => {
  assert(b.length <= n, `${b.length} bytes exceed capacity ${n}`);
  return [...b, ...Array(n - b.length).fill(0)];
};
const limbs = (b) =>
  Array.from({ length: 4 }, (_, i) => Buffer.from(b.subarray(8 * i, 8 * i + 8)).readBigUInt64LE());
const nibbles = (b) => Array.from(b).flatMap((x) => [x >> 4, x & 15]);
const packed = (n) =>
  Uint8Array.from({ length: n.length / 2 }, (_, i) => (n[2 * i] << 4) | n[2 * i + 1]);
const hex = (b) => Buffer.from(b).toString("hex");
const integer = (n) => {
  if (n === 0n) return new Uint8Array();
  const h = n.toString(16);
  return Uint8Array.from(Buffer.from(h.length % 2 ? "0" + h : h, "hex"));
};

// Random choices: Keccak of the seed and a counter.
function draw(seed) {
  const key = keccak256(Buffer.from(seed.padStart(64, "0"), "hex"));
  let block = new Uint8Array(),
    used = 0,
    counter = 0;
  const byte = () => {
    if (used === block.length) {
      block = keccak256(Uint8Array.from([...key, counter >> 8, counter++ & 255]));
      used = 0;
    }
    return block[used++];
  };
  const below = (n) => ((byte() << 16) | (byte() << 8) | byte()) % n;
  const bytes = (n) => Uint8Array.from({ length: n }, byte);
  // A canonical nonzero big-endian integer of n bytes.
  const scalar = (n) => {
    const v = bytes(n);
    if (n) v[0] ||= 1;
    return v;
  };
  return { below, bytes, scalar, pick: (a) => a[below(a.length)] };
}

// Split an EthereumJS proof for `key` (its nibbles) into the internal nodes the
// Noir verifiers take, decoding embedded children, and the node where the walk
// ends: the leaf of a present key (kind null), else the absence terminal.
function walk(root, proof, key) {
  const byHash = new Map(proof.map((p) => [hex(keccak256(p)), p]));
  let node = byHash.get(hex(root)),
    index = 0;
  const nodes = [];
  for (;;) {
    assert(node, "Missing proof node");
    const fields = RLP.decode(node);
    let child;
    if (fields.length === 17) {
      child = fields[key[index]];
      if (child.length === 0) return { nodes, end: node, kind: BRANCH };
      index += 1;
    } else {
      const path = nibbles(fields[0]),
        suffix = path.slice(path[0] % 2 ? 1 : 2),
        matches = suffix.every((n, i) => n === key[index + i]);
      if (path[0] >= 2) {
        const found = matches && index + suffix.length === key.length;
        return { nodes, end: node, kind: found ? null : LEAF_KIND };
      }
      if (!matches) return { nodes, end: node, kind: EXTENSION };
      index += suffix.length;
      child = fields[1];
    }
    nodes.push(node);
    node = Array.isArray(child) ? RLP.encode(child) : byHash.get(hex(child));
  }
}

// [EncodedNode<B>; D]: each node's bytes, length and is_extension.
function encodedNodes(nodes) {
  assert(nodes.length <= D, `${nodes.length} internal nodes exceed capacity ${D}`);
  return [...nodes, ...Array(D - nodes.length).fill(new Uint8Array())].flatMap((n) => [
    ...pad(n, B),
    n.length,
    n.length > 0 && RLP.decode(n).length === 2,
  ]);
}

// A raw-key trie of one to five storage values. Each key keeps a prefix of 0 to
// 64 nibbles of an earlier key, so the trie has extensions of every length and,
// with short values, embedded leaves and branches. The query is a stored key,
// or with `absent`, a key that leaves a stored key at a random nibble.
async function trieCase(random, absent) {
  const trie = new Trie(),
    stored = new Map(),
    keys = [];
  for (let i = 1 + random.below(5); i > 0; i--) {
    const shared = keys.length ? random.below(65) : 0,
      prefix = keys.length ? random.pick(keys).slice(0, shared) : [],
      key = [...prefix, ...nibbles(random.bytes(32)).slice(shared)],
      value = random.scalar(random.below(2) ? 1 + random.below(4) : 1 + random.below(32));
    await trie.put(packed(key), RLP.encode(value));
    stored.set(hex(packed(key)), value);
    keys.push(key);
  }
  let key = random.pick(keys),
    value = stored.get(hex(packed(key)));
  if (absent) {
    const at = random.below(64);
    const other = (key[at] + 1 + random.below(15)) % 16;
    key = [...key.slice(0, at), other, ...nibbles(random.bytes(32)).slice(at + 1)];
    while (stored.has(hex(packed(key)))) key[63] = (key[63] + 1) % 16;
    value = new Uint8Array();
  }
  const raw = packed(key),
    proof = await trie.createProof(raw),
    { nodes, end, kind } = walk(trie.root(), proof, key);
  const found = await trie.verifyProof(trie.root(), raw, proof);
  assert.deepEqual(found, absent ? null : RLP.encode(value));
  assert.equal(kind === null, !absent, "Walk disagrees with EthereumJS");
  return [
    limbs(trie.root()),
    raw,
    pad(value, 32),
    value.length,
    encodedNodes(nodes),
    nodes.length,
    pad(absent ? end : [], B),
    absent ? end.length : 0,
    kind ?? 0,
  ];
}

// An account leaf at a random nibble of keccak(address), with nonce and balance
// of random lengths.
function accountCase(random) {
  const nonce = random.scalar(random.below(9)),
    balance = random.scalar(random.below(33)),
    address = random.bytes(20),
    storage = random.bytes(32),
    code = random.bytes(32),
    at = random.below(65),
    path = nibbles(keccak256(address)).slice(at),
    compact = packed([...(path.length % 2 ? [3] : [2, 0]), ...path]),
    leaf = RLP.encode([compact, RLP.encode([nonce, balance, storage, code])]);
  return [
    pad(nonce, 8),
    pad(balance, 32),
    address,
    nonce.length,
    balance.length,
    limbs(storage),
    limbs(code),
    at,
    limbs(keccak256(leaf)),
  ];
}

// A receipts trie of one to four transactions, whose keys are RLP integers of 1
// to 9 bytes, and a random receipt at one of them: type 0 to 4, status or
// pre-Byzantium state root, zero to three logs of zero to four topics and up to
// 256 data bytes. Logs that do not fit the leaf capacity are dropped.
async function receiptCase(random) {
  const index = () => BigInt("0x" + hex(random.bytes(8))) >> BigInt(random.below(64)),
    others = Array.from({ length: random.below(4) }, index),
    target = index(),
    type = random.below(5),
    historical = type === 0 && random.below(2) === 1,
    success = random.below(2) === 1,
    postState = random.bytes(32),
    gas = BigInt("0x" + hex(random.bytes(8))) >> BigInt(random.below(65)),
    bloom = random.bytes(256);
  let logs = Array.from({ length: random.below(MAX_LOGS + 1) }, () => ({
    emitter: random.bytes(20),
    topics: Array.from({ length: random.below(5) }, () => random.bytes(32)),
    data: random.bytes(
      random.below(2) ? random.pick([0, 1, 55, 56, 255, 256]) : random.below(DATA + 1),
    ),
  }));
  const encode = (logs) => {
    const body = RLP.encode([
      historical ? postState : integer(success ? 1n : 0n),
      integer(gas),
      bloom,
      logs.map((l) => [l.emitter, l.topics, l.data]),
    ]);
    return type ? Uint8Array.from([type, ...body]) : body;
  };
  const trie = new Trie(),
    key = RLP.encode(integer(target));
  for (const other of others)
    if (other !== target) await trie.put(RLP.encode(integer(other)), encode([]));
  let receipt, proof, path;
  for (;;) {
    receipt = encode(logs);
    await trie.put(key, receipt);
    proof = await trie.createProof(key);
    path = walk(trie.root(), proof, nibbles(key));
    if (path.end.length <= LEAF) break;
    logs = logs.slice(0, -1);
  }
  assert.deepEqual(await trie.verifyProof(trie.root(), key, proof), receipt);
  assert.equal(path.kind, null);
  const logIndex = random.below(Math.max(logs.length, 1)),
    log = logs[logIndex] ?? { emitter: [], topics: [], data: [] };
  return [
    limbs(trie.root()),
    target,
    encodedNodes(path.nodes),
    path.nodes.length,
    pad(path.end, LEAF),
    path.end.length,
    type,
    historical,
    !historical && success,
    pad(historical ? postState : [], 32),
    gas,
    logs.length,
    logIndex,
    pad(log.emitter, 20),
    pad(log.topics.flatMap((t) => [...t]), 128),
    log.topics.length,
    pad(log.data, DATA),
    log.data.length,
  ];
}

const oracles = {
  storage_case: ([seed, absent]) => trieCase(draw(seed), BigInt("0x" + absent) === 1n),
  account_case: ([seed]) => accountCase(draw(seed)),
  receipt_case: ([seed]) => receiptCase(draw(seed)),
};
// A result is a list of values in the order of the Noir struct's fields, each a
// hex Field or a flat array of them.
const field = (x) => (typeof x === "boolean" ? Number(x) : x).toString(16);
const value = (x) => (typeof x === "object" ? Array.from(x, field) : field(x));

const port = Number(process.argv[2] ?? 8095);
createServer((request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    response.end("ok");
    return;
  }
  let body = "";
  request.on("data", (chunk) => (body += chunk));
  request.on("end", async () => {
    const { id, method, params } = JSON.parse(body || "{}");
    let reply;
    try {
      assert.equal(method, "resolve_foreign_call", `Unknown method ${method}`);
      const { function: name, inputs } = params[0];
      assert(name in oracles, `Unknown oracle ${name}`);
      reply = { result: { values: (await oracles[name](inputs)).map(value) } };
    } catch (error) {
      console.error(error);
      reply = { error: { code: -32000, message: String(error.message ?? error) } };
    }
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ jsonrpc: "2.0", id, ...reply }));
  });
}).listen(port, "127.0.0.1", () => console.log(`Oracle server on 127.0.0.1:${port}`));
