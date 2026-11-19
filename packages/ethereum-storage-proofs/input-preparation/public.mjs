// Packed inputs for the ethereum_public_proofs Noir package (Aztec public functions).
// The layouts are those of noir/ethereum_public_proofs/src/node.nr and leaf.nr.
// Field elements are returned as decimal strings. Root authenticity is the caller's responsibility.
import assert from "node:assert/strict";
import { prepareAccount, prepareStorage } from "./prepare.mjs";

export const PUBLIC_NODE_FIELDS = 23;
export const PUBLIC_ACCOUNT_FIELDS = 8;

const laneOf = (bytes, offset) => {
  let lane = 0n;
  for (let j = 0; j < 8; j++)
    lane |= BigInt(bytes[offset + j] ?? 0) << BigInt(8 * j);
  return lane;
};
const three = (lanes, i) =>
  (lanes[i] ?? 0n) + ((lanes[i + 1] ?? 0n) << 64n) + ((lanes[i + 2] ?? 0n) << 128n);
const integer = (bytes, length) =>
  bytes.slice(0, length).reduce((v, b) => (v << 8n) | BigInt(b), 0n);

/** One raw trie node (RLP bytes) as 23 fields: little-endian lanes, three per field. */
export function packPublicNode(bytes) {
  assert(bytes.length >= 2 && bytes.length < 544, "Node exceeds capacity");
  const lanes = Array.from({ length: 69 }, (_, i) => laneOf(bytes, 8 * i));
  return Array.from({ length: PUBLIC_NODE_FIELDS }, (_, k) =>
    three(lanes, 3 * k).toString(),
  );
}

/** An account witness (prepareAccount's `account`) as PublicAccount::from_fields input. */
export function packPublicAccount(account) {
  const balance = integer(account.balance, account.balance_length);
  const lanes = (root) => root.map(BigInt);
  const s = lanes(account.storage_hash),
    c = lanes(account.code_hash);
  return [
    integer(account.address, 20),
    integer(account.nonce, account.nonce_length),
    balance >> 128n,
    balance & ((1n << 128n) - 1n),
    three(s, 0),
    s[3],
    three(c, 0),
    c[3],
  ].map(String);
}

const packPath = (nodes, count, depth) => [
  ...nodes.slice(0, count).map((n) => packPublicNode(n.bytes.slice(0, n.length))),
  ...Array.from({ length: depth - count }, () => Array(PUBLIC_NODE_FIELDS).fill("0")),
];

/**
 * Packed account proof from a saved eth_getProof result ({stateRoot, proof}).
 * `accountDepth` is the node capacity of the Noir function that takes it.
 */
export async function preparePublicAccount(input, { accountDepth = 10 } = {}) {
  const w = await prepareAccount(input, { accountDepth, accountBytes: 532 });
  return {
    stateRoot: w.state_root,
    account: packPublicAccount(w.account),
    accountNodes: packPath(w.account_nodes, w.account_count, accountDepth),
    accountCount: w.account_count,
  };
}

/** Packed storage proof of one nonzero slot (see prepareStorage for slotIndex). */
export async function preparePublicStorage(
  input,
  { storageDepth = 8, slotIndex } = {},
) {
  const w = await prepareStorage(input, { storageDepth, storageBytes: 532, slotIndex });
  const value = integer(w.value.value, w.value.value_length);
  return {
    storageRoot: w.storage_root,
    slotKey: w.slot_key,
    valueHigh: (value >> 128n).toString(),
    valueLow: (value & ((1n << 128n) - 1n)).toString(),
    storageNodes: packPath(w.storage_nodes, w.storage_count, storageDepth),
    storageCount: w.storage_count,
  };
}
