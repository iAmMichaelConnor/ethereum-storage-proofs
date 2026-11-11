/** Explicit RPC transport only. Returned roots still require application authentication. */
import assert from "node:assert/strict";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { prepareAccount, prepareStorage } from "./prepare.mjs";
import {
  EMPTY_TRIE_ROOT,
  prepareAccountAbsent,
  prepareStorageZero,
} from "./absence.mjs";

const bytes = (value, size, label) => {
  assert(
    typeof value === "string" && /^0x(?:[0-9a-fA-F]{2})*$/.test(value),
    `Invalid ${label}`,
  );
  assert(
    size === undefined || value.length === 2 + 2 * size,
    `Invalid ${label}`,
  );
  return value.toLowerCase();
};
const quantity = (value, bits, label) => {
  assert(
    typeof value === "string" && /^0x[0-9a-fA-F]+$/.test(value),
    `Invalid ${label}`,
  );
  const n = BigInt(value);
  assert(n < 1n << BigInt(bits), `Invalid ${label}`);
  return `0x${n.toString(16)}`;
};
const slot = (value) =>
  `0x${BigInt(quantity(value, 256, "slot key"))
    .toString(16)
    .padStart(64, "0")}`;
const path = (value, label) => {
  assert(Array.isArray(value), `Invalid ${label}`);
  return value.map((node) => bytes(node, undefined, label));
};
const header = (value) => {
  assert(value && typeof value === "object", "Block is unavailable");
  return {
    number: quantity(value.number, 256, "block number"),
    hash: bytes(value.hash, 32, "block hash"),
    stateRoot: bytes(value.stateRoot, 32, "state root"),
  };
};
const EMPTY_CODE_HASH = `0x${Buffer.from(keccak256(new Uint8Array())).toString("hex")}`;

/**
 * Fetch one account proof and zero or more slots at one exact block number.
 * Re-read its hash/root after fetching to reject reorgs; verify all raw RLP paths
 * using the existing host validators. No RPC URL or provider error text escapes.
 */
export async function fetchProof(options) {
  assert(options && typeof options === "object", "Expected fetchProof options");
  for (const key of Object.keys(options))
    assert(
      ["rpcUrl", "address", "slots", "block", "fetch", "timeoutMs"].includes(
        key,
      ),
      `Unknown fetchProof option: ${key}`,
    );
  const {
    rpcUrl,
    slots = [],
    block = "finalized",
    fetch: fetcher = globalThis.fetch,
    timeoutMs = 30_000,
  } = options;
  let url;
  try {
    url = new URL(rpcUrl);
  } catch {
    throw new Error("Invalid RPC URL");
  }
  assert(
    ["https:", "http:"].includes(url.protocol),
    "Invalid RPC URL protocol",
  );
  const address = bytes(options.address, 20, "address");
  assert(Array.isArray(slots), "Expected slot keys");
  const keys = slots.map(slot);
  assert(typeof fetcher === "function", "Expected fetch implementation");
  assert(
    Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 0x7fffffff,
    "Invalid RPC timeout",
  );
  const tag = ["latest", "earliest", "safe", "finalized"].includes(block)
    ? block
    : quantity(block, 256, "block selector");
  let id = 0;
  const rpc = async (method, params) => {
    const requestId = ++id;
    let body;
    try {
      const response = await fetcher(url.href, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: requestId, method, params }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error();
      body = await response.json();
    } catch {
      throw new Error(`RPC transport failed (${method})`);
    }
    // Provider messages/data can contain endpoint credentials: never interpolate them.
    if (
      !body ||
      body.jsonrpc !== "2.0" ||
      body.id !== requestId ||
      body.error ||
      !("result" in body)
    )
      throw new Error(`RPC response failed (${method})`);
    return body.result;
  };
  const selected = header(await rpc("eth_getBlockByNumber", [tag, false]));
  if (tag.startsWith("0x"))
    assert.equal(selected.number, tag, "RPC returned a different block number");
  const raw = await rpc("eth_getProof", [address, keys, selected.number]);
  assert(raw && typeof raw === "object", "Invalid proof response");
  assert.equal(
    bytes(raw.address, 20, "proof address"),
    address,
    "RPC returned a different address",
  );
  assert(
    Array.isArray(raw.storageProof) && raw.storageProof.length === keys.length,
    "RPC returned a different slot count",
  );
  const entries = raw.storageProof.map((entry) => {
    assert(
      entry && typeof entry === "object" && !Array.isArray(entry),
      "Invalid storage proof entry",
    );
    return {
      key: slot(entry.key),
      value: quantity(entry.value, 256, "storage value"),
      proof: path(entry.proof, "storage proof"),
    };
  });
  const remaining = [...entries];
  const storageProof = keys.map((key) => {
    const i = remaining.findIndex((entry) => entry.key === key);
    assert(i >= 0, "RPC returned different slot keys");
    return remaining.splice(i, 1)[0];
  });
  const input = {
    stateRoot: selected.stateRoot,
    proof: {
      address,
      nonce: quantity(raw.nonce, 64, "account nonce"),
      balance: quantity(raw.balance, 256, "account balance"),
      storageHash: bytes(raw.storageHash, 32, "storage root"),
      codeHash: bytes(raw.codeHash, 32, "code hash"),
      accountProof: path(raw.accountProof, "account proof"),
      storageProof,
    },
    block: { number: selected.number, hash: selected.hash },
  };
  const checked = header(
    await rpc("eth_getBlockByNumber", [selected.number, false]),
  );
  assert.deepEqual(
    checked,
    selected,
    "Block changed during proof fetching; retry with an authenticated block",
  );
  try {
    // Absent accounts have no account value: use the existing absence relation.
    const p = input.proof;
    if (
      p.nonce === "0x0" &&
      p.balance === "0x0" &&
      p.storageHash === EMPTY_TRIE_ROOT &&
      p.codeHash === EMPTY_CODE_HASH
    ) {
      try {
        await prepareAccount(input, { accountDepth: 64, accountBytes: 532 });
      } catch {
        await prepareAccountAbsent(input, {
          depth: 64,
          nodeBytes: 532,
          terminalBytes: 532,
        });
      }
    } else await prepareAccount(input, { accountDepth: 64, accountBytes: 532 });
    for (let slotIndex = 0; slotIndex < storageProof.length; slotIndex++) {
      if (storageProof[slotIndex].value === "0x0")
        await prepareStorageZero(input, {
          slotIndex,
          depth: 64,
          nodeBytes: 532,
          terminalBytes: 532,
        });
      else
        await prepareStorage(input, {
          slotIndex,
          storageDepth: 64,
          storageBytes: 532,
        });
    }
  } catch {
    throw new Error("Fetched proof failed local trie validation");
  }
  return input;
}
