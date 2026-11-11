/** Inspect verified proof shapes; selecting a profile never authorizes its key. */
import assert from "node:assert/strict";
import { RLP } from "@ethereumjs/rlp";
import { prepareAccount, prepareStorage, selectSlotIndex } from "./prepare.mjs";

export const BYTE_CAPACITIES = [135, 271, 407, 532];
const capacity = (length) => {
  const result = BYTE_CAPACITIES.find((n) => n >= length);
  assert(result !== undefined, "Unsupported node size");
  return result;
};
const shape = (nodes) => ({
  lengths: nodes.map((n) => n.length),
  hasEmbedded: nodes.some((n) =>
    RLP.decode(Uint8Array.from(n.bytes.slice(0, n.length))).some(Array.isArray),
  ),
});
/**
 * slotIndex selects the storageProof entry for single-slot scopes. It is required
 * when the input holds several entries, and rejected for account and batch scopes.
 */
export async function inspectProof(input, { scope = "l1", slotIndex } = {}) {
  assert(
    ["l1", "account", "storage", "threshold", "batch"].includes(scope),
    "Unknown scope",
  );
  assert(
    slotIndex === undefined || !["account", "batch"].includes(scope),
    "slotIndex applies only to single-slot storage scopes",
  );
  const result = {
    version: 1,
    scope,
    account: { lengths: [], hasEmbedded: false },
    storage: [],
    shared: { lengths: [], hasEmbedded: false },
  };
  if (scope === "l1" || scope === "account") {
    const w = await prepareAccount(input, {
      accountDepth: 64,
      accountBytes: 532,
    });
    result.account = shape(w.account_nodes.slice(0, w.account_count));
  }
  if (scope !== "account") {
    const entries = input.proof?.storageProof;
    assert(
      Array.isArray(entries) && entries.length > 0,
      "Expected storage proofs",
    );
    const indices =
      scope === "batch"
        ? entries.map((_, i) => i)
        : [selectSlotIndex(entries, slotIndex)];
    const shared = new Map();
    for (const slot of indices) {
      const w = await prepareStorage(input, {
        storageDepth: 64,
        storageBytes: 532,
        slotIndex: slot,
      });
      const nodes = w.storage_nodes.slice(0, w.storage_count);
      result.storage.push(shape(nodes));
      for (const n of nodes)
        shared.set(Buffer.from(n.bytes.slice(0, n.length)).toString("hex"), n);
    }
    result.shared = shape([...shared.values()]);
  }
  return result;
}
/**
 * Round the observed shape up to byte buckets. By default there is no headroom: a
 * third party can lengthen a path or fill a branch (see docs/internals.md). extraDepth
 * appends that many 532-byte positions to each path; fullWidth makes every
 * position 532 bytes, which fits any branch.
 */
export function recommendProfile(
  info,
  { extraDepth = 0, fullWidth = false } = {},
) {
  assert(
    Number.isSafeInteger(extraDepth) && extraDepth >= 0 && extraDepth <= 64,
    "Invalid extraDepth",
  );
  assert(typeof fullWidth === "boolean", "Invalid fullWidth");
  if (info.scope === "batch") {
    assert(
      extraDepth === 0 && !fullWidth,
      "Headroom options apply to single-path scopes",
    );
    const base = {
      version: 1,
      scope: "batch",
      slots: info.storage.length,
      depth: Math.max(0, ...info.storage.map((x) => x.lengths.length)),
    };
    const uniform = {
      ...base,
      nodes: info.shared.lengths.length,
      bytes: Math.max(135, ...info.shared.lengths.map(capacity)),
    };
    const buckets = BYTE_CAPACITIES.map(
      (b) => info.shared.lengths.filter((n) => capacity(n) === b).length,
    );
    const mixed = { ...base, layout: "mixed", buckets };
    return profileCost(mixed).nodeHashPermutations <
      profileCost(uniform).nodeHashPermutations
      ? mixed
      : uniform;
  }
  const path = (lengths, used) => {
    if (!used) return [];
    const caps = [...lengths.map(capacity), ...Array(extraDepth).fill(532)];
    assert(caps.length <= 64, "Path capacity exceeds 64 nodes");
    return fullWidth ? caps.map(() => 532) : caps;
  };
  return {
    version: 1,
    scope: info.scope,
    mode: "general",
    account: path(info.account.lengths, ["l1", "account"].includes(info.scope)),
    storage: path(info.storage[0]?.lengths ?? [], info.scope !== "account"),
  };
}
const integer = (n, lo, hi) => Number.isSafeInteger(n) && n >= lo && n <= hi;
export function validateProfile(p) {
  assert(p && p.version === 1, "Unsupported profile version");
  if (["storage_zero", "account_absent", "l1_zero"].includes(p.scope)) {
    assert(
      integer(p.depth, 0, 64) &&
        integer(p.node_bytes, 3, 532) &&
        integer(p.terminal_bytes, 3, 532),
      "Invalid absence capacity",
    );
    if (p.scope === "l1_zero")
      assert(
        integer(p.account_depth, 0, 64) && integer(p.account_bytes, 3, 532),
        "Invalid account capacity",
      );
  } else if (["receipt", "event"].includes(p.scope)) {
    assert(
      integer(p.depth, 0, 18) &&
        integer(p.node_bytes, 3, 532) &&
        integer(p.leaf_bytes, 3, 0xffffffff) &&
        integer(p.max_logs, p.scope === "event" ? 1 : 0, 0xffffffff),
      "Invalid receipt capacity",
    );
    if (p.scope === "event")
      assert(
        integer(p.data_bytes, 1, 0xffffffff),
        "Invalid event data capacity",
      );
  } else if (p.scope === "batch") {
    assert(
      p.parsing === undefined || ["path", "shared"].includes(p.parsing),
      "Unknown parsing mode",
    );
    assert(
      integer(p.slots, 1, 64) && integer(p.depth, 0, 64),
      "Invalid batch capacity",
    );
    assert(
      p.layout === undefined || ["uniform", "mixed"].includes(p.layout),
      "Unknown batch layout",
    );
    if (p.layout === "mixed")
      assert(
        Array.isArray(p.buckets) &&
          p.buckets.length === 4 &&
          p.buckets.every((n) => integer(n, 0, 64 * p.slots)),
        "Invalid bucket capacities",
      );
    else
      assert(
        integer(p.nodes, 0, 64 * p.slots) && integer(p.bytes, 3, 532),
        "Invalid batch capacity",
      );
  } else {
    assert(
      ["l1", "account", "storage", "threshold"].includes(p.scope),
      "Unknown profile scope",
    );
    assert(["general", "hashed"].includes(p.mode), "Unknown path mode");
    for (const xs of [p.account, p.storage])
      assert(
        Array.isArray(xs) &&
          xs.length <= 64 &&
          xs.every((n) => integer(n, 3, 532)),
        "Invalid path capacities",
      );
    assert(
      !["storage", "threshold"].includes(p.scope) || p.account.length === 0,
      "Unexpected account path",
    );
    assert(
      p.scope !== "account" || p.storage.length === 0,
      "Unexpected storage path",
    );
  }
  return p;
}
/** Why profile p cannot take the inspected proof, or null when it fits. */
export function profileMisfit(info, p) {
  validateProfile(p);
  if (info.scope !== p.scope)
    return `scope ${p.scope} differs from proof scope ${info.scope}`;
  if (p.scope === "batch") {
    if (p.slots !== info.storage.length)
      return `${p.slots} slots, proof has ${info.storage.length}`;
    const deepest = Math.max(0, ...info.storage.map((s) => s.lengths.length));
    if (deepest > p.depth)
      return `path depth ${deepest} exceeds capacity ${p.depth}`;
    if (p.layout === "mixed") {
      const remaining = [...p.buckets];
      for (const length of [...info.shared.lengths].sort((a, b) => b - a)) {
        const bucket = BYTE_CAPACITIES.findIndex(
          (b, i) => b >= length && remaining[i] > 0,
        );
        if (bucket < 0)
          return `no free bucket for a ${length}-byte shared node`;
        remaining[bucket]--;
      }
      return null;
    }
    if (p.nodes < info.shared.lengths.length)
      return `${info.shared.lengths.length} shared nodes exceed capacity ${p.nodes}`;
    const largest = Math.max(0, ...info.shared.lengths);
    return largest > p.bytes
      ? `a ${largest}-byte shared node exceeds capacity ${p.bytes}`
      : null;
  }
  const misfit = (name, xs, caps) => {
    if (xs.length > caps.length)
      return `${name} path has ${xs.length} internal nodes, capacity ${caps.length}`;
    const i = xs.findIndex((n, j) => n > caps[j]);
    return i < 0
      ? null
      : `${name} node ${i} needs ${xs[i]} bytes, capacity ${caps[i]}`;
  };
  return (
    misfit("account", info.account.lengths, p.account) ??
    misfit("storage", info.storage[0]?.lengths ?? [], p.storage) ??
    (p.mode === "hashed" && info.storage.some((s) => s.hasEmbedded)
      ? "hash-only mode, but a storage path node has an embedded child"
      : null)
  );
}
export function fitsProfile(info, p) {
  return profileMisfit(info, p) === null;
}
export function profileCost(p) {
  validateProfile(p);
  const caps = ["storage_zero", "account_absent", "l1_zero"].includes(p.scope)
    ? [
        ...Array(p.depth).fill(p.node_bytes),
        p.terminal_bytes,
        ...(p.scope === "l1_zero"
          ? Array(p.account_depth).fill(p.account_bytes)
          : []),
      ]
    : ["receipt", "event"].includes(p.scope)
      ? [
          ...Array(p.depth).fill(p.node_bytes),
          p.leaf_bytes,
          ...(p.scope === "event" ? [p.data_bytes] : []),
        ]
      : p.scope === "batch"
        ? p.layout === "mixed"
          ? p.buckets.flatMap((n, i) => Array(n).fill(BYTE_CAPACITIES[i]))
          : Array(p.nodes).fill(p.bytes)
        : [...p.account, ...p.storage];
  return {
    nodeHashPermutations: caps.reduce((n, b) => n + Math.floor(b / 136) + 1, 0),
    nodeBytes: caps.reduce((a, b) => a + b, 0),
  };
}
export function selectProfile(info, catalogue) {
  assert(
    catalogue?.version === 1 && Array.isArray(catalogue.profiles),
    "Invalid catalogue",
  );
  const ids = new Set(),
    reasons = [];
  const candidates = catalogue.profiles
    .map((entry) => {
      assert(
        typeof entry.id === "string" && entry.id && !ids.has(entry.id),
        "Invalid or duplicate profile id",
      );
      ids.add(entry.id);
      assert(
        entry.fallback === undefined || typeof entry.fallback === "boolean",
        "Invalid fallback flag",
      );
      validateProfile(entry.profile);
      return { ...entry, cost: profileCost(entry.profile) };
    })
    .filter((e) => {
      const reason = profileMisfit(info, e.profile);
      if (reason !== null) reasons.push(`${e.id}: ${reason}`);
      return reason === null;
    });
  candidates.sort(
    (a, b) =>
      Number(!!a.fallback) - Number(!!b.fallback) ||
      a.cost.nodeHashPermutations - b.cost.nodeHashPermutations ||
      a.cost.nodeBytes - b.cost.nodeBytes ||
      a.id.localeCompare(b.id),
  );
  assert(
    candidates.length,
    `No catalogue profile fits; no proof was truncated. ${reasons.join("; ")}`,
  );
  return candidates[0];
}
