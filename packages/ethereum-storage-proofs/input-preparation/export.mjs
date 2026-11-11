import assert from "node:assert/strict";
import { validateProfile } from "./profiles.mjs";
const FR =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const array = (a, n, check) => {
  assert(Array.isArray(a) && a.length === n, "Invalid array length");
  a.forEach(check);
};
const decimal = (v, max) =>
  assert(
    typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) < max,
    "Noncanonical integer",
  );
const field = (v) => decimal(v, FR);
const byte = (v) =>
  assert(Number.isInteger(v) && v >= 0 && v < 256, "Invalid byte");
const word = (v) => array(v, 32, byte);
const root = (v) => array(v, 4, (x) => decimal(x, 1n << 64n));
/** Structural check only: does NOT verify the proof, statement commitment or root.
 * producer_vk_hash is the prover's claim about its own key, not an authorisation.
 * Pass expectedVkHash (from your own policy) to require that the bundle names it. */
export function checkRecursiveProofExport(bundle, { expectedVkHash } = {}) {
  assert(
    bundle?.format_version === 2,
    "Unsupported recursive_proof export version (version 1 named the producer key authorized_vk_hash)",
  );
  const p = bundle.protocol;
  assert(
    p?.aztec_tag === "v6.0.0" &&
      p.noir_commit === "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7" &&
      p.transcript === "Poseidon2" &&
      p.proof_type === 6,
    "Unsupported protocol",
  );
  validateProfile(bundle.profile);
  array(bundle.certificate?.verification_key, 115, field);
  array(bundle.certificate?.proof, 458, field);
  field(bundle.producer_vk_hash);
  if (expectedVkHash !== undefined) {
    field(expectedVkHash);
    assert(
      bundle.producer_vk_hash === expectedVkHash,
      "RecursiveProof producer key is not the authorised key",
    );
  }
  field(bundle.statement);
  const c = bundle.expected;
  assert(c && typeof c === "object", "Missing claim");
  const scope = bundle.profile.scope;
  if (["l1", "account", "account_absent", "l1_zero"].includes(scope)) {
    root(c.state_root);
    array(c.address, 20, byte);
  }
  if (
    ["account", "storage", "threshold", "batch", "storage_zero"].includes(scope)
  )
    root(c.storage_root);
  if (["receipt", "event"].includes(scope)) {
    root(c.receipts_root);
    decimal(c.transaction_index, 1n << 64n);
    const u32 = (v) =>
      assert(Number.isInteger(v) && v >= 0 && v < 2 ** 32, "Invalid u32");
    if (scope === "receipt") {
      byte(c.receipt_type);
      assert(
        typeof c.has_post_state === "boolean" && typeof c.status === "boolean",
      );
      word(c.post_state);
      decimal(c.cumulative_gas_used, 1n << 64n);
    } else {
      u32(c.log_index);
      u32(c.topic_count);
      assert(c.topic_count <= 4);
      u32(c.data_length);
      array(c.emitter, 20, byte);
      array(c.topics, 4, word);
      root(c.data_hash);
    }
  } else if (["storage_zero", "l1_zero"].includes(scope)) {
    word(c.slot_key);
  } else if (scope === "account_absent") {
  } else if (scope === "batch") {
    array(c.slot_keys, bundle.profile.slots, word);
    array(c.values, bundle.profile.slots, word);
  } else if (scope !== "account") {
    word(c.slot_key);
    word(scope === "threshold" ? c.minimum : c.value);
  }
  return bundle;
}
