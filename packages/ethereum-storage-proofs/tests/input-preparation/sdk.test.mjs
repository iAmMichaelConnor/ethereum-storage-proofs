import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  inspectProof,
  recommendProfile,
  prepareMixedBatch,
  prepareBatchStorage,
  checkRecursiveProofExport,
} from "ethereum-storage-proofs";
const input = JSON.parse(
  readFileSync(new URL("../fixtures/batch-shared-rpc.json", import.meta.url)),
);
test("package exports prepare the independently verified batch", async () => {
  const info = await inspectProof(input, { scope: "batch" }),
    p = recommendProfile(info);
  const witness =
    p.layout === "mixed"
      ? await prepareMixedBatch(input, {
          slots: p.slots,
          buckets: p.buckets,
          pathDepth: p.depth,
        })
      : await prepareBatchStorage(input, {
          slots: p.slots,
          nodeCapacity: p.nodes,
          pathDepth: p.depth,
          nodeBytes: p.bytes,
        });
  assert.equal(witness.slot_keys.length, 4);
});
const bundle = () => ({
  format_version: 2,
  protocol: {
    aztec_tag: "v6.0.0",
    noir_commit: "5a7ee9bf5ed8973076df7bb0d2b723024db09ae7",
    transcript: "Poseidon2",
    proof_type: 6,
  },
  profile: {
    version: 1,
    scope: "storage",
    mode: "general",
    account: [],
    storage: [],
  },
  certificate: {
    verification_key: Array(115).fill("0"),
    proof: Array(458).fill("0"),
  },
  expected: {
    storage_root: Array(4).fill("0"),
    slot_key: Array(32).fill(0),
    value: Array(32).fill(255),
  },
  producer_vk_hash: "7",
  statement: "0",
});
test("export checks structure; it deliberately makes no cryptographic validity claim", () =>
  assert.equal(checkRecursiveProofExport(bundle()).format_version, 2));
test("a bundle names its producer key; policy comes from the caller", () => {
  assert.equal(
    checkRecursiveProofExport(bundle(), { expectedVkHash: "7" }).producer_vk_hash,
    "7",
  );
  assert.throws(
    () => checkRecursiveProofExport(bundle(), { expectedVkHash: "8" }),
    /not the authorised key/,
  );
  // Version 1 exported the producer's own key as authorized_vk_hash.
  const old = bundle();
  old.format_version = 1;
  old.authorized_vk_hash = old.producer_vk_hash;
  delete old.producer_vk_hash;
  assert.throws(() => checkRecursiveProofExport(old), /version/);
});
test("export rejects noncanonical fields, root limbs and shapes", () => {
  for (const mutate of [
    (b) => (b.format_version = 1),
    (b) => (b.format_version = 3),
    (b) => (b.protocol.transcript = "Keccak"),
    // RecursiveProofs proved with the rc.6 backend lack the v6.0.0 soundness fixes.
    (b) => (b.protocol.aztec_tag = "v6.0.0-rc.6"),
    (b) => b.certificate.proof.pop(),
    (b) => (b.statement = "01"),
    (b) => (b.producer_vk_hash = "-1"),
    (b) => delete b.producer_vk_hash,
    (b) =>
      (b.statement =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"),
    (b) => (b.expected.storage_root[0] = "18446744073709551616"),
    (b) => (b.expected.value[0] = 256),
  ]) {
    const b = bundle();
    mutate(b);
    assert.throws(() => checkRecursiveProofExport(b));
  }
});
