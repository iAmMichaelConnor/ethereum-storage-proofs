import {
  inspectProof,
  fetchProof,
  recommendProfile,
  prepareMixedBatch,
  prepareBatchStorage,
  ProofEnvelope,
  checkRecursiveProofExport,
} from "ethereum-storage-proofs";
async function example(input: ProofEnvelope, bundle: unknown) {
  const p = recommendProfile(await inspectProof(input, { scope: "batch" }));
  if (p.scope === "batch") {
    if (p.layout === "mixed")
      await prepareMixedBatch(input, {
        buckets: p.buckets,
        slots: p.slots,
        pathDepth: p.depth,
      });
    else
      await prepareBatchStorage(input, {
        nodeCapacity: p.nodes,
        nodeBytes: p.bytes,
        slots: p.slots,
        pathDepth: p.depth,
      });
  }
  return checkRecursiveProofExport(bundle).certificate.proof;
}
void example;

async function fetchExample() {
  const result = await fetchProof({
    rpcUrl: "https://example.invalid",
    address: "0x0000000000000000000000000000000000000000",
    slots: ["0x1"],
    block: "finalized",
    fetch: globalThis.fetch,
  });
  return result.block.hash;
}
void fetchExample;
