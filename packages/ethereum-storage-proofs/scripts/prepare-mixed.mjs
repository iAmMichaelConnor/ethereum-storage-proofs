#!/usr/bin/env node
// Compatibility CLI adapter; reusable implementation lives in packages/ethereum-storage-proofs/input-preparation/.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { prepareMixedBatch } from "../input-preparation/mixed.mjs";
export * from "../input-preparation/mixed.mjs";
if (
  process.argv[1] &&
  import.meta.url === new URL(process.argv[1], "file:").href
) {
  try {
    const [input, output, k, buckets, depth] = process.argv.slice(2);
    const w = await prepareMixedBatch(JSON.parse(readFileSync(input, "utf8")), {
      slots: Number(k),
      buckets: buckets.split(",").map(Number),
      pathDepth: Number(depth),
    });
    writeFileSync(output, JSON.stringify(w, null, 2) + "\n");
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}
