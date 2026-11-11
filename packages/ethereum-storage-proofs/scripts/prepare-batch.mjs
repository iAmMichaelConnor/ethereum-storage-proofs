#!/usr/bin/env node
// Compatibility CLI adapter; reusable implementation lives in packages/ethereum-storage-proofs/input-preparation/.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { prepareBatchStorage } from "../input-preparation/batch.mjs";
export * from "../input-preparation/batch.mjs";
if (
  process.argv[1] &&
  import.meta.url === new URL(process.argv[1], "file:").href
) {
  try {
    const [input, output, k, p, d, b] = process.argv.slice(2);
    assert(
      input && output,
      "Usage: prepare-batch.mjs input output slots nodes depth bytes",
    );
    writeFileSync(
      output,
      JSON.stringify(
        await prepareBatchStorage(JSON.parse(readFileSync(input, "utf8")), {
          slots: Number(k),
          nodeCapacity: Number(p),
          pathDepth: Number(d),
          nodeBytes: Number(b),
        }),
        null,
        2,
      ) + "\n",
    );
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}
