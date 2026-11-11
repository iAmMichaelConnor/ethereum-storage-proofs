#!/usr/bin/env node
// Thin adapter: raw RLP validation and optional transport live in packages/ethereum-storage-proofs/input-preparation/.
import { writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { fetchProof } from "../input-preparation/rpc.mjs";
const usage =
  "storage-proofs fetch --rpc URL --address HEX [--slot HEX ...] [--block TAG] [--output FILE]";
try {
  const args = process.argv.slice(2),
    options = { slots: [] };
  let output;
  if (args.includes("--help")) console.log(usage);
  else {
    for (let i = 0; i < args.length; i++) {
      const key = args[i],
        value = args[++i];
      assert(
        ["--rpc", "--address", "--slot", "--block", "--output"].includes(key) &&
          value &&
          !value.startsWith("--"),
        usage,
      );
      if (key === "--slot") options.slots.push(value);
      else if (key === "--output") output = value;
      else
        options[
          { "--rpc": "rpcUrl", "--address": "address", "--block": "block" }[key]
        ] = value;
    }
    const text = JSON.stringify(await fetchProof(options), null, 2) + "\n";
    if (output) writeFileSync(output, text);
    else process.stdout.write(text);
  }
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
