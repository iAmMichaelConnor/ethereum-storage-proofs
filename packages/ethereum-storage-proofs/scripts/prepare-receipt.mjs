#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { prepareReceipt, prepareEvent } from "../input-preparation/receipts.mjs";
const [input, profile, output] = process.argv.slice(2);
if (!output)
  throw new Error(
    "Usage: prepare-receipt.mjs input.json profile.json output.json",
  );
const raw = JSON.parse(readFileSync(input, "utf8")),
  p = JSON.parse(readFileSync(profile, "utf8"));
const options = {
  depth: p.depth,
  nodeBytes: p.node_bytes,
  leafBytes: p.leaf_bytes,
  maxLogs: p.max_logs,
};
const prepared =
  p.scope === "event"
    ? await prepareEvent(raw, {
        ...options,
        dataBytes: p.data_bytes,
        logIndex: raw.logIndex ?? 0,
      })
    : await prepareReceipt(raw, options);
writeFileSync(output, JSON.stringify(prepared, null, 2) + "\n");
