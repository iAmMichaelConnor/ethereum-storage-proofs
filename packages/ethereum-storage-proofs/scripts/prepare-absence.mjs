#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import {
  prepareStorageZero,
  prepareAccountAbsent,
  prepareL1Zero,
} from "../input-preparation/absence.mjs";
import { validateProfile } from "../input-preparation/profiles.mjs";
const [input, profile, output, slot] = process.argv.slice(2),
  p = validateProfile(JSON.parse(await readFile(profile, "utf8")));
// Optional storageProof entry; required when the input holds several entries.
const slotIndex = slot === undefined ? undefined : Number(slot);
if (
  slotIndex !== undefined &&
  !(Number.isSafeInteger(slotIndex) && slotIndex >= 0)
)
  throw new Error("Invalid slot index");
const fn = {
  storage_zero: prepareStorageZero,
  account_absent: prepareAccountAbsent,
  l1_zero: prepareL1Zero,
}[p.scope];
if (!fn) throw new Error("Expected absence profile");
const result = await fn(JSON.parse(await readFile(input, "utf8")), {
  depth: p.depth,
  nodeBytes: p.node_bytes,
  terminalBytes: p.terminal_bytes,
  accountDepth: p.account_depth,
  accountBytes: p.account_bytes,
  ...(p.scope === "account_absent" ? {} : { slotIndex }),
});
await writeFile(output, JSON.stringify(result, null, 2) + "\n");
