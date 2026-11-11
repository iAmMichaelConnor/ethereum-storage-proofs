#!/usr/bin/env node
// Compatibility CLI adapter; reusable implementation lives in packages/ethereum-storage-proofs/input-preparation/.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { prepare, prepareAccount, prepareStorage } from "../input-preparation/prepare.mjs";
export * from "../input-preparation/prepare.mjs";
if (
  process.argv[1] &&
  import.meta.url === new URL(process.argv[1], "file:").href
) {
  try {
    const [input, output, ...rawArgs] = process.argv.slice(2);
    const accountOnly = rawArgs.includes("--account-only"),
      storageOnly = rawArgs.includes("--storage-only");
    assert(!(accountOnly && storageOnly), "Choose one scope");
    const args = rawArgs.filter(
      (x) => x !== "--account-only" && x !== "--storage-only",
    );
    assert(
      input && output,
      "Usage: node packages/ethereum-storage-proofs/scripts/prepare-proof.mjs input.json output.json [accountDepth accountBytes storageDepth storageBytes slotIndex]",
    );
    const names = [
      "accountDepth",
      "accountBytes",
      "storageDepth",
      "storageBytes",
      "slotIndex",
    ];
    const opts = Object.fromEntries(
      args.map((x, i) => {
        const n = Number(x);
        assert(Number.isSafeInteger(n) && n >= 0);
        return [names[i], n];
      }),
    );
    writeFileSync(
      output,
      JSON.stringify(
        await (
          accountOnly ? prepareAccount : storageOnly ? prepareStorage : prepare
        )(JSON.parse(readFileSync(input, "utf8")), opts),
        null,
        2,
      ) + "\n",
    );
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}
