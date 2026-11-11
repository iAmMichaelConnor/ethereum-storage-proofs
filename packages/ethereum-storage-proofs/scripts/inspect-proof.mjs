#!/usr/bin/env node
// Compatibility CLI adapter; reusable implementation lives in packages/ethereum-storage-proofs/input-preparation/.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import {
  inspectProof,
  recommendProfile,
  selectProfile,
  validateProfile,
  profileMisfit,
} from "../input-preparation/profiles.mjs";
export * from "../input-preparation/profiles.mjs";
if (
  process.argv[1] &&
  import.meta.url === new URL(process.argv[1], "file:").href
) {
  try {
    const usage =
      "Usage: inspect-proof.mjs input.json [scope] [catalogue.json] [--slot-index N] [--extra-depth N] [--full-width] [--profile profile.json]";
    const argv = process.argv.slice(2),
      positional = [],
      flags = {};
    for (let i = 0; i < argv.length; i++) {
      if (argv[i] === "--full-width") flags.fullWidth = true;
      else if (argv[i] === "--profile") {
        flags.profile = argv[++i];
        assert(flags.profile && !flags.profile.startsWith("--"), usage);
      } else if (argv[i] === "--slot-index" || argv[i] === "--extra-depth") {
        const n = Number(argv[++i]);
        assert(Number.isSafeInteger(n) && n >= 0, usage);
        flags[argv[i - 1] === "--slot-index" ? "slotIndex" : "extraDepth"] = n;
      } else {
        assert(!argv[i].startsWith("--"), usage);
        positional.push(argv[i]);
      }
    }
    const [path, scope = "l1", cataloguePath] = positional;
    assert(path && positional.length <= 3, usage);
    const inspection = await inspectProof(
      JSON.parse(readFileSync(path, "utf8")),
      { scope, slotIndex: flags.slotIndex },
    );
    const candidate = flags.profile
      ? validateProfile(JSON.parse(readFileSync(flags.profile, "utf8")))
      : undefined;
    const reason = candidate ? profileMisfit(inspection, candidate) : undefined;
    console.log(
      JSON.stringify(
        {
          inspection,
          depths: {
            account: inspection.account.lengths.length,
            storage: inspection.storage.map((path) => path.lengths.length),
          },
          ...(candidate
            ? { profileFit: { fits: reason === null, reason } }
            : {}),
          ...(flags.slotIndex === undefined
            ? {}
            : { slotIndex: flags.slotIndex }),
          recommended: recommendProfile(inspection, {
            extraDepth: flags.extraDepth,
            fullWidth: flags.fullWidth,
          }),
          ...(cataloguePath
            ? {
                selected: selectProfile(
                  inspection,
                  JSON.parse(readFileSync(cataloguePath, "utf8")),
                ),
              }
            : {}),
          policy:
            "Profile selection does not authenticate roots or authorize producer keys",
        },
        null,
        2,
      ),
    );
  } catch (e) {
    console.error(e.message);
    process.exitCode = 1;
  }
}
