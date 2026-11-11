import { resolve, join } from "node:path";
import {
  json,
  pathArg,
  valueArg,
  checkKeys,
  slotArg,
  run,
} from "../tool-runner.mjs";
import { validateProfile } from "./profiles.mjs";
const profileResult = async (directory) => ({
  directory: resolve(directory),
  profile: validateProfile(await json(join(directory, "profile.json"))),
});
/** Generate an exact profile; existing output directories are rejected. */
export async function generateProfile(profile, output, options = {}) {
  const tools = checkKeys("generateProfile", options, []);
  validateProfile(profile);
  await run(
    "input-preparation/generate-spec.py",
    [resolve(output)],
    tools,
    JSON.stringify(profile),
  );
  return profileResult(output);
}
/** Independently validate RPC paths and generate a fitting profile.
 * slotIndex selects the storageProof entry (required when there are several).
 * extraDepth and fullWidth add headroom to a recommended (not catalogue) profile.
 */
export async function autoProfile(options) {
  const tools = checkKeys("autoProfile", options, [
    "input",
    "output",
    "scope",
    "catalogue",
    "slotIndex",
    "extraDepth",
    "fullWidth",
  ]);
  const {
    input,
    output,
    scope = "l1",
    catalogue,
    slotIndex,
    extraDepth,
    fullWidth = false,
  } = options;
  const args = [
    "--input",
    resolve(input),
    "--output",
    resolve(output),
    "--scope",
    scope,
  ];
  pathArg(args, "--catalogue", catalogue);
  slotArg(args, slotIndex);
  if (extraDepth !== undefined) {
    if (!Number.isSafeInteger(extraDepth) || extraDepth < 0)
      throw new TypeError("extraDepth must be a nonnegative safe integer");
    args.push("--extra-depth", String(extraDepth));
  }
  if (typeof fullWidth !== "boolean")
    throw new TypeError("fullWidth must be a boolean");
  if (fullWidth) args.push("--full-width");
  await run("input-preparation/auto-profile.py", args, tools);
  return {
    ...(await profileResult(output)),
    selection: await json(join(output, "selection.json")),
  };
}
/** Prepare hints/inputs; execute=true also solves the Noir witness. No proof is made.
 * slotIndex selects the storageProof entry (required when there are several).
 */
export async function prepareCircuit(options) {
  const tools = checkKeys("prepareCircuit", options, [
    "profile",
    "input",
    "output",
    "minimum",
    "execute",
    "cache",
    "slotIndex",
  ]);
  const {
    profile,
    input,
    output,
    minimum,
    execute = false,
    cache,
    slotIndex,
  } = options;
  const args = [
    "--profile",
    resolve(profile),
    "--input",
    resolve(input),
    "--output",
    resolve(output),
  ];
  valueArg(args, "--minimum", minimum);
  pathArg(args, "--cache", cache);
  slotArg(args, slotIndex);
  if (typeof execute !== "boolean")
    throw new TypeError("execute must be a boolean");
  if (execute) args.push("--execute");
  await run("input-preparation/prepare-circuit.py", args, tools);
  return {
    directory: resolve(output),
    witnessPath: resolve(output, "ProducerProver.toml"),
    claim: await json(join(output, "claim.json")),
    preparation: await json(join(output, "preparation.json")),
  };
}
