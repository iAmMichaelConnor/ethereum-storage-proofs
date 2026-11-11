import { resolve, join } from "node:path";
import {
  json,
  pathArg,
  valueArg,
  checkKeys,
  slotArg,
  run,
} from "../tool-runner.mjs";
import { checkRecursiveProofExport } from "../input-preparation/export.mjs";
/** Prove and natively verify a recursive_proof; optionally prove its recursive consumer.
 * slotIndex selects the storageProof entry (required when there are several).
 */
export async function proveRecursiveProof(options) {
  const tools = checkKeys("proveRecursiveProof", options, [
    "profile",
    "input",
    "output",
    "bb",
    "bbSha256",
    "aztecTag",
    "minimum",
    "recursiveCheck",
    "cache",
    "slotIndex",
  ]);
  const {
    profile,
    input,
    output,
    bb,
    bbSha256,
    aztecTag,
    minimum,
    recursiveCheck = false,
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
    "--bb",
    resolve(bb),
  ];
  valueArg(args, "--bb-sha256", bbSha256);
  valueArg(args, "--aztec-tag", aztecTag);
  valueArg(args, "--minimum", minimum);
  pathArg(args, "--cache", cache);
  slotArg(args, slotIndex);
  if (typeof recursiveCheck !== "boolean")
    throw new TypeError("recursiveCheck must be a boolean");
  if (recursiveCheck) args.push("--recursive-check");
  await run("proving/prove.py", args, tools);
  return {
    directory: resolve(output),
    recursive_proofPath: resolve(output, "recursive_proof.json"),
    bundle: checkRecursiveProofExport(
      await json(join(output, "recursive_proof.json")),
    ),
    results: await json(join(output, "results.json")),
  };
}
/** Produce/verify an outer proof linking independent app and user recursive proofs. */
export async function proveLinkedRecursiveProofs(options) {
  const tools = checkKeys("proveLinkedRecursiveProofs", options, [
    "app",
    "user",
    "appVkHash",
    "userVkHash",
    "output",
    "bb",
    "bbSha256",
    "mode",
    "negativeChecks",
  ]);
  const {
    app,
    user,
    appVkHash,
    userVkHash,
    output,
    bb,
    bbSha256,
    mode = "storage",
    negativeChecks = false,
  } = options;
  const args = [
    "--app",
    resolve(app),
    "--user",
    resolve(user),
    "--output",
    resolve(output),
    "--bb",
    resolve(bb),
    "--mode",
    mode,
  ];
  // Key policy is the caller's; a bundle's producer_vk_hash is never used as policy.
  if (typeof appVkHash !== "string" || typeof userVkHash !== "string")
    throw new TypeError(
      "appVkHash and userVkHash (authorised key policy) are required",
    );
  args.push("--app-vk-hash", appVkHash, "--user-vk-hash", userVkHash);
  valueArg(args, "--bb-sha256", bbSha256);
  if (negativeChecks) args.push("--negative-checks");
  await run("proving/link-proofs.py", args, tools);
  return {
    directory: resolve(output),
    proofPath: resolve(output, "proof/proof"),
    verificationKeyPath: resolve(output, "proof/vk"),
    publicInputsPath: resolve(output, "proof/public_inputs"),
    results: await json(join(output, "results.json")),
  };
}
