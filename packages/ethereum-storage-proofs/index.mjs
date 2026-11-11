/** Public API: input preparation and explicit proof generation. */
export * from "./input-preparation/index.mjs";
export { ToolError } from "./tool-runner.mjs";
export { proveRecursiveProof, proveLinkedRecursiveProofs } from "./proving/recursive-proofs.mjs";
