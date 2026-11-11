/** Node-only orchestration. Uses pinned local Noir/bb tools through Python 3.11+.
 * Arguments are passed directly to child processes; no shell is invoked.
 * Roots and producer keys are application policy, never authorized by this API.
 */
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";
const root = dirname(fileURLToPath(import.meta.url));
export const json = async (path) => JSON.parse(await readFile(path, "utf8"));
export const pathArg = (args, flag, path) => {
  if (path !== undefined) args.push(flag, resolve(path));
};
export const valueArg = (args, flag, value) => {
  if (value !== undefined) args.push(flag, String(value));
};
const TOOL_KEYS = ["python", "onLog"];
/** Reject unknown or misspelt option keys instead of silently ignoring them. */
export const checkKeys = (name, options, allowed) => {
  if (options === null || typeof options !== "object")
    throw new TypeError(`${name} expects an options object`);
  const known = new Set([...allowed, ...TOOL_KEYS]);
  for (const key of Object.keys(options))
    if (!known.has(key)) throw new TypeError(`Unknown ${name} option: ${key}`);
  return { python: options.python, onLog: options.onLog };
};
export const slotArg = (args, slotIndex) => {
  if (slotIndex === undefined) return;
  if (!Number.isSafeInteger(slotIndex) || slotIndex < 0)
    throw new TypeError("slotIndex must be a nonnegative safe integer");
  args.push("--slot-index", String(slotIndex));
};
export class ToolError extends Error {
  constructor(script, exitCode, stdout, stderr) {
    super(`${script} failed (${exitCode}). ${stderr.trim()}`);
    this.name = "ToolError";
    Object.assign(this, { script, exitCode, stdout, stderr });
  }
}
export function run(
  script,
  args,
  { python = "python3", onLog } = {},
  input = "",
) {
  return new Promise((fulfil, reject) => {
    const child = spawn(python, [join(root, script), ...args], {
      cwd: root,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout = (stdout + text).slice(-1048576);
      onLog?.(text, "stdout");
    });
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      stderr = (stderr + text).slice(-1048576);
      onLog?.(text, "stderr");
    });
    child.once("error", reject);
    child.once("close", (code, signal) =>
      code === 0
        ? fulfil()
        : reject(new ToolError(script, code ?? signal, stdout, stderr)),
    );
    // A missing executable may close stdin before this payload is consumed.
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") reject(error);
    });
    child.stdin.end(input);
  });
}
