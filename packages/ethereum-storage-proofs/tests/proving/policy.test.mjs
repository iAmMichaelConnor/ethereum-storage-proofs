import test from "node:test";
import assert from "node:assert/strict";
import { proveRecursiveProof, proveLinkedRecursiveProofs } from "ethereum-storage-proofs";

test("linked proving requires an explicit key policy", async () => {
  for (const policy of [{}, { appVkHash: "7" }, { userVkHash: "7" }])
    await assert.rejects(
      proveLinkedRecursiveProofs({
        app: "/unused/app.json",
        user: "/unused/user.json",
        output: "/unused/linked",
        bb: "/unused/bb",
        python: "/nonexistent-python-must-not-run",
        ...policy,
      }),
      /appVkHash and userVkHash/,
    );
});

test("proving rejects unknown options before invoking tools", async () => {
  const base = { profile: "/unused", input: "/unused", output: "/unused" };
  await assert.rejects(
    proveRecursiveProof({ ...base, bb: "/unused", recursive_check: true }),
    /Unknown proveRecursiveProof option: recursive_check/,
  );
  await assert.rejects(
    proveLinkedRecursiveProofs({ app: "a", user: "u", negative_checks: true }),
    /Unknown proveLinkedRecursiveProofs option: negative_checks/,
  );
});
