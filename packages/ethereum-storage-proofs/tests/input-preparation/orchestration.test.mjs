import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  autoProfile,
  generateProfile,
  prepareCircuit,
  ToolError,
} from "ethereum-storage-proofs";
const fixture = fileURLToPath(
  new URL("../fixtures/batch-shared-rpc.json", import.meta.url),
);
test("typed host workflow uses literal paths, rejects overwrite, and prepares a real claim", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "storage-sdk-"));
  try {
    const profile = await autoProfile({
      input: fixture,
      scope: "batch",
      output: join(tmp, "automatic"),
    });
    assert.equal(profile.profile.slots, 4);
    const exact = await generateProfile(
      { ...profile.profile, parsing: "shared" },
      join(tmp, "literal $(not-a-command)"),
    );
    const before = await readFile(join(exact.directory, "src/main.nr"), "utf8");
    await assert.rejects(
      generateProfile(profile.profile, exact.directory),
      ToolError,
    );
    assert.equal(
      await readFile(join(exact.directory, "src/main.nr"), "utf8"),
      before,
    );
    const prepared = await prepareCircuit({
      profile: exact.directory,
      input: fixture,
      output: join(tmp, "inputs"),
    });
    assert.equal(prepared.claim.slot_keys.length, 4);
    assert.match(await readFile(prepared.witnessPath, "utf8"), /claim =/);
    assert.equal(prepared.preparation.profile.parsing, "shared");
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
});
test("invalid profile fails before creating a circuit", async () => {
  await assert.rejects(
    generateProfile(
      { version: 1, scope: "batch", slots: 0, nodes: 1, depth: 1, bytes: 135 },
      "/unused",
    ),
  );
});
