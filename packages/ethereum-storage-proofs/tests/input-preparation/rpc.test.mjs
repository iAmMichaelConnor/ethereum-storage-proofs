import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  fetchProof,
  inspectProof,
  EMPTY_TRIE_ROOT,
} from "../../input-preparation/index.mjs";
const fixture = (name) =>
  JSON.parse(
    readFileSync(new URL(`../fixtures/${name}.json`, import.meta.url)),
  );
const saved = fixture("batch-shared-rpc"),
  hash = `0x${"ab".repeat(32)}`;
function mock(input = saved, mutate = () => {}) {
  const calls = [];
  const fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    calls.push(request);
    let result =
      request.method === "eth_getProof"
        ? structuredClone(input.proof)
        : { number: "0x123", hash, stateRoot: input.stateRoot };
    result = mutate(result, request, calls.length) ?? result;
    return {
      ok: true,
      json: async () => ({ jsonrpc: "2.0", id: request.id, result }),
    };
  };
  return { calls, fetch };
}
const options = (input, fetch) => ({
  rpcUrl: "https://example.invalid/API_SECRET",
  address: input.proof.address,
  slots: input.proof.storageProof?.map((p) => p.key) ?? [],
  fetch,
});
test("pins multiple slots to one block and shares the account proof", async () => {
  const { fetch, calls } = mock(saved, (p, r) => {
    if (r.method === "eth_getProof") p.storageProof.reverse();
  });
  const out = await fetchProof(options(saved, fetch));
  assert.deepEqual(
    calls.map((r) => r.method),
    ["eth_getBlockByNumber", "eth_getProof", "eth_getBlockByNumber"],
  );
  assert.deepEqual(calls[0].params, ["finalized", false]);
  assert.equal(calls[1].params[2], "0x123");
  assert.deepEqual(calls[2].params, ["0x123", false]);
  assert.deepEqual(out.proof.accountProof, saved.proof.accountProof);
  assert.deepEqual(
    out.proof.storageProof.map((p) => BigInt(p.key)),
    saved.proof.storageProof.map((p) => BigInt(p.key)),
  );
  assert.deepEqual(out.block, { number: "0x123", hash });
  assert(!JSON.stringify(out).includes("API_SECRET"));
});
test("account-only requests and explicit quantity normalization", async () => {
  const input = structuredClone(saved);
  input.proof.storageProof = [];
  const { fetch, calls } = mock(input);
  const out = await fetchProof({ ...options(input, fetch), block: "0x0123" });
  assert.equal(calls[0].params[0], "0x123");
  assert.deepEqual(out.proof.storageProof, []);
});
test("preserves raw embedded-child RLP", async () => {
  const input = fixture("batch-inline-rpc"),
    { fetch } = mock(input);
  const out = await fetchProof(options(input, fetch));
  assert(
    (await inspectProof(out, { scope: "batch" })).storage.some(
      (p) => p.hasEmbedded,
    ),
  );
  assert.deepEqual(
    out.proof.storageProof.map((p) => p.proof),
    input.proof.storageProof.map((p) => p.proof),
  );
});
for (const [name, mutate] of [
  [
    "address",
    (p) => {
      p.address = `0x${"00".repeat(20)}`;
    },
  ],
  [
    "slot key",
    (p) => {
      p.storageProof[0].key = "0xffff";
    },
  ],
  [
    "slot count",
    (p) => {
      p.storageProof.pop();
    },
  ],
  [
    "storage value",
    (p) => {
      p.storageProof[0].value = "0x12345";
    },
  ],
  [
    "account value",
    (p) => {
      p.balance = "0x12345";
    },
  ],
])
  test(`rejects wrong ${name}`, async () => {
    const { fetch } = mock(saved, (p, r) => {
      if (r.method === "eth_getProof") mutate(p);
    });
    await assert.rejects(fetchProof(options(saved, fetch)));
  });
for (const field of ["number", "hash", "stateRoot"])
  test(`rejects block ${field} changing during fetch`, async () => {
    const { fetch } = mock(saved, (p, _r, count) => {
      if (count === 3)
        p[field] = field === "number" ? "0x124" : `0x${"cd".repeat(32)}`;
    });
    await assert.rejects(fetchProof(options(saved, fetch)), /Block changed/);
  });
test("rejects wrong proof/root pairing despite matching block checks", async () => {
  const input = structuredClone(saved);
  input.stateRoot = `0x${"cd".repeat(32)}`;
  const { fetch } = mock(input);
  await assert.rejects(
    fetchProof(options(input, fetch)),
    /local trie validation/,
  );
});
test("rejects a different explicitly requested height", async () => {
  const { fetch } = mock();
  await assert.rejects(
    fetchProof({ ...options(saved, fetch), block: "0x124" }),
    /different block number/,
  );
});
test("accepts independently saved zero-storage and account-absence paths", async () => {
  const cases = fixture("absence/cases");
  for (const name of ["empty", "leaf", "account-empty", "account-leaf"]) {
    const input = structuredClone(cases.find((p) => p.name === name).input);
    if (name.startsWith("account-"))
      Object.assign(input.proof, {
        nonce: "0x0",
        balance: "0x0",
        storageHash: EMPTY_TRIE_ROOT,
        codeHash:
          "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        storageProof: [],
      });
    const { fetch } = mock(input);
    assert.equal(
      (await fetchProof(options(input, fetch))).stateRoot,
      input.stateRoot,
    );
  }
});
test("sanitizes transport, HTTP, provider and JSON errors", async () => {
  const secret = "https://user:password@example.invalid/?key=API_SECRET";
  for (const fetch of [
    async () => {
      throw new Error(secret);
    },
    async () => ({ ok: false, json: async () => ({ error: secret }) }),
    async (_url, init) => ({
      ok: true,
      json: async () => ({
        jsonrpc: "2.0",
        id: JSON.parse(init.body).id,
        error: { message: secret, data: secret },
      }),
    }),
    async () => ({
      ok: true,
      json: async () => {
        throw new Error(secret);
      },
    }),
  ])
    await assert.rejects(
      fetchProof({ ...options(saved, fetch), rpcUrl: secret }),
      (error) => {
        assert.match(error.message, /^RPC (transport|response) failed/);
        assert(!/password|API_SECRET|example.invalid/.test(error.message));
        return true;
      },
    );
});
test("rejects pending, malformed keys and unknown options before requests", async () => {
  let calls = 0;
  const fetch = async () => {
    calls++;
    throw new Error();
  };
  for (const extra of [
    { block: "pending" },
    { block: "0xno" },
    { slot: "0x1" },
    { slots: ["-1"] },
    { address: "0x12" },
  ])
    await assert.rejects(fetchProof({ ...options(saved, fetch), ...extra }));
  assert.equal(calls, 0);
});

test("CLI exposes fetch and conversion without executing tools", async () => {
  const { spawnSync } = await import("node:child_process");
  for (const command of ["fetch", "convert"]) {
    const result = spawnSync(
      "python3",
      ["bin/storage-proofs", command, "--help"],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.match(
      result.stdout,
      command === "fetch" ? /--rpc URL/ : /--profile/,
    );
  }
});
test("inspection reports depths, capacities, embedded children and exact profile fit", async () => {
  const { spawnSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const directory = mkdtempSync(join(tmpdir(), "rpc-inspection-"));
  try {
    const profile = join(directory, "profile.json");
    writeFileSync(
      profile,
      JSON.stringify({
        version: 1,
        scope: "storage",
        mode: "hashed",
        account: [],
        storage: Array(64).fill(532),
      }),
    );
    const result = spawnSync(
      process.execPath,
      [
        "scripts/inspect-proof.mjs",
        "tests/fixtures/batch-inline-rpc.json",
        "storage",
        "--slot-index",
        "0",
        "--profile",
        profile,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(
      report.depths.storage[0],
      report.inspection.storage[0].lengths.length,
    );
    assert(report.inspection.storage[0].hasEmbedded);
    assert(
      report.recommended.storage.every((n) => [135, 271, 407, 532].includes(n)),
    );
    assert.equal(report.profileFit.fits, false);
    assert.match(report.profileFit.reason, /embedded/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("fetch CLI writes normalized JSON through the same mocked transport", async () => {
  const { spawnSync } = await import("node:child_process");
  const { mkdtempSync, writeFileSync, readFileSync, rmSync } = await import(
    "node:fs"
  );
  const { tmpdir } = await import("node:os");
  const { join, resolve } = await import("node:path");
  const directory = mkdtempSync(join(tmpdir(), "rpc-cli-"));
  try {
    const preload = join(directory, "mock.mjs"),
      output = join(directory, "proof.json");
    writeFileSync(
      preload,
      `import {readFileSync} from 'node:fs';
const input=JSON.parse(readFileSync(${JSON.stringify(resolve("tests/fixtures/batch-shared-rpc.json"))},'utf8'));
globalThis.fetch=async(_url,init)=>{const r=JSON.parse(init.body);return {ok:true,json:async()=>({jsonrpc:'2.0',id:r.id,result:r.method==='eth_getProof'?input.proof:{number:'0x123',hash:'${hash}',stateRoot:input.stateRoot}})}};`,
    );
    const args = [
      "bin/storage-proofs",
      "fetch",
      "--rpc",
      "https://example.invalid/?secret=DEMO",
      "--address",
      saved.proof.address,
      ...saved.proof.storageProof.flatMap((p) => ["--slot", p.key]),
      "--output",
      output,
    ];
    const result = spawnSync("python3", args, {
      encoding: "utf8",
      env: { ...process.env, NODE_OPTIONS: `--import=${preload}` },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "");
    const normalized = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(normalized.stateRoot, saved.stateRoot);
    assert.equal(normalized.proof.storageProof.length, 4);
    assert(!JSON.stringify(normalized).includes("DEMO"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("convert exports the exact selected-profile witness as JSON and TOML", async () => {
  const { spawnSync } = await import("node:child_process");
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { generateProfile, inspectProof, recommendProfile } = await import(
    "../../input-preparation/index.mjs"
  );
  const directory = mkdtempSync(join(tmpdir(), "rpc-convert-"));
  try {
    const inspection = await inspectProof(saved, { scope: "batch" });
    const profile = await generateProfile(
      recommendProfile(inspection),
      join(directory, "profile"),
    );
    const output = join(directory, "witness");
    const converted = spawnSync(
      "python3",
      [
        "bin/storage-proofs",
        "convert",
        "--profile",
        profile.directory,
        "--input",
        "tests/fixtures/batch-shared-rpc.json",
        "--output",
        output,
      ],
      { encoding: "utf8" },
    );
    assert.equal(converted.status, 0, converted.stderr);
    const witness = JSON.parse(readFileSync(join(output, "witness.json")));
    const parsed = spawnSync(
      "python3",
      [
        "-c",
        "import json,sys,tomllib; print(json.dumps(tomllib.load(open(sys.argv[1], 'rb'))))",
        join(output, "ProducerProver.toml"),
      ],
      { encoding: "utf8" },
    );
    assert.equal(parsed.status, 0, parsed.stderr);
    // prove.literal represents every scalar except bool as a TOML string.
    const tomlValues = (value) =>
      Array.isArray(value)
        ? value.map(tomlValues)
        : value && typeof value === "object"
          ? Object.fromEntries(
              Object.entries(value).map(([k, v]) => [k, tomlValues(v)]),
            )
          : typeof value === "boolean"
            ? value
            : String(value);
    assert.deepEqual(JSON.parse(parsed.stdout), tomlValues(witness));
    assert.equal(witness.claim.slot_keys.length, 4);
    assert.equal(witness.claim.values.length, 4);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("timeout accepts the timer boundary and rejects overflow before requests", async () => {
  const { fetch, calls } = mock();
  await fetchProof({ ...options(saved, fetch), timeoutMs: 0x7fffffff });
  assert.equal(calls.length, 3);
  for (const timeoutMs of [
    0,
    -1,
    1.5,
    0x80000000,
    0xffffffff,
    Number.MAX_SAFE_INTEGER,
  ]) {
    await assert.rejects(
      fetchProof({ ...options(saved, fetch), timeoutMs }),
      /Invalid RPC timeout/,
    );
  }
  assert.equal(calls.length, 3);
});

test("malformed storage entries fail with a stable validation error", async () => {
  for (const entry of [null, [], "https://example.invalid/DEMO_SECRET"]) {
    const { fetch } = mock(saved, (p, r) => {
      if (r.method === "eth_getProof") p.storageProof[0] = entry;
    });
    await assert.rejects(fetchProof(options(saved, fetch)), (error) => {
      assert.equal(error.message, "Invalid storage proof entry");
      return true;
    });
  }
});
