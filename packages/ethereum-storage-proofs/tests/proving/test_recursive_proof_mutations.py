"""RecursiveProof negative-test generation and key policy; no Noir, bb or proof."""

import ast
import copy
import json
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "proving"))
import prove  # noqa: E402
import honk_proof  # noqa: E402


def leaves(value, path=()):
    if isinstance(value, list):
        for i, item in enumerate(value):
            yield from leaves(item, path + (i,))
    else:
        yield path, value


def differences(a, b):
    result = []
    for component in a:
        old, new = dict(leaves(a[component])), dict(leaves(b[component]))
        result += [(component, p) for p in old if old[p] != new[p]]
    return result


def proof():
    values = [i % 251 for i in range(honk_proof.PROOF_FIELDS)]
    g = honk_proof.GENERATOR
    values[honk_proof.SHPLONK_Q] = honk_proof.encode(honk_proof.add(g, g))
    values[honk_proof.KZG_W] = honk_proof.encode(
        honk_proof.add(honk_proof.add(g, g), g)
    )
    return list(map(str, values))


BATCH = dict(
    storage_root=["1", "2", "3", "4"],
    slot_keys=[[(i * 7 + j) % 256 for j in range(32)] for i in range(4)],
    values=[[(i * 11 + j) % 256 for j in range(32)] for i in range(4)],
)
EVENT = dict(
    receipts_root=["1", "2", "3", "4"],
    transaction_index="5",
    log_index=6,
    emitter=[9] * 20,
    topics=[[i] * 32 for i in range(4)],
    topic_count=2,
    data_hash=["7", "8", "9", "10"],
    data_length=11,
)
RECEIPT = dict(
    receipts_root=["1", "2", "3", "4"],
    transaction_index="5",
    receipt_type=2,
    has_post_state=False,
    status=True,
    post_state=[0] * 32,
    cumulative_gas_used="21000",
)


class LeafMutationTests(unittest.TestCase):
    """Sample every dimension (first, middle, last) and high bits."""

    def check(self, claim):
        mutations = dict(prove.leaf_mutations(claim))
        for name, changed in mutations.items():
            changes = differences(claim, changed)
            self.assertEqual(len(changes), 1, name)
            component, path = changes[0]
            value = dict(leaves(changed[component]))[path]
            if isinstance(value, str):
                self.assertTrue(0 <= int(value) < 1 << 64, name)
            elif isinstance(value, int) and not isinstance(value, bool):
                bits = 32 if component in prove.U32_LEAVES else 8
                if component != "topic_count":
                    self.assertTrue(0 <= value < 1 << bits, name)
        return mutations

    def test_batch_samples_every_dimension_with_high_bits(self):
        mutations = self.check(BATCH)
        touched = {differences(BATCH, m)[0] for m in mutations.values()}
        for component in ["slot_keys", "values"]:
            for i in [0, 2, 3]:
                for j in [0, 16, 31]:
                    self.assertIn((component, (i, j)), touched)
        for component, i, j in [("slot_keys", 3, 31), ("values", 0, 0)]:
            self.assertIn(f"changed-{component}[{i}][{j}]-high", mutations)
            changed = mutations[f"changed-{component}[{i}][{j}]-high"]
            self.assertEqual(changed[component][i][j] ^ BATCH[component][i][j], 0x80)
        self.assertEqual(
            int(mutations["changed-storage_root[3]-high"]["storage_root"][3]),
            4 ^ (1 << 63),
        )

    def test_event_skips_inactive_topics_and_keeps_types(self):
        mutations = self.check(EVENT)
        touched = {differences(EVENT, m)[0] for m in mutations.values()}
        self.assertFalse(
            any(c == "topics" and p[0] >= EVENT["topic_count"] for c, p in touched)
        )
        self.assertIn(("topics", (1, 31)), touched)
        self.assertEqual(
            mutations["changed-log_index-high"]["log_index"], 6 ^ (1 << 31)
        )
        self.assertLessEqual(mutations["changed-topic_count"]["topic_count"], 4)

    def test_receipt_bools_are_negated_once(self):
        mutations = self.check(RECEIPT)
        self.assertEqual(mutations["changed-status-low"]["status"], False)
        self.assertNotIn("changed-status-high", mutations)


class RecursiveMutationTests(unittest.TestCase):
    """Pairing-only substitutions and honest labels."""

    def test_pairing_only_substitutions_require_the_pairing_stage(self):
        outer = dict(
            recursive_proof=dict(verification_key=["0"] * 115, proof=proof()),
            expected=copy.deepcopy(BATCH),
            authorized_vk_hash="7",
        )
        mutations = prove.recursive_mutations(outer, outer["expected"], "7")
        pairing = {n for n, (_, ok) in mutations.items() if ok == {"pairing"}}
        self.assertEqual(
            pairing,
            {
                "substitute-kzg-w-generator",
                "substitute-kzg-w-negated",
                "substitute-kzg-w-doubled",
                "substitute-shplonk-q-generator",
            },
        )
        for name in pairing:
            changed = mutations[name][0]["recursive_proof"]["proof"]
            indices = [
                i
                for i, x in enumerate(changed)
                if x != outer["recursive_proof"]["proof"][i]
            ]
            self.assertTrue(indices and min(indices) >= 450, name)
        self.assertIn("off-curve-kzg-w", mutations)
        self.assertIn("corrupt-sumcheck-scalar", mutations)
        self.assertNotIn("corrupt-proof", mutations)
        self.assertEqual(mutations["wrong-key-hash"][0]["authorized_vk_hash"], "8")
        # Only the off-curve point may stop in the circuit builder.
        for name, (_, accepted) in mutations.items():
            if name != "off-curve-kzg-w":
                self.assertNotIn("circuit construction", accepted, name)

    def test_rejection_stage_does_not_count_builder_asserts_as_cryptographic(self):
        stage = prove.rejection_stage
        self.assertEqual(
            stage(
                "UltraVerifier: verification failed at pairing check\n"
                "Failed to verify the generated proof!"
            ),
            "pairing",
        )
        self.assertEqual(stage("Failed to verify the generated proof!"), "verification")
        self.assertEqual(
            stage("Assertion failed: (remainder_1024.lo == uint512_t(0))"),
            "circuit construction",
        )
        self.assertIsNone(stage("mismatch in some unrelated text"))


class PackagingTests(unittest.TestCase):
    """prove.py must load from an installed copy, outside the repository."""

    def test_prove_loads_from_an_installed_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "node_modules/ethereum-storage-proofs"
            for directory in ["scripts", "input-preparation", "proving"]:
                shutil.copytree(ROOT / directory, package / directory)
            for name in ["toolchain.json", "package.json"]:
                shutil.copy(ROOT / name, package / name)
            result = subprocess.run(
                [sys.executable, package / "proving/prove.py", "--help"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--recursive-check", result.stdout)

    def test_staging_directory_name_is_never_rebound_in_main(self):
        # `stage` is the staging directory for every recursive negative.
        main = next(
            node
            for node in ast.walk(ast.parse((ROOT / "proving/prove.py").read_text()))
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        bindings = [
            node
            for node in ast.walk(main)
            if isinstance(node, ast.Name)
            and node.id == "stage"
            and isinstance(node.ctx, ast.Store)
        ]
        self.assertEqual(len(bindings), 1)


class LinkPolicyTests(unittest.TestCase):
    """The linked proof takes key policy from the caller, not the bundles."""

    def run_link(self, tmp, app_hash, user_hash, *extra):
        bundles = []
        for name, key in [("app", "11"), ("user", "12")]:
            path = Path(tmp) / f"{name}.json"
            path.write_text(
                json.dumps(dict(format_version=2, producer_vk_hash=key, expected={}))
            )
            bundles.append(path)
        args = ["--app", bundles[0], "--user", bundles[1]]
        if app_hash:
            args += ["--app-vk-hash", app_hash]
        if user_hash:
            args += ["--user-vk-hash", user_hash]
        return subprocess.run(
            [
                sys.executable,
                ROOT / "proving/link-proofs.py",
                *args,
                *extra,
                "--bb",
                Path(tmp) / "missing-bb",
                "--output",
                Path(tmp) / "out",
            ],
            capture_output=True,
            text=True,
        )

    def test_policy_is_required_and_must_match_each_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = self.run_link(tmp, None, None)
            self.assertEqual(missing.returncode, 2)
            self.assertIn("--app-vk-hash", missing.stderr)
            wrong = self.run_link(tmp, "11", "13")
            self.assertEqual(wrong.returncode, 2)
            self.assertIn("is not the authorised key", wrong.stderr)
            noncanonical = self.run_link(tmp, "011", "12")
            self.assertIn("canonical", noncanonical.stderr)
            self.assertFalse((Path(tmp) / "out").exists())


if __name__ == "__main__":
    unittest.main()
