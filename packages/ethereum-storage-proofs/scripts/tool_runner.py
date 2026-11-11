"""Shared process, serialization and pinned-tool helpers for this library's commands."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "input-preparation"))
from profile_common import LIBRARY, manifest_text

# The pinned compiler: NARGO_BIN, else the copy scripts/bootstrap-noir.sh installs.
NARGO = Path(os.environ.get("NARGO_BIN", str(ROOT / ".tools/noir/nargo")))
TOOLCHAIN = ROOT / "toolchain.json"
MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def literal(value):
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(literal(x) for x in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(k + " = " + literal(v) for k, v in value.items()) + "}"
    return json.dumps(str(value))


def write_witness(path, values):
    path.write_text("".join(f"{k} = {literal(v)}\n" for k, v in values.items()))


def gate_report(path):
    text = path.read_text()
    return json.JSONDecoder().raw_decode(text[text.index("{") :])[0]


def fields(path, count):
    data = path.read_bytes()
    if len(data) != count * 32:
        raise ValueError(f"{path}: expected {count} fields, got {len(data)} bytes")
    result = [int.from_bytes(data[i : i + 32], "big") for i in range(0, len(data), 32)]
    if any(x >= MODULUS for x in result):
        raise ValueError("Noncanonical field serialization")
    return list(map(str, result))


def run(cmd, cwd, out, label, negative=False):
    start = time.monotonic()
    env = dict(os.environ)
    with (out / (label + ".log")).open("w") as log:
        result = subprocess.run(
            list(map(str, cmd)), cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT
        )
    print(
        f"{label}: exit {result.returncode}, {time.monotonic() - start:.2f}s",
        flush=True,
    )
    if (result.returncode == 0) == negative:
        log = out / (label + ".log")
        tail = "\n".join(log.read_text(errors="replace").splitlines()[-5:])
        raise RuntimeError(f"Unexpected result: see {log}\n{tail}")
    return dict(exit_code=result.returncode, seconds=round(time.monotonic() - start, 3))


def manifest(path, name):
    """Write the manifest for the staged package; src/ already holds its sources."""
    source = "".join(f.read_text() for f in sorted((path / "src").rglob("*.nr")))
    (path / "Nargo.toml").write_text(
        manifest_text(name, source, lambda package: LIBRARY / "noir" / package)
    )


def noir_sources():
    return sorted((LIBRARY / "noir").glob("*/src/**/*.nr"))


def source_hashes():
    return {
        str(p.relative_to(LIBRARY)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in noir_sources()
    }
