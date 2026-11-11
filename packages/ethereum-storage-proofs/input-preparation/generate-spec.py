#!/usr/bin/env python3
"""Generate a producer from a validated JSON profile on stdin."""

import argparse, importlib.util, json, subprocess, sys
from pathlib import Path
from profile import generate
from profile_common import ROOT

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("output", type=Path)
a = p.parse_args()
# Reuse the host validator so profile acceptance has one definition.
raw = sys.stdin.read()
check = subprocess.run(
    [
        "node",
        "--input-type=module",
        "-e",
        "import {readFileSync} from 'node:fs'; import {validateProfile} from './input-preparation/profiles.mjs'; validateProfile(JSON.parse(readFileSync(0,'utf8')));",
    ],
    input=raw,
    text=True,
    cwd=ROOT,
)
if check.returncode:
    p.error("Invalid profile specification")
s = json.loads(raw)
try:
    if s["scope"] in ["storage_zero", "account_absent", "l1_zero"]:
        spec = importlib.util.spec_from_file_location(
            "absence_profile", ROOT / "input-preparation/absence-profile.py"
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.generate(
            a.output,
            s["scope"],
            s["depth"],
            s["node_bytes"],
            s["terminal_bytes"],
            s.get("account_depth", 8),
            s.get("account_bytes", 532),
        )
    elif s["scope"] in ["receipt", "event"]:
        spec = importlib.util.spec_from_file_location(
            "receipt_profile", ROOT / "input-preparation/receipt-profile.py"
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.generate(
            a.output,
            s["scope"],
            s["depth"],
            s["node_bytes"],
            s["leaf_bytes"],
            s["max_logs"],
            s.get("data_bytes", 1),
        )
    elif s["scope"] != "batch":
        generate(a.output, s["scope"], s["mode"], s["account"], s["storage"])
    else:
        spec = importlib.util.spec_from_file_location(
            "batch_profile", ROOT / "input-preparation/batch-profile.py"
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        if s.get("layout") == "mixed":
            m.generate_mixed(
                a.output,
                s["slots"],
                s["buckets"],
                s["depth"],
                s.get("parsing") == "shared",
            )
        else:
            m.generate(
                a.output,
                s["slots"],
                s["nodes"],
                s["depth"],
                s["bytes"],
                s.get("parsing") == "shared",
            )
except (ValueError, FileExistsError) as e:
    p.error(str(e))
print(a.output.resolve())
