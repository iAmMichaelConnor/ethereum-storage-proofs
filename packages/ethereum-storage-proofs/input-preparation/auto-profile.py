#!/usr/bin/env python3
"""Generate a fitting producer from validated proof shapes or an explicit catalogue."""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
from profile import generate
from profile_common import ROOT


def auto_profile(
    input_path,
    output,
    scope="l1",
    catalogue=None,
    slot_index=None,
    extra_depth=None,
    full_width=False,
):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Choose a fresh output directory")
    command = [
        "node",
        ROOT / "scripts/inspect-proof.mjs",
        Path(input_path).resolve(),
        scope,
    ]
    if catalogue:
        if extra_depth is not None or full_width:
            # A catalogue entry is chosen by fit; headroom would be silently ignored.
            raise ValueError(
                "Headroom options apply to a recommended profile, not --catalogue"
            )
        command.append(Path(catalogue).resolve())
    if slot_index is not None:
        command += ["--slot-index", str(slot_index)]
    if extra_depth is not None:
        command += ["--extra-depth", str(extra_depth)]
    if full_width:
        command.append("--full-width")
    report = json.loads(subprocess.check_output(command, text=True))
    spec = report.get("selected", {}).get("profile", report["recommended"])
    if scope == "batch":
        module_spec = importlib.util.spec_from_file_location(
            "batch_profile", ROOT / "input-preparation/batch-profile.py"
        )
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        if spec.get("layout") == "mixed":
            module.generate_mixed(
                output,
                spec["slots"],
                spec["buckets"],
                spec["depth"],
                spec.get("parsing") == "shared",
            )
        else:
            module.generate(
                output,
                spec["slots"],
                spec["nodes"],
                spec["depth"],
                spec["bytes"],
                spec.get("parsing") == "shared",
            )
    else:
        generate(output, spec["scope"], spec["mode"], spec["account"], spec["storage"])
    (output / "selection.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument(
        "--scope",
        choices=["l1", "account", "storage", "threshold", "batch"],
        default="l1",
    )
    p.add_argument("--catalogue", type=Path)
    p.add_argument(
        "--slot-index",
        type=int,
        help="storageProof entry for single-slot scopes; required if there are several",
    )
    p.add_argument(
        "--extra-depth",
        type=int,
        help="Append this many 532-byte positions to each recommended path",
    )
    p.add_argument(
        "--full-width",
        action="store_true",
        help="Make every recommended position 532 bytes (fits any branch)",
    )
    a = p.parse_args()
    for name in ["slot_index", "extra_depth"]:
        if getattr(a, name) is not None and getattr(a, name) < 0:
            p.error(f"--{name.replace('_', '-')} must be nonnegative")
    try:
        auto_profile(
            a.input,
            a.output,
            a.scope,
            a.catalogue,
            a.slot_index,
            a.extra_depth,
            a.full_width,
        )
        print(a.output.resolve())
    except (ValueError, subprocess.CalledProcessError) as error:
        p.error(str(error))
