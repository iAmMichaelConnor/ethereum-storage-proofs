"""Shared package emission for standalone Noir producer generators.

Generated sources import the focused packages that define each item
(ethereum_proofs, ethereum_keccak, ethereum_types, ethereum_ssz and
ethereum_recursive_proofs), not the ethereum_storage_proofs compatibility facade.
The manifest lists exactly the packages the source imports.
"""

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The repository root holds the Noir workspace (noir/) when this package runs from
# a checkout (packages/ethereum-storage-proofs); an installed copy carries the
# workspace that `npm run build` staged in dist/library.
_CHECKOUT = ROOT.parents[1]
LIBRARY = (
    _CHECKOUT
    if ROOT.parent.name == "packages"
    and (_CHECKOUT / "noir/ethereum_proofs/Nargo.toml").is_file()
    else ROOT / "dist/library"
)

# Paths of the defining modules; templates build their imports from these.
PROOF = "ethereum_proofs::proof"
BATCH = "ethereum_proofs::batch"
ABSENCE = "ethereum_proofs::absence"
EVENTS = "ethereum_proofs::events"
RECEIPTS = "ethereum_proofs::receipts"
TYPES = "ethereum_types"
KECCAK = "ethereum_keccak"
SSZ = "ethereum_ssz"
RECURSIVE_PROOF = "ethereum_recursive_proofs"
RECURSIVE_PROOF_ABSENCE = "ethereum_recursive_proofs::absence"
RECURSIVE_PROOF_RECEIPTS = "ethereum_recursive_proofs::receipts"

PACKAGES = (
    "ethereum_keccak",
    "ethereum_proofs",
    "ethereum_ssz",
    "ethereum_types",
    "ethereum_recursive_proofs",
)
_IMPORT = re.compile(r"\b(" + "|".join(PACKAGES) + r")::")
_FACADE = re.compile(r"\blib::")


def imported_packages(source):
    """Return the focused packages a Noir source imports, sorted by name."""
    if _FACADE.search(source):
        raise ValueError("Source uses the ethereum_storage_proofs facade (lib::)")
    return sorted(set(_IMPORT.findall(source)))


def facade_source(source):
    """Rewrite a focused source to the ethereum_storage_proofs facade (`lib::`).

    Only the compatibility measurements use this: they test the facade on purpose.
    """
    for focused, facade in [
        ("ethereum_proofs::", "lib::"),
        ("ethereum_types::", "lib::types::"),
        ("ethereum_keccak::", "lib::keccak::"),
        ("ethereum_ssz::", "lib::ssz::"),
        ("ethereum_recursive_proofs::", "lib::recursive_proof::"),
    ]:
        source = source.replace(focused, facade)
    return source


def manifest_text(name, source, locate):
    """Emit a bin package manifest; locate(package) gives the dependency path."""
    text = f'[package]\nname = "{name}"\ntype = "bin"\nauthors = []\n[dependencies]\n'
    for package in imported_packages(source):
        text += f"{package} = {{ path = {json.dumps(str(locate(package)))} }}\n"
    return text


def example_comments(spec):
    """Describe the producer and distinguish runtime sizes from compiled capacities."""
    scope = spec["scope"]
    purposes = {
        "account": "Authenticate an account and bind its storage root in a recursive_proof statement.",
        "storage": "Authenticate a storage value and return its recursive_proof statement.",
        "threshold": "Authenticate a storage value above the claimed minimum and bind the threshold statement.",
        "l1": "Authenticate an account and its storage value under one state root.",
        "storage_zero": "Authenticate a zero or absent storage slot and bind its recursive_proof statement.",
        "account_absent": "Authenticate an absent account and bind its recursive_proof statement.",
        "l1_zero": "Authenticate an account and a zero or absent slot under its storage root.",
        "batch": "Authenticate an ordered batch of storage values using a shared node table.",
        "receipt": "Authenticate a receipt summary and bind its recursive_proof statement.",
        "event": "Authenticate a receipt log and bind its emitter, topics and data hash.",
    }
    lines = [purposes[scope]]
    if scope in ("account", "storage", "threshold", "l1"):
        counts = []
        for path in ("account", "storage"):
            if path == "account" and scope in ("storage", "threshold"):
                continue
            if path == "storage" and scope == "account":
                continue
            counts.append(f"{path} <= {len(spec[path])}")
        lines.append(
            "Internal-node maxima: "
            + "; ".join(counts)
            + "; *_count is actual use; byte limits: profile.json."
        )
        if spec["mode"] == "hashed" and scope != "account":
            lines.append(
                "Hash-only storage paths; choose general mode for embedded children."
            )
    elif scope == "batch":
        lines.append(
            f"Exactly {spec['slots']} slots; each path uses at most {spec['depth']} internal nodes."
        )
        if spec.get("layout") == "mixed":
            lines.append(
                "Shared node bucket capacities and byte sizes are fixed in profile.json."
            )
        else:
            lines.append(
                f"node_count <= {spec['nodes']}; each encoded node fits {spec['bytes']} bytes."
            )
    elif scope in ("storage_zero", "account_absent", "l1_zero"):
        lines.append(
            f"count <= {spec['depth']} internal nodes; node/terminal byte limits: profile.json."
        )
        if scope == "l1_zero":
            lines.append(
                f"The independent account path allows at most {spec['account_depth']} internal nodes."
            )
        lines.append(
            "terminal_length is actual encoded bytes, not terminal buffer capacity."
        )
    else:
        lines.append(
            f"count <= {spec['depth']} internal nodes; encoded leaf bytes <= {spec['leaf_bytes']}; logs <= {spec['max_logs']}."
        )
        if scope == "event":
            lines.append(
                f"Event data uses at most {spec['data_bytes']} bytes; lengths carry actual encoded sizes."
            )
    preparation = (
        "input-preparation"
        if LIBRARY == ROOT / "dist/library"
        else (ROOT / "input-preparation").relative_to(LIBRARY).as_posix()
    )
    lines.append(
        f"Compile several profiles with {preparation}/generate-spec.py; supported bounds: {preparation}/profiles.mjs."
    )
    return "".join("// " + line + "\n" for line in lines)


def write_profile(folder, spec, source):
    """Write the same library dependencies and package shape for every producer."""
    folder = Path(folder).resolve()
    folder.mkdir(parents=True, exist_ok=False)
    (folder / "src").mkdir()
    (folder / "profile.json").write_text(json.dumps(spec, indent=2) + "\n")
    (folder / "Nargo.toml").write_text(
        manifest_text(
            "storage_producer",
            source,
            lambda package: os.path.relpath(LIBRARY / "noir" / package, folder),
        )
    )
    (folder / "src/main.nr").write_text(example_comments(spec) + source)
    return spec
