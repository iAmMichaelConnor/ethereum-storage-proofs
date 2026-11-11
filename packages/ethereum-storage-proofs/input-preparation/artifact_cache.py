"""Optional local compiled-artifact cache. Never caches witnesses, proofs or policy.

The lookup covers every producer/library source and manifest, the compiler and
backend binaries, pins, and all transitive dependency sources and manifests.
Each hit rechecks dependency files and artifact integrity. This is a user-owned
build cache, not an authentication mechanism for untrusted artifacts.
"""

import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import tomllib
from urllib.parse import urlparse


import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tree(path):
    files = [path / "Nargo.toml", *sorted((path / "src").rglob("*.nr"))]
    return {str(f.resolve()): digest(f.read_bytes()) for f in files}


def dependencies(package, seen=None):
    """Resolve the pinned compiler's local/tagged dependency layout, fail closed."""
    seen = set() if seen is None else seen
    result = {}
    manifest = tomllib.loads((package / "Nargo.toml").read_text())
    for dep in manifest.get("dependencies", {}).values():
        if "path" in dep:
            location = (package / dep["path"]).resolve()
        elif "git" in dep and "tag" in dep:
            url = urlparse(dep["git"])
            location = (
                Path.home()
                / "nargo"
                / str(url.hostname)
                / url.path.strip("/")
                / dep["tag"]
            )
            location = location / dep.get("directory", "")
        else:
            raise ValueError("Cache requires local or pinned tagged dependencies")
        location = location.resolve()
        if location in seen:
            continue
        seen.add(location)
        result[str(location)] = tree(location)
        result.update(dependencies(location, seen))
    return result


def compile_artifact(stage, out, cache=None, bb=None):
    from tool_runner import LIBRARY, NARGO, TOOLCHAIN, run, sha, save

    if cache is None:
        run([NARGO, "compile", "--deny-warnings"], stage, out, "compile")
        return
    cache = Path(cache).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    sources = {
        "library/" + str(f.relative_to(LIBRARY)): sha(f)
        for f in sorted((LIBRARY / "noir").rglob("*.nr"))
    }
    sources.update(
        {
            "producer/" + str(f.relative_to(stage)): sha(f)
            for f in sorted((stage / "src").rglob("*.nr"))
        }
    )
    sources["library_manifest"] = sha(LIBRARY / "noir/Nargo.toml")
    sources["producer_manifest"] = sha(stage / "Nargo.toml")
    key = digest(
        json.dumps(
            dict(
                version=1,
                sources=sources,
                compiler=sha(NARGO),
                backend=sha(bb) if bb else None,
                pins=sha(TOOLCHAIN),
            ),
            sort_keys=True,
        ).encode()
    )
    entry = cache / key
    with (cache / (key + ".lock")).open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        hit = False
        if (entry / "manifest.json").exists():
            try:
                meta = json.loads((entry / "manifest.json").read_text())
                hit = sha(entry / "artifact.json") == meta["artifact_sha256"] and all(
                    tree(Path(p)) == files for p, files in meta["dependencies"].items()
                )
                if hit:
                    (stage / "target").mkdir(exist_ok=True)
                    shutil.copyfile(
                        entry / "artifact.json", stage / "target" / meta["name"]
                    )
            except (OSError, ValueError, KeyError, TypeError):
                hit = False
        if not hit:
            run([NARGO, "compile", "--deny-warnings"], stage, out, "compile")
            artifacts = list((stage / "target").glob("*.json"))
            if len(artifacts) != 1:
                raise ValueError("Expected one compiled producer")
            artifact = artifacts[0]
            # Walk manifests, including dependencies optimized out of file_map.
            # Never fingerprint or store Prover.toml / private witness contents.
            dependency_sources = dependencies(stage)
            meta = dict(
                name=artifact.name,
                artifact_sha256=sha(artifact),
                dependencies=dependency_sources,
            )
            with tempfile.TemporaryDirectory(dir=cache, prefix=".write-") as tmp:
                temp = Path(tmp)
                shutil.copyfile(artifact, temp / "artifact.json")
                save(temp / "manifest.json", meta)
                if entry.exists():
                    shutil.rmtree(entry)
                temp.rename(entry)
        save(
            out / "cache.json",
            dict(
                version=1,
                key=key,
                hit=hit,
                scope="Compiled artifact only; witnesses and proofs are always regenerated",
            ),
        )
