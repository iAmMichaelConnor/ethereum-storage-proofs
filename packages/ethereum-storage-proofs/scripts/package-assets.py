"""Stage the Noir workspace, LICENSE and NOTICE into the package for npm pack.

An installed package has no repository around it, so the producer and consumer
circuits it generates depend on this copy (dist/library/noir) instead.
"""

from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parents[1]

shutil.rmtree(ROOT / "dist", ignore_errors=True)
shutil.copytree(
    REPOSITORY / "noir",
    ROOT / "dist/library/noir",
    ignore=shutil.ignore_patterns("target", "export", "__pycache__"),
)
for name in ["LICENSE", "NOTICE"]:
    shutil.copy2(REPOSITORY / name, ROOT / name)
print("staged", (ROOT / "dist/library/noir").relative_to(ROOT))
