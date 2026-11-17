"""Stamp an installer-built wheel with its source identity, without importing it.

Run from the trusted installer using ``python3 -I ... /path/to/repository``.
A dirty checkout or source archive with no verified commit gets a null revision,
so it cannot falsely claim to contain every change in a published commit.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


def source_version(root: Path) -> str:
    package = (root / "panel" / "__init__.py").read_text(encoding="utf-8")
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    package_match = re.search(r'^__version__\s*=\s*["\'](\d+\.\d+\.\d+)["\']\s*$', package, re.M)
    project_match = re.search(r'^version\s*=\s*["\'](\d+\.\d+\.\d+)["\']\s*$', project, re.M)
    if not package_match or not project_match or package_match[1] != project_match[1]:
        raise ValueError("package and project must declare the same major.minor.patch version")
    return package_match[1]


def source_revision(root: Path) -> str | None:
    try:
        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
        # A commit identifies the source only if modified AND newly added
        # files match it. Generated, gitignored build products are not source.
        dirty = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=normal"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return revision if not dirty and re.fullmatch(r"[0-9a-f]{40}", revision) else None


def write_metadata(root: Path) -> dict:
    metadata = {"version": source_version(root), "revision": source_revision(root)}
    target = root / "panel" / "data" / "build.json"
    if target.is_symlink():
        raise ValueError("build metadata destination must not be a symlink")
    target.write_text(json.dumps(metadata) + "\n", encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    write_metadata(args.source.resolve())


if __name__ == "__main__":
    main()
