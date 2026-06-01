#!/usr/bin/env python3
"""Pre-publish gate for guardian-agent — builds sdist + wheel, inspects both.

Equivalent of `scripts/verify-pack.mjs` in the TS npm packages. Hard-fails the
publish if either archive contains a forbidden pattern. Asserts the expected
files (LICENSE, README.md, METADATA / PKG-INFO) ARE present.

Exit codes:
  0 — both archives clean; ready to upload
  1 — forbidden pattern found OR required file missing
  2 — build itself failed
"""

from __future__ import annotations

import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist"

# Forbidden patterns split by archive type. Hatchling hard-codes `.gitignore`
# into sdists by default (standard Python packaging convention — sdists ship
# source-state metadata). It's never appropriate in a wheel.
SDIST_FORBIDDEN: list[re.Pattern[str]] = [
    re.compile(r"__pycache__/"),
    re.compile(r"\.pyc$"),
    re.compile(r"\.pyo$"),
    re.compile(r"(^|/)tests/"),
    re.compile(r"(^|/)test_[^/]+\.py$"),
    re.compile(r"\.pytest_cache/"),
    re.compile(r"\.ruff_cache/"),
    re.compile(r"\.mypy_cache/"),
    re.compile(r"(^|/)\.github/"),
    re.compile(r"(^|/)\.env"),
    re.compile(r"(^|/)scripts/"),
    re.compile(r"\.log$"),
    re.compile(r"(^|/)\.DS_Store$"),
    re.compile(r"(^|/)Thumbs\.db$"),
]

WHEEL_FORBIDDEN: list[re.Pattern[str]] = SDIST_FORBIDDEN + [
    re.compile(r"(^|/)\.gitignore$"),
    re.compile(r"(^|/)CHANGELOG\.md$"),
    re.compile(r"(^|/)CONTRIBUTING\.md$"),
    re.compile(r"(^|/)SPEC\.md$"),
    re.compile(r"(^|/)ROADMAP\.md$"),
]


def build() -> tuple[Path, Path]:
    """Run `python -m build`; return (sdist_path, wheel_path)."""
    print("==> Building sdist + wheel via `python -m build`...")
    if DIST_DIR.exists():
        for p in DIST_DIR.iterdir():
            p.unlink()
    try:
        subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(DIST_DIR)],
            cwd=str(REPO_ROOT),
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"FAIL: build failed with exit code {exc.returncode}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print(
            "FAIL: `python -m build` not available. Install with `pip install build`.",
            file=sys.stderr,
        )
        sys.exit(2)

    sdists = sorted(DIST_DIR.glob("*.tar.gz"))
    wheels = sorted(DIST_DIR.glob("*.whl"))
    if not sdists or not wheels:
        print(f"FAIL: build did not produce both sdist + wheel in {DIST_DIR}", file=sys.stderr)
        sys.exit(2)
    return sdists[-1], wheels[-1]


def _check_names(
    archive_label: str,
    names: Iterable[str],
    forbidden: list[re.Pattern[str]],
    required: list[str],
) -> int:
    """Return number of failures found."""
    name_list = list(names)
    failures = 0

    # Forbidden patterns
    for name in name_list:
        for pat in forbidden:
            if pat.search(name):
                print(f"FAIL: {archive_label}: forbidden pattern {pat.pattern!r} matched {name}",
                      file=sys.stderr)
                failures += 1

    # Required files (each must appear somewhere)
    for needed in required:
        found = any(needed in n for n in name_list)
        if not found:
            print(f"FAIL: {archive_label}: required entry {needed!r} not present", file=sys.stderr)
            failures += 1
    return failures


def inspect_sdist(path: Path) -> int:
    print(f"==> Inspecting sdist: {path.name}")
    with tarfile.open(path, mode="r:gz") as tf:
        names = tf.getnames()
    return _check_names("sdist", names, SDIST_FORBIDDEN, required=[
        "PKG-INFO",
        "LICENSE",
        "README.md",
        "CHANGELOG.md",
        "pyproject.toml",
        "src/guardian_agent/__init__.py",
    ])


def inspect_wheel(path: Path) -> int:
    print(f"==> Inspecting wheel: {path.name}")
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    # Wheels do not include top-level CHANGELOG/pyproject — only the package dir + dist-info.
    return _check_names("wheel", names, WHEEL_FORBIDDEN, required=[
        ".dist-info/METADATA",
        ".dist-info/RECORD",
        ".dist-info/WHEEL",
        ".dist-info/licenses/LICENSE",
        "guardian_agent/__init__.py",
    ])


def main() -> int:
    sdist, wheel = build()
    failures = inspect_sdist(sdist) + inspect_wheel(wheel)
    if failures:
        print(f"\nFAIL: {failures} verification problem(s). Fix before publishing.", file=sys.stderr)
        return 1
    print("\nOK: sdist + wheel both clean. Ready to upload.")
    print(f"  sdist: {sdist}")
    print(f"  wheel: {wheel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
