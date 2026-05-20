"""guardian-correlator — cross-surface correlation CLI. SPEC §18 (v0.5+).

Reads two or more audit JSONL files for the same agent_id and reports patterns
that span surfaces: overlapping sessions, identical-args collisions, similar
tool-frequency sequences. Writes findings as x_cross_surface_match JSONL to
its own log (NEVER mutates source files).

Usage:
  guardian-correlator <file1>:<surface1> <file2>:<surface2> [...]
  guardian-correlator ... --out <correlations.jsonl>
  guardian-correlator ... --threshold <0..1>          # cosine threshold (default 0.9)
  guardian-correlator ... --window-ms <N>             # args-hash window (default 60000)

Exit codes:
  0 — success
  1 — IO error / bad JSONL
  2 — usage error
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from ..audit.correlation import (
    AuditSource,
    CorrelationMatch,
    CorrelationOptions,
    correlate,
)
from ..audit.reader import AuditLogReader


@dataclass
class CorrelatorArgs:
    sources: list[tuple[str, str]] = field(default_factory=list)
    """List of (path, surface_name) pairs."""
    out: Optional[str] = None
    threshold: float = 0.9
    args_hash_window_ms: int = 60_000
    similarity_window_ms: int = 600_000
    similarity_min_calls: int = 5


@dataclass
class CorrelatorRunResult:
    exit_code: int
    message: str
    matches: list[CorrelationMatch]
    out_path: Optional[str]


USAGE = """\
guardian-correlator — cross-surface audit correlation

Usage:
  guardian-correlator <path1>:<surface1> <path2>:<surface2> [...]
  [--out <path>] [--threshold <0..1>] [--window-ms <N>]
  [--similarity-window-ms <N>] [--similarity-min-calls <N>]"""


def parse_args(argv: Sequence[str]) -> Optional[CorrelatorArgs]:
    sources: list[tuple[str, str]] = []
    out: Optional[str] = None
    threshold = 0.9
    args_hash_window_ms = 60_000
    similarity_window_ms = 600_000
    similarity_min_calls = 5
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--out":
            if not args:
                return None
            out = args.pop(0)
        elif a == "--threshold":
            if not args:
                return None
            try:
                n = float(args.pop(0))
            except ValueError:
                return None
            if not (0.0 <= n <= 1.0):
                return None
            threshold = n
        elif a == "--window-ms":
            if not args:
                return None
            try:
                args_hash_window_ms = int(args.pop(0))
            except ValueError:
                return None
            if args_hash_window_ms <= 0:
                return None
        elif a == "--similarity-window-ms":
            if not args:
                return None
            try:
                similarity_window_ms = int(args.pop(0))
            except ValueError:
                return None
            if similarity_window_ms <= 0:
                return None
        elif a == "--similarity-min-calls":
            if not args:
                return None
            try:
                similarity_min_calls = int(args.pop(0))
            except ValueError:
                return None
            if similarity_min_calls < 1:
                return None
        elif a.startswith("--"):
            return None
        else:
            # path:surface — split on LAST `:` so Windows drive letters work
            idx = a.rfind(":")
            if idx <= 0 or idx == len(a) - 1:
                return None
            sources.append((a[:idx], a[idx + 1:]))
    if len(sources) < 2:
        return None
    return CorrelatorArgs(
        sources=sources,
        out=out,
        threshold=threshold,
        args_hash_window_ms=args_hash_window_ms,
        similarity_window_ms=similarity_window_ms,
        similarity_min_calls=similarity_min_calls,
    )


def default_correlations_path() -> str:
    env = os.environ.get("FLOWDOT_CORRELATIONS_PATH")
    if env:
        return env
    return str(Path.home() / ".flowdot" / "audit" / "correlations.jsonl")


def run_correlator(args: CorrelatorArgs) -> CorrelatorRunResult:
    if len(args.sources) < 2:
        return CorrelatorRunResult(
            exit_code=2, message="need at least two sources", matches=[], out_path=None,
        )
    sources: list[AuditSource] = []
    for path, surface in args.sources:
        if not Path(path).exists():
            return CorrelatorRunResult(
                exit_code=1, message=f"audit file not found: {path}",
                matches=[], out_path=None,
            )
        try:
            reader = AuditLogReader(path)
            records = list(reader.records())
        except (OSError, ValueError) as exc:
            return CorrelatorRunResult(
                exit_code=1, message=f"failed to read {path}: {exc}",
                matches=[], out_path=None,
            )
        sources.append(AuditSource(surface=surface, records=records))

    matches = correlate(
        sources,
        CorrelationOptions(
            similarity_threshold=args.threshold,
            args_hash_window_ms=args.args_hash_window_ms,
            similarity_window_ms=args.similarity_window_ms,
            similarity_min_calls=args.similarity_min_calls,
        ),
    )

    out_path = args.out or default_correlations_path()
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with Path(out_path).open("a", encoding="utf-8") as f:
        for m in matches:
            f.write(json.dumps(m.to_dict(), sort_keys=True) + "\n")

    return CorrelatorRunResult(
        exit_code=0,
        message=f"{len(matches)} match(es) written to {out_path}",
        matches=matches,
        out_path=out_path,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parsed = parse_args(argv if argv is not None else sys.argv[1:])
    if parsed is None:
        sys.stderr.write(USAGE + "\n")
        return 2
    result = run_correlator(parsed)
    out_stream = sys.stdout if result.exit_code == 0 else sys.stderr
    out_stream.write(result.message + "\n")
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
