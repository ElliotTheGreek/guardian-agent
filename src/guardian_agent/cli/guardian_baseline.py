"""guardian-baseline — offline behavioral-baseline CLI. SPEC §17 (v0.5+).

Usage:
  guardian-baseline <jsonl>                            # build profile(s); write to ~/.flowdot/audit/baselines/<agent>.json
  guardian-baseline <jsonl> --agent <id>               # restrict to one agent_id
  guardian-baseline <jsonl> --out <path>               # custom output path
  guardian-baseline <jsonl> --check                    # compare jsonl against saved baseline(s); report deviations
  guardian-baseline <jsonl> --check --sigma <N>        # custom σ threshold (default 3)

Exit codes:
  0 — success (profile written, or --check found zero deviations)
  1 — IO error / bad JSONL / --check found deviations
  2 — usage error
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from ..audit.reader import AuditLogReader
from ..audit.stats import (
    AgentProfile,
    CompareOptions,
    DeviationReport,
    analyze_multi_agent,
    compare_to_baseline,
)


@dataclass
class BaselineArgs:
    path: Optional[str]
    agent: Optional[str]
    out: Optional[str]
    check: bool
    sigma: float


@dataclass
class BaselineRunResult:
    exit_code: int
    message: str
    profiles_written: list[str]
    reports: list[DeviationReport]


USAGE = """\
guardian-baseline — behavioral baselines + σ-deviation reports

Usage:
  guardian-baseline <jsonl> [--agent <id>] [--out <path>]
  guardian-baseline <jsonl> --check [--sigma <N>]"""


def parse_args(argv: Sequence[str]) -> Optional[BaselineArgs]:
    path: Optional[str] = None
    agent: Optional[str] = None
    out: Optional[str] = None
    check = False
    sigma = 3.0
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--agent":
            if not args:
                return None
            agent = args.pop(0)
        elif a == "--out":
            if not args:
                return None
            out = args.pop(0)
        elif a == "--check":
            check = True
        elif a == "--sigma":
            if not args:
                return None
            try:
                sigma = float(args.pop(0))
            except ValueError:
                return None
            if sigma <= 0:
                return None
        elif a.startswith("--"):
            return None
        elif path is None:
            path = a
        else:
            return None
    if path is None:
        return None
    return BaselineArgs(path=path, agent=agent, out=out, check=check, sigma=sigma)


def default_baselines_dir() -> str:
    env_dir = os.environ.get("FLOWDOT_BASELINES_DIR")
    if env_dir:
        return env_dir
    return str(Path.home() / ".flowdot" / "audit" / "baselines")


def _baseline_path(agent_id: str, baselines_dir: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", agent_id)
    return str(Path(baselines_dir) / f"{safe}.json")


def run_baseline(args: BaselineArgs) -> BaselineRunResult:
    if not args.path:
        return BaselineRunResult(exit_code=2, message="missing path",
                                 profiles_written=[], reports=[])
    if not Path(args.path).exists():
        return BaselineRunResult(
            exit_code=1, message=f"audit file not found: {args.path}",
            profiles_written=[], reports=[],
        )
    try:
        reader = AuditLogReader(args.path)
        records = list(reader.records())
    except (OSError, ValueError) as exc:
        return BaselineRunResult(
            exit_code=1, message=f"failed to read audit file: {exc}",
            profiles_written=[], reports=[],
        )

    profiles = analyze_multi_agent(records)
    if args.agent is not None:
        profiles = {k: v for k, v in profiles.items() if k == args.agent}
    if not profiles:
        msg = (
            f"no records for agent_id {args.agent!r}"
            if args.agent is not None
            else "no records found in audit file"
        )
        return BaselineRunResult(exit_code=1, message=msg, profiles_written=[], reports=[])

    baselines_dir = str(Path(args.out).parent) if args.out else default_baselines_dir()

    if args.check:
        reports: list[DeviationReport] = []
        for agent_id, profile in profiles.items():
            base_file = args.out or _baseline_path(agent_id, baselines_dir)
            if not Path(base_file).exists():
                return BaselineRunResult(
                    exit_code=1,
                    message=(
                        f"no baseline for {agent_id} at {base_file} — "
                        "run without --check first to produce one"
                    ),
                    profiles_written=[],
                    reports=reports,
                )
            try:
                payload = json.loads(Path(base_file).read_text(encoding="utf-8"))
                baseline = AgentProfile.from_dict(payload)
            except (OSError, ValueError, KeyError) as exc:
                return BaselineRunResult(
                    exit_code=1,
                    message=f"failed to read baseline {base_file}: {exc}",
                    profiles_written=[],
                    reports=reports,
                )
            reports.append(
                compare_to_baseline(profile, baseline, CompareOptions(sigma_threshold=args.sigma))
            )
        total = sum(len(r.deviations) for r in reports)
        if total == 0:
            return BaselineRunResult(
                exit_code=0,
                message=f"OK: {len(reports)} agent(s) checked, no deviations at σ={args.sigma}",
                profiles_written=[],
                reports=reports,
            )
        return BaselineRunResult(
            exit_code=1,
            message=f"{total} deviation(s) across {len(reports)} agent(s) at σ={args.sigma}",
            profiles_written=[],
            reports=reports,
        )

    # Write path
    if args.out and len(profiles) > 1:
        return BaselineRunResult(
            exit_code=2,
            message="--out requires --agent when the file contains multiple agent_ids",
            profiles_written=[],
            reports=[],
        )
    Path(baselines_dir).mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for agent_id, profile in profiles.items():
        file = args.out or _baseline_path(agent_id, baselines_dir)
        Path(file).write_text(json.dumps(profile.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            os.chmod(file, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except OSError:
            pass
        written.append(file)
    return BaselineRunResult(
        exit_code=0, message=f"wrote {len(written)} baseline(s)",
        profiles_written=written, reports=[],
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parsed = parse_args(argv if argv is not None else sys.argv[1:])
    if parsed is None:
        sys.stderr.write(USAGE + "\n")
        return 2
    result = run_baseline(parsed)
    out_stream = sys.stdout if result.exit_code == 0 else sys.stderr
    out_stream.write(result.message + "\n")
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
