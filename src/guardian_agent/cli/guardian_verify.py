"""guardian-verify — audit-log integrity verification CLI. SPEC §2.5, §2.6.

Exit codes:
  0 — chain ok + signatures ok (when --pubkey supplied)
  1 — chain broken / signature invalid / IO error
  2 — usage error (bad args)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from ..audit.reader import AuditLogReader
from ..audit.signature import load_public_key
from ..errors import GuardianIntegrityError


@dataclass
class VerifyArgs:
    path: Optional[str]
    pubkey_path: Optional[str]


@dataclass
class VerifyResult:
    record_count: int
    chain_verified: bool
    signatures_verified: bool
    exit_code: int
    message: str


USAGE = """\
guardian-verify — verify guardian-agent audit log integrity

Usage:
  guardian-verify <audit.jsonl> [--pubkey <pem>]

Options:
  --pubkey <pem>   Path to an ed25519 public key (PEM). When supplied, signatures are verified.
  --help, -h       Show this message."""


def parse_args(argv: Sequence[str]) -> Optional[VerifyArgs]:
    """Parse argv. Returns parsed args, or None on usage error.

    Empty VerifyArgs (both fields None) means --help was requested.
    """
    path: Optional[str] = None
    pubkey_path: Optional[str] = None
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--pubkey":
            if not args:
                return None
            pubkey_path = args.pop(0)
        elif a in ("--help", "-h"):
            return VerifyArgs(path=None, pubkey_path=None)
        elif a.startswith("--"):
            return None
        else:
            if path is not None:
                return None
            path = a
    return VerifyArgs(path=path, pubkey_path=pubkey_path)


def run_verify(args: VerifyArgs) -> VerifyResult:
    if not args.path:
        return VerifyResult(
            record_count=0, chain_verified=False, signatures_verified=False,
            exit_code=2, message=USAGE,
        )
    reader = AuditLogReader(args.path)
    try:
        chain_count = reader.verify_chain()
    except GuardianIntegrityError as exc:
        return VerifyResult(
            record_count=0, chain_verified=False, signatures_verified=False,
            exit_code=1, message=f"chain verification failed: {exc}",
        )
    except (OSError, ValueError) as exc:
        return VerifyResult(
            record_count=0, chain_verified=False, signatures_verified=False,
            exit_code=1, message=f"chain verification failed: {exc}",
        )

    signatures_verified = False
    if args.pubkey_path:
        try:
            pem = Path(args.pubkey_path).read_bytes()
            pubkey = load_public_key(pem)
            reader.verify_signatures(pubkey)
            signatures_verified = True
        except GuardianIntegrityError as exc:
            return VerifyResult(
                record_count=chain_count, chain_verified=True, signatures_verified=False,
                exit_code=1, message=f"signature verification failed: {exc}",
            )
        except (OSError, ValueError) as exc:
            return VerifyResult(
                record_count=chain_count, chain_verified=True, signatures_verified=False,
                exit_code=1, message=f"signature verification failed: {exc}",
            )

    parts = [f"chain ok ({chain_count} records)"]
    if signatures_verified:
        parts.append("signatures ok")
    return VerifyResult(
        record_count=chain_count, chain_verified=True,
        signatures_verified=signatures_verified, exit_code=0,
        message="; ".join(parts),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parsed = parse_args(argv if argv is not None else sys.argv[1:])
    if parsed is None:
        sys.stderr.write(USAGE + "\n")
        return 2
    result = run_verify(parsed)
    out_stream = sys.stdout if result.exit_code == 0 else sys.stderr
    out_stream.write(result.message + "\n")
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
