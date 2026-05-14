"""AuditLogReader — iterate + verify hash chain. SPEC §2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..errors import GuardianIntegrityError
from ..types import AuditRecord
from .chain import GENESIS_HASH, compute_record_hash


class AuditLogReader:
    """Read + verify JSONL audit logs."""

    def __init__(self, path: str) -> None:
        self.path = path

    def records(self) -> Iterator[AuditRecord]:
        """Yield each record in file order."""
        with Path(self.path).open("r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                yield json.loads(line)

    def verify_chain(self) -> int:
        """Verify the full hash chain. Returns count of records verified.

        Raises GuardianIntegrityError on first break.
        """
        expected_prev = GENESIS_HASH
        count = 0
        for record in self.records():
            if record.get("prev_hash") != expected_prev:
                raise GuardianIntegrityError(
                    f"audit log hash chain broken at record {count + 1}",
                    f"expected prev_hash={expected_prev}, got {record.get('prev_hash')}",
                )
            expected_prev = compute_record_hash(record)
            count += 1
        return count
