"""Single-writer append-only JSONL audit log with hash chain. SPEC §2."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from ulid import ULID

    def _ulid() -> str:
        return str(ULID())
except ImportError:  # pragma: no cover — ulid is in pyproject deps
    import uuid

    def _ulid() -> str:
        return uuid.uuid4().hex.upper()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..types import SPEC_VERSION, AuditRecord, AuditRecordInput
from .chain import GENESIS_HASH, canonical_json_string, compute_record_hash
from .signature import sign_record


@dataclass
class AuditLogWriterOptions:
    """Constructor options for AuditLogWriter."""

    path: str
    agent_id: str
    session_id: str
    file_mode: int = 0o600
    sign_with: Ed25519PrivateKey | None = None
    """ed25519 private key. When set, every record is signed. SPEC §2.6."""


class AuditLogWriter:
    """Append-only JSONL writer with hash chain.

    Thread-safe via an internal lock; hash chain remains strictly ordered
    even when multiple threads call append concurrently.
    """

    def __init__(self, options: AuditLogWriterOptions) -> None:
        self.path = options.path
        self.agent_id = options.agent_id
        self.session_id = options.session_id
        self._file_mode = options.file_mode
        self._sign_with = options.sign_with
        self._lock = threading.Lock()
        self._tip_hash: str = GENESIS_HASH
        self._handle: Optional[object] = None
        self._opened = False
        self._closed = False

    @property
    def tip_hash(self) -> str:
        """Tip of the hash chain (last appended record's hash)."""
        return self._tip_hash

    def open(self) -> None:
        """Open the underlying file. Idempotent. Recovers tip hash if file exists."""
        with self._lock:
            self._open_locked()

    def _open_locked(self) -> None:
        if self._opened:
            return
        self._opened = True
        path = Path(self.path)
        if path.exists():
            self._tip_hash = self._recover_tip_hash()
        # Open for append; create if absent.
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            mode=self._file_mode,
        )
        self._handle = os.fdopen(fd, "ab", buffering=0)

    def append(self, record_input: AuditRecordInput) -> AuditRecord:
        """Append a record. Returns the persisted record (with assigned fields)."""
        with self._lock:
            if self._closed:
                raise RuntimeError("AuditLogWriter is closed")
            self._open_locked()
            return self._write_one(record_input)

    def close(self) -> None:
        """Flush and close. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._handle is not None:
                self._handle.close()  # type: ignore[attr-defined]
                self._handle = None

    # ---- internal ---------------------------------------------------------

    def _write_one(self, input_record: AuditRecordInput) -> AuditRecord:
        record: AuditRecord = {
            "v": SPEC_VERSION,
            "event_id": "evt_" + _ulid(),
            "ts": _iso_now(),
            "agent_id": input_record.get("agent_id", self.agent_id),
            "session_id": input_record.get("session_id", self.session_id),
            "kind": input_record["kind"],
            "status": input_record["status"],
            "initiator": input_record["initiator"],
            "prev_hash": self._tip_hash,
        }
        if "tool" in input_record:
            record["tool"] = input_record["tool"]
        if "model" in input_record:
            record["model"] = input_record["model"]
        if "detail" in input_record:
            record["detail"] = input_record["detail"]
        # Sign or write `signature: null` per SPEC §2.6. canonicalize_for_hash
        # strips the field before hashing/signing so either state is safe.
        record["signature"] = None
        if self._sign_with is not None:
            record["signature"] = sign_record(record, self._sign_with)

        line = canonical_json_string(record) + "\n"
        assert self._handle is not None  # narrowing for type checker
        self._handle.write(line.encode("utf-8"))  # type: ignore[attr-defined]
        try:
            self._handle.flush()  # type: ignore[attr-defined]
        except OSError:  # pragma: no cover
            pass

        self._tip_hash = compute_record_hash(record)
        return record

    def _recover_tip_hash(self) -> str:
        buf = Path(self.path).read_text(encoding="utf-8")
        if not buf:
            return GENESIS_HASH
        for line in reversed(buf.split("\n")):
            if not line:
                continue
            import json as _json

            record = _json.loads(line)
            return compute_record_hash(record)
        return GENESIS_HASH


def _iso_now() -> str:
    """Z-suffixed millisecond-precision UTC ISO-8601 timestamp."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
