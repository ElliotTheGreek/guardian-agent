"""Single-writer append-only JSONL audit log with hash chain. SPEC §2."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

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
from .attestor import Attestor, payload_from_record
from .chain import GENESIS_HASH, canonical_json_string, compute_record_hash
from .signature import sign_record

OnTipRecoveredCallback = Callable[[AuditRecord], None]


@dataclass
class AuditLogWriterOptions:
    """Constructor options for AuditLogWriter."""

    path: str
    agent_id: str
    session_id: str
    file_mode: int = 0o600
    sign_with: Ed25519PrivateKey | None = None
    """ed25519 private key. When set, every record is signed. SPEC §2.6."""
    on_tip_recovered: Optional[OnTipRecoveredCallback] = None
    """Called once on open() when an existing log is reopened, with the last
    record. Lets the host detect unclean shutdown (last record was anything
    other than session_close). Not called on a fresh file. Errors do not
    prevent open(); they propagate to the caller of append()."""
    attestor: Optional[Attestor] = None
    """External chain attestor. When set, the writer publishes the current
    chain head every `attest_every` records and on close(). Each successful
    publish emits x_chain_attested; failures emit x_chain_attestation_failed.
    Attestor errors are NEVER fatal. SPEC §2.7."""
    attest_every: int = 100
    """Records between attestations. Ignored when attestor is None."""
    attest_on_close: bool = True
    """Attest the final chain head on close(). Ignored when attestor is None."""


class AuditLogWriter:
    """Append-only JSONL writer with hash chain.

    Thread-safe via an internal lock; hash chain remains strictly ordered
    even when multiple threads call append concurrently.
    """

    def __init__(self, options: AuditLogWriterOptions) -> None:
        if options.attest_every <= 0:
            raise ValueError("attest_every must be > 0")
        self.path = options.path
        self.agent_id = options.agent_id
        self.session_id = options.session_id
        self._file_mode = options.file_mode
        self._sign_with = options.sign_with
        self._on_tip_recovered = options.on_tip_recovered
        self._attestor = options.attestor
        self._attest_every = options.attest_every
        self._attest_on_close = options.attest_on_close
        self._lock = threading.RLock()
        self._tip_hash: str = GENESIS_HASH
        self._handle: Optional[object] = None
        self._opened = False
        self._closed = False
        self._appended_count = 0
        self._attestation_in_flight = False

    @property
    def tip_hash(self) -> str:
        """Tip of the hash chain (last appended record's hash)."""
        return self._tip_hash

    def open(self) -> None:
        """Open the underlying file. Idempotent. Recovers tip hash if file exists."""
        recovered: Optional[AuditRecord]
        with self._lock:
            recovered = self._open_locked()
        # Fire the recovery callback OUTSIDE the lock so callbacks that
        # call append() back into the writer do not deadlock.
        if recovered is not None and self._on_tip_recovered is not None:
            self._on_tip_recovered(recovered)

    def _open_locked(self) -> Optional[AuditRecord]:
        """Open the file. Returns the recovered tip record if the log existed."""
        if self._opened:
            return None
        self._opened = True
        path = Path(self.path)
        recovered: Optional[AuditRecord] = None
        if path.exists():
            recovered = self._recover_tip_record()
            if recovered is not None:
                self._tip_hash = compute_record_hash(recovered)
        # Open for append; create if absent.
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            mode=self._file_mode,
        )
        self._handle = os.fdopen(fd, "ab", buffering=0)
        return recovered

    def append(self, record_input: AuditRecordInput) -> AuditRecord:
        """Append a record. Returns the persisted record (with assigned fields)."""
        recovered: Optional[AuditRecord]
        with self._lock:
            if self._closed:
                raise RuntimeError("AuditLogWriter is closed")
            recovered = self._open_locked()
            written = self._write_one(record_input)
            # Fire attestation when we cross an attest_every boundary. The
            # callback runs UNDER the lock (we hold an RLock) and uses
            # _append_internal which bypasses the closed check.
            if (
                self._attestor is not None
                and not self._attestation_in_flight
                and self._appended_count % self._attest_every == 0
            ):
                self._run_attestation_locked()
        if recovered is not None and self._on_tip_recovered is not None:
            self._on_tip_recovered(recovered)
        return written

    def close(self) -> None:
        """Flush and close. Idempotent."""
        with self._lock:
            if self._closed:
                return
            # Final attestation BEFORE flipping closed, so we can still append.
            if (
                self._attestor is not None
                and self._attest_on_close
                and self._appended_count > 0
            ):
                self._run_attestation_locked()
            self._closed = True
            if self._handle is not None:
                self._handle.close()  # type: ignore[attr-defined]
                self._handle = None

    def run_attestation(self) -> None:
        """Force a chain-head attestation right now.

        Useful for manually-triggered checkpoints. Idempotent on no-attestor
        / in-flight / closed.
        """
        with self._lock:
            if self._attestor is None or self._attestation_in_flight or self._closed:
                return
            self._run_attestation_locked()

    def _run_attestation_locked(self) -> None:
        """Caller MUST hold self._lock."""
        if self._attestor is None:
            return
        self._attestation_in_flight = True
        try:
            head = self._tip_hash
            synth: AuditRecord = {
                "agent_id": self.agent_id,
                "session_id": self.session_id,
                "signature": None,
            }
            payload = payload_from_record(synth, self._appended_count, head)
            try:
                receipt = self._attestor.publish(payload)
                detail: dict[str, Any] = {
                    "chain_head": head,
                    "records_in_session": self._appended_count,
                    "receipt_id": receipt.receipt_id,
                }
                if receipt.url is not None:
                    detail["receipt_url"] = receipt.url
                self._append_internal_locked(
                    {
                        "kind": "x_chain_attested",
                        "status": "approved",
                        "initiator": "system",
                        "detail": detail,
                    }
                )
            except BaseException as exc:  # noqa: BLE001 — attestor MUST NOT crash writer
                self._append_internal_locked(
                    {
                        "kind": "x_chain_attestation_failed",
                        "status": "errored",
                        "initiator": "system",
                        "detail": {
                            "chain_head": head,
                            "records_in_session": self._appended_count,
                            "error": str(exc),
                        },
                    }
                )
        finally:
            self._attestation_in_flight = False

    def _append_internal_locked(self, input_record: AuditRecordInput) -> AuditRecord:
        """Internal append that bypasses the closed check.

        Used by attestation outcome rows so close() can write them after
        flipping closed=False is impractical. Caller MUST hold self._lock.
        """
        if not self._opened:
            self._open_locked()
        return self._write_one(input_record)

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
        self._appended_count += 1
        return record

    def _recover_tip_record(self) -> Optional[AuditRecord]:
        """Read the last record from the existing file, or None if empty."""
        buf = Path(self.path).read_text(encoding="utf-8")
        if not buf:
            return None
        for line in reversed(buf.split("\n")):
            if not line:
                continue
            import json as _json

            return _json.loads(line)
        return None


def _iso_now() -> str:
    """Z-suffixed millisecond-precision UTC ISO-8601 timestamp."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
