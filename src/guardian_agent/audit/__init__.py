"""Audit-log module: JSONL writer + reader + hash chain. SPEC §2."""

from .chain import (
    GENESIS_HASH,
    canonical_json_string,
    canonicalize_for_hash,
    compute_record_hash,
)
from .reader import AuditLogReader
from .writer import AuditLogWriter, AuditLogWriterOptions

__all__ = [
    "AuditLogReader",
    "AuditLogWriter",
    "AuditLogWriterOptions",
    "GENESIS_HASH",
    "canonical_json_string",
    "canonicalize_for_hash",
    "compute_record_hash",
]
