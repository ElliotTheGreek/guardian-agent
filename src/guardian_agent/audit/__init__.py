"""Audit-log module: JSONL writer + reader + hash chain + signatures. SPEC §2."""

from .chain import (
    GENESIS_HASH,
    canonical_json_string,
    canonicalize_for_hash,
    compute_record_hash,
)
from .reader import AuditLogReader
from .signature import (
    SIGNATURE_PREFIX,
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
    sign_record,
    verify_record,
)
from .writer import AuditLogWriter, AuditLogWriterOptions

__all__ = [
    "AuditLogReader",
    "AuditLogWriter",
    "AuditLogWriterOptions",
    "GENESIS_HASH",
    "SIGNATURE_PREFIX",
    "canonical_json_string",
    "canonicalize_for_hash",
    "compute_record_hash",
    "generate_ed25519_keypair",
    "load_private_key",
    "load_public_key",
    "sign_record",
    "verify_record",
]
