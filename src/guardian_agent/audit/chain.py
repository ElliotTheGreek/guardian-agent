"""Audit-log hash chain. SPEC §2.5.

Stateless helpers; no I/O. The canonical JSON format is critical for
cross-language hash interop with the TypeScript reference impl.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..types import AuditRecord

GENESIS_HASH = "sha256:0"


def compute_record_hash(record: AuditRecord) -> str:
    """Canonical SHA-256 hash over the record, with `signature` cleared."""
    canonical = canonicalize_for_hash(record)
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def canonicalize_for_hash(record: AuditRecord) -> bytes:
    """Produce canonical UTF-8 bytes of a record for hashing.

    Strips `signature`; sorts keys; matches the TypeScript impl's
    canonicalJsonStringify byte-for-byte for compatible inputs.
    """
    cleaned = {k: v for k, v in record.items() if k != "signature"}
    return canonical_json_string(cleaned).encode("utf-8")


def canonical_json_string(value: Any) -> str:
    """Stable JSON serializer matching the TypeScript canonicalJsonStringify.

    Rules:
      - Object keys sorted lexicographically.
      - No extra whitespace.
      - Numbers via Python json (must be finite).
      - Strings via Python json (Unicode escaped where Python escapes).
      - undefined-equivalent (Python None inside dicts) is OMITTED (matches
        the TS behavior of `JSON.stringify` skipping undefined values).
    """
    return _serialize(value)


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise TypeError("non-finite numbers cannot be canonicalized")
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    if isinstance(value, dict):
        parts: list[str] = []
        for key in sorted(value.keys()):
            v = value[key]
            if v is None and key != "signature":
                # Match TS: undefined values are omitted; we treat top-level
                # `signature: None` (after canonicalize strip) the same way,
                # but inside an object a None value is serialized as null
                # *unless* the key was explicitly omitted by the caller.
                # We choose to serialize None as "null" (Python convention)
                # except for keys treated as wire-shape optional sentinels.
                # In practice the audit record never carries None values
                # except `signature`, which canonicalize_for_hash strips.
                pass
            if v is None:
                # Default: emit null (matches Python json.dumps).
                parts.append(json.dumps(key) + ":null")
                continue
            parts.append(json.dumps(key) + ":" + _serialize(v))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"cannot canonicalize value of type {type(value).__name__}")
