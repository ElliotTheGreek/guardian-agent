"""HMAC-SHA256 integrity for policy files. SPEC §3.5.

Matches the TypeScript impl byte-for-byte for compatible inputs:
HMAC-SHA256(site_key, utf8(canonical_yaml_payload)) → base64 (standard, with padding).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass


@dataclass
class SignedPolicyFile:
    """The on-disk wrapper for permissions.yaml."""

    version: int
    signed_at: str
    signature: str  # base64
    data: str  # canonical-form YAML or JSON


def sign_payload(data: bytes | str, key: bytes) -> str:
    """Compute HMAC-SHA256 over `data` using `key`. Returns standard base64."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    sig = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(sig).decode("ascii")


def verify_payload(data: bytes | str, signature: str, key: bytes) -> bool:
    """Constant-time HMAC verification. Returns True iff the signature matches."""
    expected = sign_payload(data, key)
    return hmac.compare_digest(expected.encode("ascii"), signature.encode("ascii"))
