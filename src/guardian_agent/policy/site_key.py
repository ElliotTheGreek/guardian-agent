"""Site key — 32 random bytes used as HMAC key for policy integrity. SPEC §3.5.

Persisted under `.guardian/site.key` (or wherever the host points it).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from ..errors import GuardianConfigError

SITE_KEY_BYTES = 32


@dataclass
class SiteKey:
    """Wrapping struct: the 32-byte key plus its on-disk path (or marker)."""

    bytes_: bytes
    path: str


def load_or_create_site_key(path: str) -> SiteKey:
    """Load the site key from `path`, or generate and persist a new one if absent."""
    p = Path(path)
    if p.exists():
        data = p.read_bytes()
        if len(data) != SITE_KEY_BYTES:
            raise GuardianConfigError(
                f"site key at {path} is {len(data)} bytes, expected {SITE_KEY_BYTES}"
            )
        return SiteKey(bytes_=data, path=path)

    p.parent.mkdir(parents=True, exist_ok=True)
    data = secrets.token_bytes(SITE_KEY_BYTES)
    p.write_bytes(data)
    try:
        os.chmod(p, 0o600)
    except OSError:  # pragma: no cover — Windows path
        pass
    return SiteKey(bytes_=data, path=path)


def site_key_from_bytes(data: bytes) -> SiteKey:
    """Construct a SiteKey from raw bytes (testing)."""
    if len(data) != SITE_KEY_BYTES:
        raise GuardianConfigError(
            f"site key bytes are {len(data)}, expected {SITE_KEY_BYTES}"
        )
    return SiteKey(bytes_=data, path="<in-memory>")
