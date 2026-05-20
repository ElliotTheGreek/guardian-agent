"""External chain attestation. SPEC §2.7 (v0.3.0+).

Why this exists: the local audit log is hash-chained + ed25519-signed, but the
writer's signing key lives on the same machine as the writer. If the runtime
is fully compromised, an attacker can sign a fabricated chain just as easily
as the legitimate writer. Attestation closes that gap by periodically
publishing the current chain head to an external append-only store the local
process cannot rewrite. A later verifier can cross-check the local chain
against the external receipts; any divergence indicates tamper.

The library defines the `Attestor` protocol plus reference HTTP / null
adapters. Production deployments may use S3 with object-lock, a Sigstore
Rekor log, or a second-party receiver. The library never assumes a backend.

Failure mode: attestor errors are NEVER fatal. A failed attestation is itself
an audit row (`x_chain_attestation_failed`). An adversary who DoSes the
attestation endpoint cannot use that to halt the agent's session.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Protocol

from ..types import AuditRecord

ATTESTATION_PAYLOAD_VERSION = "1"


@dataclass
class AttestationPayload:
    """Payload sent to the attestor for one attestation event."""

    agent_id: str
    session_id: str
    head: str
    """sha256:<hex> of the canonical-JSON of the head record."""
    signature: Optional[str]
    """Head record's ed25519:<base64url> signature (or None when unsigned)."""
    record_count: int
    ts: str
    v: str = ATTESTATION_PAYLOAD_VERSION

    def to_wire(self) -> dict[str, Any]:
        """Wire-format dict. Matches TS payloadFromRecord output."""
        return {
            "agentId": self.agent_id,
            "sessionId": self.session_id,
            "head": self.head,
            "signature": self.signature,
            "recordCount": self.record_count,
            "ts": self.ts,
            "v": self.v,
        }


@dataclass
class AttestationReceipt:
    """Receipt an attestor returns on successful publish."""

    receipt_id: str
    url: Optional[str] = None


class Attestor(Protocol):
    """Protocol all attestors implement. SPEC §2.7."""

    def publish(self, payload: AttestationPayload) -> AttestationReceipt:
        """Publish the attestation. Raises on failure (caller catches)."""
        ...


# ===========================================================================
# http_attestor — reference HTTP adapter
# ===========================================================================


@dataclass
class HttpAttestorOptions:
    """Options for the reference HTTP attestor."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    timeout_seconds: float = 5.0
    post: Optional[Callable[[str, bytes, dict[str, str], float], bytes]] = None
    """Override transport (for tests). Must return response body bytes."""


class HttpAttestorError(RuntimeError):
    """Raised by http_attestor on non-2xx, malformed response, or network error."""


def http_attestor(options: HttpAttestorOptions) -> Attestor:
    """Reference HTTP attestor: POSTs JSON, expects `{receiptId, url?}` back.

    Intentionally minimal. Production wants retries, auth refresh,
    content-addressed bodies — those belong in the consumer's adapter.
    """
    post = options.post or _default_post

    class _HttpAttestor:
        def publish(self, payload: AttestationPayload) -> AttestationReceipt:
            body = json.dumps(payload.to_wire(), separators=(",", ":"), sort_keys=True).encode("utf-8")
            headers = {"content-type": "application/json", **options.headers}
            response_bytes = post(options.url, body, headers, options.timeout_seconds)
            try:
                response = json.loads(response_bytes.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise HttpAttestorError(f"http_attestor: malformed response: {exc}") from exc
            receipt_id = response.get("receiptId") if isinstance(response, dict) else None
            if not isinstance(receipt_id, str) or not receipt_id:
                raise HttpAttestorError("http_attestor: response missing receiptId")
            receipt = AttestationReceipt(receipt_id=receipt_id)
            url = response.get("url") if isinstance(response, dict) else None
            if isinstance(url, str):
                receipt.url = url
            return receipt

    return _HttpAttestor()


def _default_post(url: str, body: bytes, headers: dict[str, str], timeout_seconds: float) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            status = response.status
            if not (200 <= status < 300):
                raise HttpAttestorError(f"http_attestor: {status}")
            return response.read()
    except urllib.error.HTTPError as exc:
        raise HttpAttestorError(f"http_attestor: {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise HttpAttestorError(f"http_attestor: network error: {exc.reason}") from exc


# ===========================================================================
# null_attestor — for tests + explicit-disable scenarios
# ===========================================================================


def null_attestor() -> Attestor:
    """No-op attestor that returns synthetic incrementing receipts.

    Useful in tests, or when a consumer wants the supervisor to log
    `x_chain_attested` rows for audit-shape parity without publishing.
    """

    class _NullAttestor:
        n = 0

        def publish(self, payload: AttestationPayload) -> AttestationReceipt:  # noqa: ARG002
            self.n += 1
            return AttestationReceipt(receipt_id=f"null-{self.n}")

    return _NullAttestor()


# ===========================================================================
# Helpers
# ===========================================================================


def payload_from_record(
    record: AuditRecord,
    record_count: int,
    head_hash: str,
) -> AttestationPayload:
    """Build the canonical payload from a head record + the running count.

    Pure: same inputs → same payload (modulo the timestamp). Exposed for tests.
    """
    return AttestationPayload(
        agent_id=record["agent_id"],  # type: ignore[typeddict-item]
        session_id=record["session_id"],  # type: ignore[typeddict-item]
        head=head_hash,
        signature=record.get("signature"),
        record_count=record_count,
        ts=_iso_now(),
    )


def _iso_now() -> str:
    """Z-suffixed millisecond-precision UTC ISO-8601 timestamp."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
