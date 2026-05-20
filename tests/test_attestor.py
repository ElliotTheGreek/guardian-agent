"""Tests for audit/attestor.py + writer attestation integration. SPEC §2.7."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from guardian_agent.audit.attestor import (
    AttestationPayload,
    AttestationReceipt,
    Attestor,
    HttpAttestorError,
    HttpAttestorOptions,
    http_attestor,
    null_attestor,
    payload_from_record,
)
from guardian_agent.audit.reader import AuditLogReader
from guardian_agent.audit.signature import (
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
)
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions


# ---- null_attestor + payload helpers -----------------------------------


def test_null_attestor_returns_incrementing_receipts():
    a = null_attestor()
    p = AttestationPayload(
        agent_id="x", session_id="s", head="sha256:abc",
        signature=None, record_count=1, ts="2026-05-20T00:00:00.000Z",
    )
    r1 = a.publish(p)
    r2 = a.publish(p)
    assert r1.receipt_id == "null-1"
    assert r2.receipt_id == "null-2"


def test_payload_from_record_uses_record_fields():
    rec: dict[str, Any] = {
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "signature": "ed25519:abc",
    }
    p = payload_from_record(rec, 42, "sha256:deadbeef")  # type: ignore[arg-type]
    assert p.agent_id == "agent-1"
    assert p.session_id == "sess-1"
    assert p.head == "sha256:deadbeef"
    assert p.signature == "ed25519:abc"
    assert p.record_count == 42
    assert p.v == "1"


def test_payload_wire_format_matches_ts_camelcase():
    p = AttestationPayload(
        agent_id="a", session_id="s", head="sha256:h", signature=None,
        record_count=5, ts="2026-01-01T00:00:00.000Z",
    )
    wire = p.to_wire()
    # TS uses camelCase in the wire (agentId, sessionId, recordCount).
    assert wire == {
        "agentId": "a",
        "sessionId": "s",
        "head": "sha256:h",
        "signature": None,
        "recordCount": 5,
        "ts": "2026-01-01T00:00:00.000Z",
        "v": "1",
    }


# ---- http_attestor ------------------------------------------------------


def test_http_attestor_posts_and_parses_receipt():
    captured: dict[str, Any] = {}

    def fake_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
        captured["url"] = url
        captured["body"] = body
        captured["headers"] = headers
        captured["timeout"] = timeout
        return json.dumps({"receiptId": "rec-1", "url": "https://h/r/1"}).encode("utf-8")

    a = http_attestor(HttpAttestorOptions(
        url="https://h/v1/heads", headers={"x-auth": "t"}, timeout_seconds=3.0,
        post=fake_post,
    ))
    p = AttestationPayload(
        agent_id="a", session_id="s", head="sha256:h", signature=None,
        record_count=1, ts="2026-01-01T00:00:00.000Z",
    )
    receipt = a.publish(p)
    assert receipt.receipt_id == "rec-1"
    assert receipt.url == "https://h/r/1"
    assert captured["url"] == "https://h/v1/heads"
    assert captured["headers"]["x-auth"] == "t"
    sent = json.loads(captured["body"])
    assert sent["agentId"] == "a"


def test_http_attestor_rejects_missing_receipt_id():
    def fake_post(*_a: Any, **_kw: Any) -> bytes:
        return b"{}"
    a = http_attestor(HttpAttestorOptions(url="https://x", post=fake_post))
    with pytest.raises(HttpAttestorError, match="receiptId"):
        a.publish(AttestationPayload("a", "s", "sha256:h", None, 1, "t"))


def test_http_attestor_rejects_malformed_json():
    def fake_post(*_a: Any, **_kw: Any) -> bytes:
        return b"not json"
    a = http_attestor(HttpAttestorOptions(url="https://x", post=fake_post))
    with pytest.raises(HttpAttestorError, match="malformed response"):
        a.publish(AttestationPayload("a", "s", "sha256:h", None, 1, "t"))


# ---- writer integration -------------------------------------------------


def test_writer_attests_when_appended_count_crosses_attest_every(tmp_path: Path):
    """Attestation fires when appended_count is a multiple of attest_every.

    Outcome rows (x_chain_attested) themselves count toward appended_count —
    this matches the TS reference impl. Net effect: with attest_every=N and
    K user appends, the number of fires is approximately K/(N-1), not K/N.
    Tests assert the semantics, not an ideal cadence.
    """
    received: list[AttestationPayload] = []

    class CaptureAttestor:
        def publish(self, p: AttestationPayload) -> AttestationReceipt:
            received.append(p)
            return AttestationReceipt(receipt_id=f"r{len(received)}")

    priv_pem, _ = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(tmp_path / "a.jsonl"), agent_id="a", session_id="s",
        sign_with=priv, attestor=CaptureAttestor(), attest_every=2,
    ))
    for _ in range(5):
        w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    w.close()

    # Every payload was fired at an even count (the boundary condition).
    # Final close-time fire goes at whatever count we reached.
    assert len(received) >= 2
    for p in received[:-1]:
        assert p.record_count % 2 == 0, f"non-close fire at count {p.record_count}"

    # File contains the user rows + the attestation outcome rows
    contents = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    kinds = [json.loads(line)["kind"] for line in contents]
    assert kinds.count("tool_call") == 5
    assert kinds.count("x_chain_attested") == len(received)


def test_writer_attestor_failure_lands_as_x_chain_attestation_failed(tmp_path: Path):
    class BrokenAttestor:
        def publish(self, _p: AttestationPayload) -> AttestationReceipt:
            raise RuntimeError("attestor down")

    priv_pem, _ = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(tmp_path / "a.jsonl"), agent_id="a", session_id="s",
        sign_with=priv, attestor=BrokenAttestor(), attest_every=1,
    ))
    w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    w.close()

    contents = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in contents]
    failed = [r for r in rows if r["kind"] == "x_chain_attestation_failed"]
    assert len(failed) >= 1
    assert failed[0]["status"] == "errored"
    assert "attestor down" in failed[0]["detail"]["error"]


def test_writer_attest_on_close_false_skips_final(tmp_path: Path):
    received: list[AttestationPayload] = []

    class CA:
        def publish(self, p: AttestationPayload) -> AttestationReceipt:
            received.append(p)
            return AttestationReceipt(receipt_id="r")

    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(tmp_path / "a.jsonl"), agent_id="a", session_id="s",
        attestor=CA(), attest_every=10, attest_on_close=False,
    ))
    w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    w.close()
    assert received == []  # no boundary crossed, no close attest


def test_writer_rejects_zero_attest_every(tmp_path: Path):
    with pytest.raises(ValueError, match="attest_every"):
        AuditLogWriter(AuditLogWriterOptions(
            path=str(tmp_path / "a.jsonl"), agent_id="a", session_id="s",
            attest_every=0,
        ))


def test_writer_force_run_attestation(tmp_path: Path):
    received: list[AttestationPayload] = []

    class CA:
        def publish(self, p: AttestationPayload) -> AttestationReceipt:
            received.append(p)
            return AttestationReceipt(receipt_id="r")

    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(tmp_path / "a.jsonl"), agent_id="a", session_id="s",
        attestor=CA(), attest_every=999_999, attest_on_close=False,
    ))
    w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    assert received == []
    w.run_attestation()
    assert len(received) == 1
    w.close()


def test_on_tip_recovered_fires_when_reopening_existing_log(tmp_path: Path):
    # Open + write + close cleanly (so a session_close is the tip).
    priv_pem, _ = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    p = tmp_path / "a.jsonl"

    w1 = AuditLogWriter(AuditLogWriterOptions(
        path=str(p), agent_id="a", session_id="s1", sign_with=priv,
    ))
    w1.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    w1.append({"kind": "session_close", "status": "approved", "initiator": "system"})
    w1.close()

    seen: list[Any] = []
    w2 = AuditLogWriter(AuditLogWriterOptions(
        path=str(p), agent_id="a", session_id="s2", sign_with=priv,
        on_tip_recovered=lambda rec: seen.append(rec),
    ))
    # The callback fires when the file is first opened (lazily on first append).
    w2.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    w2.close()

    assert len(seen) == 1
    assert seen[0]["kind"] == "session_close"


def test_attest_does_not_recurse_on_outcome_row(tmp_path: Path):
    """Writing the x_chain_attested row must NOT trigger another attestation."""
    calls = []

    class CA:
        def publish(self, p: AttestationPayload) -> AttestationReceipt:
            calls.append(p)
            return AttestationReceipt(receipt_id=f"r{len(calls)}")

    # attest_every=1 → would normally fire on every append, including the
    # outcome row. The in_flight flag must prevent recursion.
    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(tmp_path / "a.jsonl"), agent_id="a", session_id="s",
        attestor=CA(), attest_every=1, attest_on_close=False,
    ))
    w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    w.close()
    # 1 user record → 1 attestation. If recursion were broken, we'd see N+1.
    assert len(calls) == 1
