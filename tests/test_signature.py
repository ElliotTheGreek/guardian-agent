"""Tests for ed25519 signing (audit/signature.py + signed-writer mode)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardian_agent.audit.chain import compute_record_hash
from guardian_agent.audit.reader import AuditLogReader
from guardian_agent.audit.signature import (
    SIGNATURE_PREFIX,
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
    sign_record,
    verify_record,
)
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.errors import GuardianIntegrityError


def test_generate_keypair_produces_loadable_pems():
    priv_pem, pub_pem = generate_ed25519_keypair()
    assert priv_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
    priv = load_private_key(priv_pem)
    pub = load_public_key(pub_pem)
    # round-trip sign/verify on an arbitrary record
    rec = {"v": "0.5.0", "kind": "tool_call", "signature": None}
    sig = sign_record(rec, priv)
    rec["signature"] = sig
    assert verify_record(rec, pub) is True


def test_sign_record_format_is_ed25519_prefixed_base64url():
    priv_pem, _ = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    rec = {"v": "0.5.0", "kind": "tool_call", "signature": None}
    sig = sign_record(rec, priv)
    assert sig.startswith(SIGNATURE_PREFIX)
    body = sig[len(SIGNATURE_PREFIX):]
    # base64url: no '+' or '/'; ed25519 sig is 64 bytes → 86 chars unpadded
    assert "+" not in body
    assert "/" not in body
    assert "=" not in body
    assert len(body) == 86


def test_verify_record_rejects_tampered_record():
    priv_pem, pub_pem = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    pub = load_public_key(pub_pem)
    rec = {"v": "0.5.0", "kind": "tool_call", "signature": None}
    rec["signature"] = sign_record(rec, priv)
    assert verify_record(rec, pub) is True
    # mutate any field other than signature → verify must fail
    rec["kind"] = "tool_result"
    assert verify_record(rec, pub) is False


def test_verify_record_rejects_unsigned_or_malformed():
    _, pub_pem = generate_ed25519_keypair()
    pub = load_public_key(pub_pem)
    assert verify_record({"signature": None}, pub) is False
    assert verify_record({"signature": "not-prefixed"}, pub) is False
    assert verify_record({"signature": "ed25519:!!!invalid!!!"}, pub) is False
    assert verify_record({}, pub) is False  # missing field


def test_load_private_key_rejects_non_ed25519():
    # An RSA PEM should be rejected, but generating one requires extra deps;
    # easier: feed a public key PEM in where a private was expected.
    _, pub_pem = generate_ed25519_keypair()
    with pytest.raises(ValueError):
        load_private_key(pub_pem)


def test_load_public_key_rejects_non_ed25519():
    priv_pem, _ = generate_ed25519_keypair()
    with pytest.raises(ValueError):
        load_public_key(priv_pem)


def test_writer_signs_every_record_when_sign_with_set(tmp_path: Path):
    priv_pem, pub_pem = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    pub = load_public_key(pub_pem)
    w = AuditLogWriter(
        AuditLogWriterOptions(
            path=str(tmp_path / "audit.jsonl"),
            agent_id="test",
            session_id="sess_signed",
            sign_with=priv,
        )
    )
    w.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    w.append({"kind": "tool_call", "status": "pending", "initiator": "agent",
              "tool": {"name": "list_accounts", "args": {"broker": "x"}}})
    w.append({"kind": "session_close", "status": "approved", "initiator": "system"})
    w.close()

    reader = AuditLogReader(str(tmp_path / "audit.jsonl"))
    # Chain must still verify
    assert reader.verify_chain() == 3
    # Every signature must verify
    assert reader.verify_signatures(pub) == 3
    # And every line on disk must have a signature
    contents = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    for line in (l for l in contents.split("\n") if l):
        parsed = json.loads(line)
        assert isinstance(parsed["signature"], str)
        assert parsed["signature"].startswith(SIGNATURE_PREFIX)


def test_reader_verify_signatures_raises_on_tampered_log(tmp_path: Path):
    priv_pem, pub_pem = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    pub = load_public_key(pub_pem)
    path = tmp_path / "audit.jsonl"
    w = AuditLogWriter(
        AuditLogWriterOptions(
            path=str(path), agent_id="t", session_id="s", sign_with=priv,
        )
    )
    w.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    w.close()
    # Tamper: rewrite the second record's status without re-signing
    lines = path.read_text(encoding="utf-8").splitlines()
    parsed = json.loads(lines[1])
    parsed["status"] = "denied"  # was "pending"
    lines[1] = json.dumps(parsed, separators=(",", ":"), sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reader = AuditLogReader(str(path))
    with pytest.raises(GuardianIntegrityError):
        reader.verify_signatures(pub)


def test_unsigned_writer_still_works(tmp_path: Path):
    """Backwards-compatible: when sign_with is None, signature is null."""
    w = AuditLogWriter(
        AuditLogWriterOptions(
            path=str(tmp_path / "audit.jsonl"),
            agent_id="a",
            session_id="s",
        )
    )
    r = w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    w.close()
    assert r["signature"] is None
    # Hash chain still works
    assert AuditLogReader(str(tmp_path / "audit.jsonl")).verify_chain() == 1


def test_signature_does_not_affect_hash_chain(tmp_path: Path):
    """Two writers — one signed, one unsigned — must produce the same prev_hash chain
    for byte-identical record inputs (signature is stripped from canonicalization)."""
    priv_pem, _ = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)

    # Force deterministic event_id + ts by stubbing — easier: just check that the
    # hash of a signed record matches the hash of the same record with signature
    # set to None.
    rec_signed = {
        "v": "0.5.0",
        "event_id": "evt_TEST",
        "ts": "2026-05-19T00:00:00.000Z",
        "agent_id": "a",
        "session_id": "s",
        "kind": "tool_call",
        "status": "pending",
        "initiator": "agent",
        "prev_hash": "sha256:0",
        "signature": None,
    }
    rec_signed["signature"] = sign_record(rec_signed, priv)

    rec_unsigned = dict(rec_signed)
    rec_unsigned["signature"] = None

    assert compute_record_hash(rec_signed) == compute_record_hash(rec_unsigned)
