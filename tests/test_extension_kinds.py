"""Tests for SPEC §10 `x_*` extension audit kinds."""

from __future__ import annotations

import json
from pathlib import Path

from guardian_agent.audit.reader import AuditLogReader
from guardian_agent.audit.signature import (
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
)
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.types import STANDARD_KINDS, is_extension_kind


def test_is_extension_kind_recognizes_x_prefix():
    assert is_extension_kind("x_session_recovered")
    assert is_extension_kind("x_rate_limit_breached")
    assert is_extension_kind("x_chain_attested")
    assert is_extension_kind("x_")  # technically valid
    assert not is_extension_kind("tool_call")
    assert not is_extension_kind("session_open")
    assert not is_extension_kind("")


def test_standard_kinds_set_has_expected_members():
    assert "tool_call" in STANDARD_KINDS
    assert "session_open" in STANDARD_KINDS
    assert "session_close" in STANDARD_KINDS
    assert "policy_check" in STANDARD_KINDS
    assert "x_chain_attested" not in STANDARD_KINDS  # extensions excluded
    assert len(STANDARD_KINDS) == 9


def test_writer_accepts_and_persists_extension_kind(tmp_path: Path):
    """The writer must accept any x_* kind and write it verbatim."""
    priv_pem, pub_pem = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    pub = load_public_key(pub_pem)
    w = AuditLogWriter(
        AuditLogWriterOptions(
            path=str(tmp_path / "audit.jsonl"),
            agent_id="ext-test",
            session_id="sess_ext",
            sign_with=priv,
        )
    )
    w.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    w.append(
        {
            "kind": "x_chain_attested",
            "status": "approved",
            "initiator": "system",
            "detail": {"head": "sha256:abc123", "receipt_id": "att_001"},
        }
    )
    w.append(
        {
            "kind": "x_rate_limit_breached",
            "status": "denied",
            "initiator": "system",
            "detail": {"bucket": "credential", "burst_size": 12},
        }
    )
    w.append({"kind": "session_close", "status": "approved", "initiator": "system"})
    w.close()

    reader = AuditLogReader(str(tmp_path / "audit.jsonl"))
    assert reader.verify_chain() == 4
    assert reader.verify_signatures(pub) == 4

    contents = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    rec1 = json.loads(contents[1])
    rec2 = json.loads(contents[2])
    assert rec1["kind"] == "x_chain_attested"
    assert rec1["detail"]["receipt_id"] == "att_001"
    assert rec2["kind"] == "x_rate_limit_breached"
