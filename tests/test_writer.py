"""Tests for audit/writer.py."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from guardian_agent.audit.chain import GENESIS_HASH, compute_record_hash
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions


def make_writer(tmp_path: Path) -> AuditLogWriter:
    return AuditLogWriter(
        AuditLogWriterOptions(
            path=str(tmp_path / "audit.jsonl"),
            agent_id="a",
            session_id="s",
        )
    )


def test_single_record_genesis_prev_hash(tmp_path):
    w = make_writer(tmp_path)
    r = w.append(
        {
            "kind": "tool_call",
            "status": "pending",
            "initiator": "agent",
            "tool": {"name": "list_accounts", "args": {"broker": "x"}},
        }
    )
    w.close()

    assert r["prev_hash"] == GENESIS_HASH
    assert r["event_id"].startswith("evt_")
    assert r["agent_id"] == "a"
    assert r["signature"] is None

    contents = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    lines = [line for line in contents.split("\n") if line]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["event_id"] == r["event_id"]


def test_chains_records_via_prev_hash(tmp_path):
    w = make_writer(tmp_path)
    r1 = w.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    r2 = w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    r3 = w.append({"kind": "tool_result", "status": "executed", "initiator": "system"})
    w.close()

    assert r1["prev_hash"] == GENESIS_HASH
    assert r2["prev_hash"] == compute_record_hash(r1)
    assert r3["prev_hash"] == compute_record_hash(r2)
    assert w.tip_hash == compute_record_hash(r3)


def test_recovers_tip_on_reopen(tmp_path):
    w1 = make_writer(tmp_path)
    r1 = w1.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    w1.close()

    w2 = make_writer(tmp_path)
    w2.open()
    assert w2.tip_hash == compute_record_hash(r1)
    r2 = w2.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})
    assert r2["prev_hash"] == compute_record_hash(r1)
    w2.close()


def test_returns_genesis_on_empty_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    w = AuditLogWriter(
        AuditLogWriterOptions(path=str(path), agent_id="a", session_id="s")
    )
    w.open()
    assert w.tip_hash == GENESIS_HASH
    w.close()


def test_returns_genesis_on_blank_lines_only(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("\n\n\n", encoding="utf-8")
    w = AuditLogWriter(
        AuditLogWriterOptions(path=str(path), agent_id="a", session_id="s")
    )
    w.open()
    assert w.tip_hash == GENESIS_HASH
    w.close()


def test_open_idempotent(tmp_path):
    w = make_writer(tmp_path)
    w.open()
    w.open()
    w.close()


def test_close_idempotent(tmp_path):
    w = make_writer(tmp_path)
    w.close()
    w.close()


def test_refuses_append_after_close(tmp_path):
    w = make_writer(tmp_path)
    w.close()
    with pytest.raises(RuntimeError, match="closed"):
        w.append({"kind": "tool_call", "status": "pending", "initiator": "agent"})


def test_per_append_override(tmp_path):
    w = make_writer(tmp_path)
    r = w.append(
        {
            "agent_id": "override",
            "session_id": "sess_override",
            "kind": "tool_call",
            "status": "pending",
            "initiator": "agent",
        }
    )
    assert r["agent_id"] == "override"
    assert r["session_id"] == "sess_override"
    w.close()


def test_model_attribution_recorded(tmp_path):
    w = make_writer(tmp_path)
    r = w.append(
        {
            "kind": "tool_call",
            "status": "pending",
            "initiator": "agent",
            "model": {"provider": "anthropic", "id": "claude-opus-4"},
        }
    )
    assert r["model"] == {"provider": "anthropic", "id": "claude-opus-4"}
    w.close()


def test_detail_recorded(tmp_path):
    w = make_writer(tmp_path)
    r = w.append(
        {
            "kind": "estop_press",
            "status": "halted",
            "initiator": "operator",
            "detail": {"reason": "manual", "ip": "127.0.0.1"},
        }
    )
    assert r["detail"]["reason"] == "manual"
    w.close()


def test_serializes_concurrent_appends(tmp_path):
    w = make_writer(tmp_path)

    results = []

    def worker(i: int):
        r = w.append(
            {
                "kind": "tool_call",
                "status": "pending",
                "initiator": "agent",
                "tool": {"name": f"t{i}", "args": {}},
            }
        )
        results.append(r)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    w.close()

    # All records form a valid chain (in some order).
    # Verify by re-reading.
    contents = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    lines = [line for line in contents.split("\n") if line]
    expected_prev = GENESIS_HASH
    for line in lines:
        rec = json.loads(line)
        assert rec["prev_hash"] == expected_prev
        expected_prev = compute_record_hash(rec)
