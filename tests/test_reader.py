"""Tests for audit/reader.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardian_agent.audit.reader import AuditLogReader
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.errors import GuardianIntegrityError


def make_writer(tmp_path: Path) -> AuditLogWriter:
    return AuditLogWriter(
        AuditLogWriterOptions(
            path=str(tmp_path / "audit.jsonl"),
            agent_id="a",
            session_id="s",
        )
    )


def write_sample(tmp_path: Path, count: int = 3) -> Path:
    w = make_writer(tmp_path)
    for i in range(count):
        w.append(
            {
                "kind": "tool_call",
                "status": "pending",
                "initiator": "agent",
                "tool": {"name": f"t{i}", "args": {}},
            }
        )
    w.close()
    return tmp_path / "audit.jsonl"


def test_iterates_records_in_order(tmp_path):
    path = write_sample(tmp_path)
    reader = AuditLogReader(str(path))
    records = list(reader.records())
    assert len(records) == 3
    assert records[0]["tool"]["name"] == "t0"
    assert records[2]["tool"]["name"] == "t2"


def test_verifies_intact_chain(tmp_path):
    path = write_sample(tmp_path, 5)
    reader = AuditLogReader(str(path))
    assert reader.verify_chain() == 5


def test_throws_on_broken_chain(tmp_path):
    path = write_sample(tmp_path, 3)
    lines = [line for line in path.read_text(encoding="utf-8").split("\n") if line]
    parsed = json.loads(lines[1])
    parsed["prev_hash"] = "sha256:deadbeef"
    lines[1] = json.dumps(parsed)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reader = AuditLogReader(str(path))
    with pytest.raises(GuardianIntegrityError):
        reader.verify_chain()


def test_handles_empty_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    reader = AuditLogReader(str(path))
    assert reader.verify_chain() == 0
    assert list(reader.records()) == []


def test_skips_blank_lines(tmp_path):
    path = write_sample(tmp_path, 2)
    content = path.read_text(encoding="utf-8")
    path.write_text(content.replace("\n", "\n\n"), encoding="utf-8")

    reader = AuditLogReader(str(path))
    records = list(reader.records())
    assert len(records) == 2
