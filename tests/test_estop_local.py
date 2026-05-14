"""Tests for estop/local.py."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from guardian_agent.audit.reader import AuditLogReader
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.estop.local import EStopLocal
from guardian_agent.estop.types import EStopClearOptions, EStopPressOptions


def make_audit(tmp_path: Path) -> AuditLogWriter:
    return AuditLogWriter(
        AuditLogWriterOptions(path=str(tmp_path / "audit.jsonl"), agent_id="a", session_id="s")
    )


def test_starts_not_pressed():
    e = EStopLocal()
    assert e.is_pressed() is False
    assert e.state().pressed is False
    assert e.halt_event.is_set() is False


def test_initially_pressed():
    e = EStopLocal(initially_pressed=True)
    assert e.is_pressed() is True
    assert e.halt_event.is_set() is True


def test_press_transitions_state(tmp_path):
    e = EStopLocal()
    r = e.press(EStopPressOptions(reason="manual_halt"))
    assert e.is_pressed() is True
    assert r.state.pressed_reason == "manual_halt"
    assert e.halt_event.is_set() is True


def test_press_records_audit(tmp_path):
    audit = make_audit(tmp_path)
    e = EStopLocal(audit=audit)
    e.press(
        EStopPressOptions(
            reason="shutdown",
            operator_id="op_1",
            detail={"ip": "10.0.0.1"},
        )
    )
    audit.close()

    records = list(AuditLogReader(str(tmp_path / "audit.jsonl")).records())
    assert len(records) == 1
    assert records[0]["kind"] == "estop_press"
    assert records[0]["status"] == "halted"
    assert records[0]["initiator"] == "operator"
    assert records[0]["detail"]["reason"] == "shutdown"
    assert records[0]["detail"]["operator_id"] == "op_1"
    assert records[0]["detail"]["ip"] == "10.0.0.1"


def test_press_idempotent(tmp_path):
    audit = make_audit(tmp_path)
    e = EStopLocal(audit=audit)

    e.press(EStopPressOptions(reason="first"))
    before = e.state()
    e.press(EStopPressOptions(reason="second"))
    after = e.state()
    audit.close()

    assert after.pressed_at == before.pressed_at
    assert after.pressed_reason == "first"

    records = list(AuditLogReader(str(tmp_path / "audit.jsonl")).records())
    assert len(records) == 2  # two audit rows


def test_clear_transitions_but_halt_event_stays_set(tmp_path):
    e = EStopLocal()
    e.press(EStopPressOptions(reason="r"))
    r = e.clear(EStopClearOptions(operator_id="op_1"))

    assert r.state.pressed is False
    assert r.state.cleared_at is not None
    # SPEC §5.3: recovery requires new instance; halt_event stays set.
    assert e.halt_event.is_set() is True


def test_clear_noop_when_not_pressed(tmp_path):
    audit = make_audit(tmp_path)
    e = EStopLocal(audit=audit)
    r = e.clear(EStopClearOptions())
    assert r.state.pressed is False
    audit.close()

    path = tmp_path / "audit.jsonl"
    if path.exists():
        records = list(AuditLogReader(str(path)).records())
        assert len(records) == 0


def test_notifier_fired_on_press_and_clear():
    events: list[str] = []

    class TestNotifier:
        def notify(self, event):
            events.append(event["kind"])

    e = EStopLocal(notifier=TestNotifier())
    e.press(EStopPressOptions(reason="r"))
    e.clear(EStopClearOptions())
    assert events == ["estop_press", "estop_clear"]


def test_custom_initiator(tmp_path):
    audit = make_audit(tmp_path)
    e = EStopLocal(audit=audit)
    e.press(EStopPressOptions(reason="r", initiator="system"))
    audit.close()
    records = list(AuditLogReader(str(tmp_path / "audit.jsonl")).records())
    assert records[0]["initiator"] == "system"


def test_press_without_audit_or_notifier():
    e = EStopLocal()
    e.press(EStopPressOptions(reason="r"))
    assert e.is_pressed() is True
    e.clear(EStopClearOptions())
    assert e.is_pressed() is False


def test_press_with_audit_and_notifier_and_operator_id(tmp_path):
    audit = make_audit(tmp_path)
    events: list[dict] = []

    class TestNotifier:
        def notify(self, event):
            events.append(event)

    e = EStopLocal(audit=audit, notifier=TestNotifier())
    e.press(EStopPressOptions(reason="r", operator_id="op_x"))
    e.clear(EStopClearOptions(operator_id="op_y"))
    audit.close()

    assert events[0]["summary"]["operator_id"] == "op_x"
    assert events[1]["summary"]["operator_id"] == "op_y"

    records = list(AuditLogReader(str(tmp_path / "audit.jsonl")).records())
    assert records[0]["kind"] == "estop_press"
    assert records[0]["status"] == "halted"
    assert records[1]["kind"] == "estop_clear"
    assert records[1]["status"] == "approved"
