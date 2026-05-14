"""Tests for errors.py."""

from __future__ import annotations

from guardian_agent.errors import (
    GuardianConfigError,
    GuardianHaltedError,
    GuardianIntegrityError,
)


def test_halted_with_reason_and_operator():
    e = GuardianHaltedError("halt", reason="manual", operator_id="op_1")
    assert str(e) == "halt"
    assert e.reason == "manual"
    assert e.operator_id == "op_1"


def test_halted_message_only():
    e = GuardianHaltedError("halt")
    assert e.reason is None
    assert e.operator_id is None


def test_config_message():
    e = GuardianConfigError("bad config")
    assert str(e) == "bad config"


def test_integrity_with_detail():
    e = GuardianIntegrityError("bad chain", detail="x")
    assert str(e) == "bad chain"
    assert e.detail == "x"


def test_integrity_message_only():
    e = GuardianIntegrityError("bad chain")
    assert e.detail is None
