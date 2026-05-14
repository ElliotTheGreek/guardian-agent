"""Tests for runtime/runtime.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from guardian_agent.audit.reader import AuditLogReader
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.errors import GuardianHaltedError
from guardian_agent.estop.local import EStopLocal
from guardian_agent.runtime.runtime import (
    GuardianRuntime,
    GuardianRuntimeOptions,
)
from guardian_agent.types import ModelAttribution


def make_audit(tmp_path: Path) -> AuditLogWriter:
    return AuditLogWriter(
        AuditLogWriterOptions(
            path=str(tmp_path / "audit.jsonl"),
            agent_id="a",
            session_id="s",
        )
    )


def read_all(tmp_path: Path) -> list:
    return list(AuditLogReader(str(tmp_path / "audit.jsonl")).records())


def test_opens_session_on_first_call(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))

    @rt.tool
    def inc(x: int) -> int:
        return x + 1

    assert inc(2) == 3
    rt.close()

    recs = read_all(tmp_path)
    assert recs[0]["kind"] == "session_open"
    assert recs[-1]["kind"] == "session_close"


def test_emits_documented_event_sequence(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))

    @rt.tool(name="adder")
    def adder(x: int) -> int:
        return x + 10

    assert adder(5) == 15
    rt.close()

    recs = read_all(tmp_path)
    kinds = [r["kind"] for r in recs]
    assert kinds == [
        "session_open",
        "tool_call",
        "policy_check",
        "tool_result",
        "session_close",
    ]
    result = next(r for r in recs if r["kind"] == "tool_result")
    assert result["status"] == "executed"
    assert result["tool"]["result"] == 15
    assert result["tool"]["duration_ms"] >= 0


def test_records_errored_on_throw(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))

    @rt.tool
    def broken():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        broken()
    rt.close()

    recs = read_all(tmp_path)
    result = next(r for r in recs if r["kind"] == "tool_result")
    assert result["status"] == "errored"
    assert result["detail"]["error"] == "boom"


def test_refuses_tool_call_when_estop_pressed(tmp_path):
    audit = make_audit(tmp_path)
    estop = EStopLocal(audit=audit, initially_pressed=True)
    rt = GuardianRuntime(
        GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit, estop=estop)
    )

    @rt.tool
    def noop():
        return 1

    with pytest.raises(GuardianHaltedError):
        noop()
    rt.close()

    recs = read_all(tmp_path)
    halted = next(r for r in recs if r["kind"] == "policy_check" and r["status"] == "halted")
    assert halted["detail"]["reason"] == "estop"


def test_press_estop_via_runtime(tmp_path):
    audit = make_audit(tmp_path)
    estop = EStopLocal(audit=audit)
    rt = GuardianRuntime(
        GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit, estop=estop)
    )
    rt.press_estop("manual")
    assert estop.is_pressed() is True
    rt.close()


def test_press_estop_without_attached_estop_raises(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))
    with pytest.raises(RuntimeError, match="without an EStopLocal"):
        rt.press_estop("r")
    rt.close()


def test_rejects_reserved_tool_prefixes(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))

    with pytest.raises(ValueError, match="reserved"):
        @rt.tool(name="guardian.foo")
        def f():
            return 1

    with pytest.raises(ValueError, match="reserved"):
        @rt.tool(name="runtime.bar")
        def g():
            return 1

    with pytest.raises(ValueError, match="reserved"):
        @rt.tool(name="internal.baz")
        def h():
            return 1

    rt.close()


def test_records_model_attribution(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))

    @rt.tool(model=ModelAttribution(provider="anthropic", id="claude-opus-4", input_tokens=100, output_tokens=50))
    def t():
        return 1

    t()
    rt.close()

    recs = read_all(tmp_path)
    call = next(r for r in recs if r["kind"] == "tool_call")
    assert call["model"] == {
        "provider": "anthropic",
        "id": "claude-opus-4",
        "input_tokens": 100,
        "output_tokens": 50,
    }


def test_default_model(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(
        GuardianRuntimeOptions(
            agent_id="a",
            session_id="s",
            audit=audit,
            default_model=ModelAttribution(provider="openai", id="gpt-5"),
        )
    )

    @rt.tool
    def t():
        return 1

    t()
    rt.close()

    recs = read_all(tmp_path)
    call = next(r for r in recs if r["kind"] == "tool_call")
    assert call["model"] == {"provider": "openai", "id": "gpt-5"}


def test_records_positional_args_as_object(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))

    @rt.tool
    def t(x: int, y: str) -> str:
        return f"{x}:{y}"

    t(7, "hi")
    rt.close()

    recs = read_all(tmp_path)
    call = next(r for r in recs if r["kind"] == "tool_call")
    assert call["tool"]["args"] == {"0": 7, "1": "hi"}


def test_auto_session_id():
    audit = AuditLogWriter(
        AuditLogWriterOptions(path="/tmp/_unused.jsonl", agent_id="a", session_id="s")
    )
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", audit=audit))
    assert rt.session_id.startswith("sess_")


def test_close_idempotent(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))
    rt.close()
    rt.close()


def test_open_session_idempotent(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))
    rt.open_session()
    rt.open_session()
    rt.close()
    recs = read_all(tmp_path)
    opens = [r for r in recs if r["kind"] == "session_open"]
    assert len(opens) == 1


def test_no_session_close_if_never_opened(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))
    rt.close()
    path = tmp_path / "audit.jsonl"
    if path.exists():
        assert list(AuditLogReader(str(path)).records()) == []


def test_rejects_empty_tool_name(tmp_path):
    audit = make_audit(tmp_path)
    rt = GuardianRuntime(GuardianRuntimeOptions(agent_id="a", session_id="s", audit=audit))
    with pytest.raises(ValueError, match="requires a name"):
        @rt.tool(name="")
        def f():
            return 1
    rt.close()
