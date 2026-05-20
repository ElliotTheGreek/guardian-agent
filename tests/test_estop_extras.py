"""Tests for the four new estop modules: heartbeat, hub, middleware, poller."""

from __future__ import annotations

import io
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.estop.heartbeat import HeartbeatMonitor, HeartbeatMonitorOptions
from guardian_agent.estop.hub import (
    EStopActorContext,
    EStopHub,
    EStopHubOptions,
    InMemoryEStopStateStore,
)
from guardian_agent.estop.local import EStopLocal
from guardian_agent.estop.middleware import (
    EStopMiddlewareOptions,
    create_estop_middleware,
)
from guardian_agent.estop.poller import (
    EStopPollerOptions,
    create_estop_poller,
)
from guardian_agent.estop.types import (
    EStopClearOptions,
    EStopPressOptions,
    EStopState,
)


# ---- helpers -----------------------------------------------------------


def _writer(tmp_path: Path) -> AuditLogWriter:
    return AuditLogWriter(AuditLogWriterOptions(
        path=str(tmp_path / "audit.jsonl"), agent_id="a", session_id="s",
    ))


def _records(tmp_path: Path) -> list[dict[str, Any]]:
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    return [json.loads(l) for l in text.splitlines() if l]


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


# =====================================================================
# HeartbeatMonitor
# =====================================================================


def test_heartbeat_rejects_invalid_thresholds(tmp_path: Path):
    audit = _writer(tmp_path)
    with pytest.raises(ValueError, match="soft_ms"):
        HeartbeatMonitor(HeartbeatMonitorOptions(soft_ms=0, hard_ms=100, audit=audit))
    with pytest.raises(ValueError, match="hard_ms"):
        HeartbeatMonitor(HeartbeatMonitorOptions(soft_ms=100, hard_ms=100, audit=audit))


def test_heartbeat_starts_idle_and_resets_on_beat(tmp_path: Path):
    clock = FakeClock()
    audit = _writer(tmp_path)
    monitor = HeartbeatMonitor(HeartbeatMonitorOptions(
        soft_ms=1000, hard_ms=5000, audit=audit, now=clock,
    ))
    assert monitor.state()["state"] == "idle"
    monitor.heartbeat()
    assert monitor.state()["state"] == "idle"


def test_heartbeat_writes_soft_warning_after_soft_window(tmp_path: Path):
    clock = FakeClock()
    audit = _writer(tmp_path)
    monitor = HeartbeatMonitor(HeartbeatMonitorOptions(
        soft_ms=100, hard_ms=500, audit=audit, now=clock,
    ))
    clock.t += 150  # past soft
    monitor.tick()
    assert monitor.state()["state"] == "soft_missed"
    audit.close()
    warnings = [r for r in _records(tmp_path) if r["kind"] == "x_heartbeat_warning"]
    assert len(warnings) == 1
    assert warnings[0]["detail"]["level"] == "soft"


def test_heartbeat_hard_miss_presses_estop(tmp_path: Path):
    clock = FakeClock()
    audit = _writer(tmp_path)
    estop = EStopLocal(audit=audit)
    monitor = HeartbeatMonitor(HeartbeatMonitorOptions(
        soft_ms=100, hard_ms=500, audit=audit, estop=estop, now=clock,
    ))
    clock.t += 600  # past hard
    monitor.tick()
    assert monitor.state()["state"] == "hard_missed"
    assert estop.is_pressed() is True
    assert estop.state().pressed_reason == "heartbeat_missed"
    audit.close()
    rows = _records(tmp_path)
    kinds = [r["kind"] for r in rows]
    assert "x_heartbeat_warning" in kinds
    assert "estop_press" in kinds


def test_heartbeat_recovers_from_soft_on_new_beat(tmp_path: Path):
    clock = FakeClock()
    audit = _writer(tmp_path)
    monitor = HeartbeatMonitor(HeartbeatMonitorOptions(
        soft_ms=100, hard_ms=500, audit=audit, now=clock,
    ))
    clock.t += 150
    monitor.tick()
    assert monitor.state()["state"] == "soft_missed"
    monitor.heartbeat()
    assert monitor.state()["state"] == "idle"


def test_heartbeat_no_recover_from_hard(tmp_path: Path):
    clock = FakeClock()
    audit = _writer(tmp_path)
    estop = EStopLocal(audit=audit)
    monitor = HeartbeatMonitor(HeartbeatMonitorOptions(
        soft_ms=100, hard_ms=500, audit=audit, estop=estop, now=clock,
    ))
    clock.t += 600
    monitor.tick()
    assert monitor.state()["state"] == "hard_missed"
    monitor.heartbeat()  # no-op
    assert monitor.state()["state"] == "hard_missed"


def test_heartbeat_thread_lifecycle(tmp_path: Path):
    """Smoke test: start + stop the real-thread loop without deadlock."""
    audit = _writer(tmp_path)
    monitor = HeartbeatMonitor(HeartbeatMonitorOptions(
        soft_ms=10_000, hard_ms=20_000, audit=audit,
        check_interval_ms=50,  # fast tick for tests
    ))
    monitor.start()
    time.sleep(0.1)
    monitor.stop()
    audit.close()


# =====================================================================
# EStopHub
# =====================================================================


def _hub(tmp_path: Path, **opts: Any) -> tuple[EStopHub, InMemoryEStopStateStore]:
    audit = _writer(tmp_path)
    store = InMemoryEStopStateStore()
    hub = EStopHub(EStopHubOptions(state=store, audit=audit, **opts))
    return hub, store


def test_hub_press_sets_state_and_emits_audit(tmp_path: Path):
    hub, store = _hub(tmp_path)
    result = hub.press("u1", EStopPressOptions(reason="manual", operator_id="op-1"))
    assert result.state.pressed is True
    assert store.get("u1").pressed is True  # type: ignore[union-attr]
    rows = _records(tmp_path)
    presses = [r for r in rows if r["kind"] == "estop_press"]
    assert len(presses) == 1
    assert presses[0]["detail"]["user_id"] == "u1"
    assert presses[0]["detail"]["reason"] == "manual"


def test_hub_press_idempotent_on_already_pressed(tmp_path: Path):
    hub, _ = _hub(tmp_path)
    first = hub.press("u1", EStopPressOptions(reason="a"))
    second = hub.press("u1", EStopPressOptions(reason="b"))
    # First press wins; reason stays "a"
    assert first.state.pressed_reason == "a"
    assert second.state.pressed_reason == "a"


def test_hub_is_pressed_uses_cache(tmp_path: Path):
    hub, store = _hub(tmp_path, cache_ttl_ms=60_000)
    hub.press("u1", EStopPressOptions(reason="r"))
    assert hub.is_pressed("u1") is True
    # Mutate store out-of-band; cached value should stick until invalidated
    store.set("u1", EStopState(pressed=False))
    assert hub.is_pressed("u1") is True  # still cached
    hub.invalidate_cache("u1")
    assert hub.is_pressed("u1") is False


def test_hub_clear_requires_recent_auth_when_check_present(tmp_path: Path):
    auth_ok = [False]

    def check(_u: str, _o: EStopClearOptions) -> bool:
        return auth_ok[0]

    hub, _ = _hub(tmp_path, recent_auth_check=check)
    hub.press("u1", EStopPressOptions(reason="r"))
    result = hub.clear("u1", EStopClearOptions(operator_id="op-1"))
    assert result.auth_required is True
    assert result.state.pressed is True
    auth_ok[0] = True
    result2 = hub.clear("u1", EStopClearOptions(operator_id="op-1"))
    assert result2.auth_required is False
    assert result2.state.pressed is False


def test_hub_clear_rejects_agent_initiator(tmp_path: Path):
    hub, _ = _hub(tmp_path)
    hub.press("u1", EStopPressOptions(reason="r"))
    result = hub.clear("u1", EStopClearOptions(initiator="agent"))
    assert result.state.pressed is True  # still pressed


def test_hub_status_returns_default_when_unset(tmp_path: Path):
    hub, _ = _hub(tmp_path)
    state = hub.status("never-seen")
    assert state.pressed is False


def test_hub_broadcast_called_on_transitions(tmp_path: Path):
    class FakeBroadcast:
        def __init__(self) -> None:
            self.presses: list[str] = []
            self.clears: list[str] = []

        def broadcast_press(self, user_id: str, state: EStopState) -> None:
            self.presses.append(user_id)

        def broadcast_clear(self, user_id: str, state: EStopState) -> None:
            self.clears.append(user_id)

    bc = FakeBroadcast()
    hub, _ = _hub(tmp_path, broadcast=bc)
    hub.press("u1", EStopPressOptions(reason="r"))
    hub.clear("u1", EStopClearOptions())
    assert bc.presses == ["u1"]
    assert bc.clears == ["u1"]


def test_hub_notifier_failure_does_not_break_press(tmp_path: Path):
    def boom(_event: dict) -> None:
        raise RuntimeError("notifier down")
    hub, _ = _hub(tmp_path, notifier=boom)
    # Must not raise
    hub.press("u1", EStopPressOptions(reason="r"))


# =====================================================================
# EStop middleware
# =====================================================================


def test_middleware_passes_through_when_not_pressed(tmp_path: Path):
    hub, _ = _hub(tmp_path)
    called = [False]

    def app(environ: dict, start_response: Any) -> list[bytes]:
        called[0] = True
        start_response("200 OK", [])
        return [b"hello"]

    wrapped = create_estop_middleware(hub, EStopMiddlewareOptions(
        resolve_user_id=lambda _e: "u1",
    ))(app)
    captured: dict[str, Any] = {}
    def sr(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
    body = wrapped({}, sr)
    assert called[0] is True
    assert captured["status"] == "200 OK"
    assert body == [b"hello"]


def test_middleware_returns_423_when_pressed(tmp_path: Path):
    hub, _ = _hub(tmp_path)
    hub.press("u1", EStopPressOptions(reason="r"))
    app = lambda environ, start_response: [b"ignored"]  # noqa: E731
    wrapped = create_estop_middleware(hub, EStopMiddlewareOptions(
        resolve_user_id=lambda _e: "u1",
    ))(app)
    captured: dict[str, Any] = {}
    def sr(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = headers
    body = wrapped({}, sr)
    assert captured["status"].startswith("423")
    payload = json.loads(body[0].decode("utf-8"))
    assert payload["error"] == "estop_active"


def test_middleware_skips_when_resolve_returns_none(tmp_path: Path):
    hub, _ = _hub(tmp_path)
    hub.press("u1", EStopPressOptions(reason="r"))
    called = [False]
    def app(environ: dict, start_response: Any) -> list[bytes]:
        called[0] = True
        start_response("200 OK", [])
        return [b""]
    wrapped = create_estop_middleware(hub, EStopMiddlewareOptions(
        resolve_user_id=lambda _e: None,
    ))(app)
    wrapped({}, lambda s, h: None)
    assert called[0] is True


def test_middleware_exclude_bypasses_gate(tmp_path: Path):
    hub, _ = _hub(tmp_path)
    hub.press("u1", EStopPressOptions(reason="r"))
    called = [False]
    def app(environ: dict, start_response: Any) -> list[bytes]:
        called[0] = True
        start_response("200 OK", [])
        return [b""]
    wrapped = create_estop_middleware(hub, EStopMiddlewareOptions(
        resolve_user_id=lambda _e: "u1",
        exclude=lambda env: env.get("PATH_INFO") == "/estop/clear",
    ))(app)
    wrapped({"PATH_INFO": "/estop/clear"}, lambda s, h: None)
    assert called[0] is True


# =====================================================================
# EStopPoller
# =====================================================================


def test_poller_fires_on_press_transition():
    presses: list[EStopState] = []
    clears: list[EStopState] = []

    body_seq = [
        b'{"pressed": false}',                 # initial → no fire
        b'{"pressed": true, "pressed_at": "t"}',  # transition → on_press
        b'{"pressed": false, "cleared_at": "t"}',  # transition → on_clear
    ]
    idx = [0]
    def fake_get(_u: str, _h: dict[str, str], _t: float) -> bytes:
        body = body_seq[idx[0]]
        idx[0] = min(idx[0] + 1, len(body_seq) - 1)
        return body

    poller = create_estop_poller(EStopPollerOptions(
        status_url="https://h/status",
        on_press=presses.append,
        on_clear=clears.append,
        get=fake_get,
    ))
    poller.poll()  # initial; no fire
    poller.poll()  # press
    poller.poll()  # clear
    assert len(presses) == 1
    assert len(clears) == 1


def test_poller_reports_invalid_state_shape_to_on_error():
    errors: list[BaseException] = []
    poller = create_estop_poller(EStopPollerOptions(
        status_url="https://h",
        on_press=lambda _: None,
        on_clear=lambda _: None,
        get=lambda *_a, **_kw: b'{"weird": "shape"}',
        on_error=errors.append,
    ))
    poller.poll()
    assert errors
    assert isinstance(errors[0], ValueError)


def test_poller_swallows_get_errors_into_on_error():
    errors: list[BaseException] = []
    def boom(*_a: Any, **_kw: Any) -> bytes:
        raise RuntimeError("network down")
    poller = create_estop_poller(EStopPollerOptions(
        status_url="https://h",
        on_press=lambda _: None,
        on_clear=lambda _: None,
        get=boom,
        on_error=errors.append,
    ))
    poller.poll()
    assert errors
    assert "network down" in str(errors[0])


def test_poller_stop_is_idempotent():
    poller = create_estop_poller(EStopPollerOptions(
        status_url="https://h",
        on_press=lambda _: None,
        on_clear=lambda _: None,
        get=lambda *_a, **_kw: b'{"pressed": false}',
    ))
    poller.stop()
    poller.stop()
