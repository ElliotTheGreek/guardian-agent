"""Tests for notify adapters (console, multi, webhook). SPEC §6.3."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from guardian_agent.notify import (
    ConsoleNotifierOptions,
    MultiNotifierOptions,
    NotificationEvent,
    WebhookNotifierOptions,
    WebhookStatusError,
    console_notifier,
    multi_notifier,
    webhook_notifier,
)


def _event(kind: str = "estop_press", **overrides: Any) -> NotificationEvent:
    base: dict[str, Any] = {
        "kind": kind,
        "agent_id": "agent_demo",
        "ts": "2026-05-20T00:00:00.000Z",
        "source": "cli",
        "summary": {"reason": "test"},
    }
    base.update(overrides)
    return base  # type: ignore[return-value]


# ---- console_notifier ---------------------------------------------------


def test_console_notifier_writes_formatted_line():
    buf = io.StringIO()
    notify = console_notifier(ConsoleNotifierOptions(stream=buf, prefix="[g]"))
    notify(_event())
    line = buf.getvalue()
    assert line.startswith("[g] estop_press ")
    assert "agent=agent_demo" in line
    assert "source=cli" in line
    assert "summary=" in line


def test_console_notifier_omits_empty_summary():
    buf = io.StringIO()
    notify = console_notifier(ConsoleNotifierOptions(stream=buf))
    notify(_event(summary={}))
    assert "summary=" not in buf.getvalue()


def test_console_notifier_includes_optional_fields():
    buf = io.StringIO()
    notify = console_notifier(ConsoleNotifierOptions(stream=buf))
    notify(_event(user_id="u-1", canonical_clear_url="https://h/clear"))
    out = buf.getvalue()
    assert "user=u-1" in out
    assert "clear=https://h/clear" in out


# ---- multi_notifier -----------------------------------------------------


def test_multi_notifier_fans_out_to_all():
    seen: list[int] = []

    def make(idx: int):
        def n(_event: NotificationEvent) -> None:
            seen.append(idx)
        return n

    notify = multi_notifier(MultiNotifierOptions(notifiers=[make(0), make(1), make(2)]))
    notify(_event())
    assert seen == [0, 1, 2]


def test_multi_notifier_isolates_failures_and_reports_to_on_error():
    errors: list[tuple[int, str]] = []

    def good(_e: NotificationEvent) -> None:
        pass

    def bad(_e: NotificationEvent) -> None:
        raise RuntimeError("boom")

    def on_err(exc: BaseException, _e: NotificationEvent, idx: int) -> None:
        errors.append((idx, str(exc)))

    notify = multi_notifier(MultiNotifierOptions(notifiers=[good, bad, good], on_error=on_err))
    notify(_event())
    assert errors == [(1, "boom")]


def test_multi_notifier_swallows_on_error_failure():
    """on_error itself raising must not stop other notifiers running."""
    ran: list[int] = []

    def first(_e: NotificationEvent) -> None:
        raise RuntimeError("first")

    def second(_e: NotificationEvent) -> None:
        ran.append(2)

    def on_err(*_a: Any) -> None:
        raise RuntimeError("on_error itself fails")

    notify = multi_notifier(MultiNotifierOptions(notifiers=[first, second], on_error=on_err))
    notify(_event())
    assert ran == [2]


# ---- webhook_notifier ---------------------------------------------------


def test_webhook_notifier_posts_json_body():
    captured: dict[str, Any] = {}

    def fake_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> None:
        captured["url"] = url
        captured["body"] = body
        captured["headers"] = headers
        captured["timeout"] = timeout

    notify = webhook_notifier(
        WebhookNotifierOptions(
            url="https://example.com/hook",
            headers={"x-extra": "v"},
            timeout_seconds=2.5,
            post=fake_post,
        )
    )
    notify(_event(kind="estop_clear"))

    assert captured["url"] == "https://example.com/hook"
    assert captured["timeout"] == 2.5
    assert captured["headers"]["content-type"] == "application/json"
    assert captured["headers"]["x-extra"] == "v"
    decoded = json.loads(captured["body"])
    assert decoded["kind"] == "estop_clear"


def test_webhook_notifier_reports_error_via_callback():
    errors: list[BaseException] = []

    def fake_post(*_a: Any, **_kw: Any) -> None:
        raise WebhookStatusError(500)

    def on_err(exc: BaseException, _e: NotificationEvent) -> None:
        errors.append(exc)

    notify = webhook_notifier(
        WebhookNotifierOptions(url="https://x", on_error=on_err, post=fake_post)
    )
    notify(_event())
    assert len(errors) == 1
    assert isinstance(errors[0], WebhookStatusError)
    assert errors[0].status == 500


def test_webhook_notifier_swallows_when_no_on_error():
    def fake_post(*_a: Any, **_kw: Any) -> None:
        raise WebhookStatusError(503)

    notify = webhook_notifier(WebhookNotifierOptions(url="https://x", post=fake_post))
    # Must NOT raise — notifier failures cannot interrupt press/clear.
    notify(_event())


def test_webhook_status_error_string():
    err = WebhookStatusError(404)
    assert str(err) == "webhook_status_404"
    assert err.status == 404


def test_webhook_default_post_handles_network_error(monkeypatch: pytest.MonkeyPatch):
    """Default urllib path: simulate connection error → routed to on_error."""
    import urllib.error

    def fake_urlopen(*_a: Any, **_kw: Any) -> Any:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    seen: list[BaseException] = []

    def on_err(exc: BaseException, _e: NotificationEvent) -> None:
        seen.append(exc)

    notify = webhook_notifier(
        WebhookNotifierOptions(url="http://127.0.0.1:1/h", on_error=on_err, timeout_seconds=0.1)
    )
    notify(_event())
    assert seen, "expected at least one error reported via on_error"
