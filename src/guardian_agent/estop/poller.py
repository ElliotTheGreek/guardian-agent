"""create_estop_poller — pull-based safety net. SPEC §5.4.

Polls a status endpoint every N seconds; fires on_press / on_clear on
transitions. Belt-and-braces alongside push notifications.

The Python equivalent uses a daemon thread + threading.Event for stop
signalling. Transport is pluggable for testability.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .types import EStopState

DEFAULT_INTERVAL_MS = 5000

OnTransition = Callable[[EStopState], None]
OnErrorCallback = Callable[[BaseException], None]
GetFn = Callable[[str, dict[str, str], float], bytes]
"""(url, headers, timeout_seconds) → raw JSON bytes (raises on non-2xx)."""


@dataclass
class EStopPollerOptions:
    status_url: str
    on_press: OnTransition
    on_clear: OnTransition
    interval_ms: int = DEFAULT_INTERVAL_MS
    headers: dict[str, str] = field(default_factory=dict)
    get: Optional[GetFn] = None
    on_error: Optional[OnErrorCallback] = None


class EStopPoller:
    """Polls a hub status endpoint; fires callbacks on press/clear transitions."""

    def __init__(self, options: EStopPollerOptions) -> None:
        self._options = options
        self._get = options.get or _default_get
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_pressed: Optional[bool] = None
        self._running = False

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
        self._stop_event.set()

    def poll(self) -> None:
        """Single poll iteration. Exposed for tests."""
        try:
            body_bytes = self._get(
                self._options.status_url,
                dict(self._options.headers),
                self._options.interval_ms / 1000.0,
            )
        except BaseException as exc:  # noqa: BLE001
            if self._options.on_error is not None:
                try:
                    self._options.on_error(exc)
                except BaseException:  # noqa: BLE001
                    pass
            return
        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            if self._options.on_error is not None:
                try:
                    self._options.on_error(exc)
                except BaseException:  # noqa: BLE001
                    pass
            return
        state = _parse_state(payload)
        if state is None:
            if self._options.on_error is not None:
                try:
                    self._options.on_error(ValueError("invalid_state_shape"))
                except BaseException:  # noqa: BLE001
                    pass
            return
        previous = self._last_pressed
        self._last_pressed = state.pressed
        if previous is None:
            return  # first observation; no transition to fire
        if not previous and state.pressed:
            try:
                self._options.on_press(state)
            except BaseException as exc:  # noqa: BLE001
                if self._options.on_error is not None:
                    try:
                        self._options.on_error(exc)
                    except BaseException:  # noqa: BLE001
                        pass
        elif previous and not state.pressed:
            try:
                self._options.on_clear(state)
            except BaseException as exc:  # noqa: BLE001
                if self._options.on_error is not None:
                    try:
                        self._options.on_error(exc)
                    except BaseException:  # noqa: BLE001
                        pass

    def _loop(self) -> None:
        # Kick off immediately
        self.poll()
        while not self._stop_event.wait(self._options.interval_ms / 1000.0):
            self.poll()


def create_estop_poller(options: EStopPollerOptions) -> EStopPoller:
    return EStopPoller(options)


def _default_get(url: str, headers: dict[str, str], timeout_seconds: float) -> bytes:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            if not (200 <= resp.status < 300):
                raise RuntimeError(f"status_{resp.status}")
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"status_{exc.code}") from exc


def _parse_state(payload: Any) -> Optional[EStopState]:
    if not isinstance(payload, dict):
        return None
    pressed = payload.get("pressed")
    if not isinstance(pressed, bool):
        return None
    pressed_at = payload.get("pressed_at") or payload.get("pressedAt")
    cleared_at = payload.get("cleared_at") or payload.get("clearedAt")
    if pressed_at is not None and not isinstance(pressed_at, str):
        return None
    if cleared_at is not None and not isinstance(cleared_at, str):
        return None
    return EStopState(
        pressed=pressed,
        pressed_at=pressed_at if isinstance(pressed_at, str) else None,
        cleared_at=cleared_at if isinstance(cleared_at, str) else None,
    )
