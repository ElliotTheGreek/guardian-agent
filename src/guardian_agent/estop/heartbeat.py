"""Dead-man's-switch heartbeat. SPEC §6 (v0.4+).

For long-running surfaces (CLI daemon, MCP persistent session, Native main
loop) the agent (or its harness) must call `monitor.heartbeat()` every N
seconds. If no heartbeat arrives within `soft_ms`, an x_heartbeat_warning
audit row is written (no behavior change). If still no heartbeat by
`hard_ms`, the configured EStopLocal is pressed with reason
`heartbeat_missed`.

OPT-IN PER SURFACE. Default OFF. A surface that hasn't wired heartbeat()
calls into its main loop must not enable this — guaranteed day-1 false E-stop.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from ..audit.writer import AuditLogWriter
from .local import EStopLocal
from .types import EStopPressOptions

HeartbeatState = Literal["idle", "soft_missed", "hard_missed"]


@dataclass
class HeartbeatMonitorOptions:
    soft_ms: int
    hard_ms: int
    audit: Optional[AuditLogWriter] = None
    estop: Optional[EStopLocal] = None
    check_interval_ms: Optional[int] = None
    """How often to check; defaults to clamp(50, soft_ms/4, 5000)."""
    now: Optional[Callable[[], float]] = None
    """Time source returning ms since some epoch."""


class HeartbeatMonitor:
    """Per-session watchdog. State: idle → soft_missed → hard_missed."""

    def __init__(self, options: HeartbeatMonitorOptions) -> None:
        if options.soft_ms <= 0:
            raise ValueError("soft_ms must be > 0")
        if options.hard_ms <= options.soft_ms:
            raise ValueError("hard_ms must be > soft_ms")
        self._audit = options.audit
        self._estop = options.estop
        self._soft_ms = options.soft_ms
        self._hard_ms = options.hard_ms
        self._now = options.now or (lambda: time.monotonic() * 1000.0)
        check = options.check_interval_ms
        if check is None:
            check = max(50, min(5000, self._soft_ms // 4))
        self._check_interval_ms = check
        self._lock = threading.Lock()
        self._last_beat: float = self._now()
        self._state: HeartbeatState = "idle"
        self._thread: Optional[threading.Thread] = None
        self._stopped = False
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Start the watchdog thread. Idempotent."""
        with self._lock:
            if self._thread is not None or self._stopped:
                return
            self._last_beat = self._now()
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop the watchdog. Idempotent. Call from supervisor close()."""
        with self._lock:
            self._stopped = True
        self._stop_event.set()
        # Don't join — daemon thread will exit on next tick or process exit.

    def heartbeat(self) -> None:
        """Record a heartbeat. Resets soft_missed → idle. No-op on hard_missed."""
        with self._lock:
            if self._state == "hard_missed":
                return
            self._last_beat = self._now()
            self._state = "idle"

    def state(self) -> dict[str, object]:
        """Current state for tests + introspection."""
        with self._lock:
            return {"state": self._state, "last_beat_ms": self._last_beat}

    def tick(self) -> None:
        """One check iteration. Exposed for deterministic tests."""
        with self._lock:
            if self._stopped:
                return
            elapsed = self._now() - self._last_beat
            if elapsed >= self._hard_ms and self._state != "hard_missed":
                self._state = "hard_missed"
                if self._audit is not None:
                    self._audit.append(
                        {
                            "kind": "x_heartbeat_warning",
                            "status": "halted",
                            "initiator": "system",
                            "detail": {
                                "elapsed_ms": elapsed,
                                "hard_ms": self._hard_ms,
                                "level": "hard",
                            },
                        }
                    )
                if self._estop is not None:
                    self._estop.press(EStopPressOptions(reason="heartbeat_missed", initiator="system"))
                # Once hard-missed, stop checking — the session is halted.
                self._stopped = True
                self._stop_event.set()
                return
            if elapsed >= self._soft_ms and self._state == "idle":
                self._state = "soft_missed"
                if self._audit is not None:
                    self._audit.append(
                        {
                            "kind": "x_heartbeat_warning",
                            "status": "approved",
                            "initiator": "system",
                            "detail": {
                                "elapsed_ms": elapsed,
                                "soft_ms": self._soft_ms,
                                "level": "soft",
                            },
                        }
                    )

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            # Wait either for interval to elapse or stop signal
            if self._stop_event.wait(self._check_interval_ms / 1000.0):
                return
            self.tick()
