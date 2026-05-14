"""EStopLocal — in-process emergency-stop. SPEC §5.3."""

from __future__ import annotations

import threading
from dataclasses import replace
from datetime import datetime, timezone
from typing import Optional

from ..audit.writer import AuditLogWriter
from ..notify.types import Notifier
from .types import (
    EStopClearOptions,
    EStopClearResult,
    EStopPressOptions,
    EStopPressResult,
    EStopState,
)


class EStopLocal:
    """In-process halt flag with thread-safe state.

    Recovery requires constructing a new EStopLocal — `clear` flips
    `pressed` back to False but the underlying halt event stays set,
    matching SPEC §5.3 "halts are session-terminal."
    """

    def __init__(
        self,
        audit: AuditLogWriter | None = None,
        notifier: Notifier | None = None,
        initially_pressed: bool = False,
    ) -> None:
        self._audit = audit
        self._notifier = notifier
        self._lock = threading.RLock()
        self.halt_event = threading.Event()
        self._state = EStopState()
        if initially_pressed:
            self._state = EStopState(
                pressed=True,
                pressed_at=_iso_now(),
                pressed_reason="initially_pressed",
            )
            self.halt_event.set()

    def is_pressed(self) -> bool:
        with self._lock:
            return self._state.pressed

    def state(self) -> EStopState:
        with self._lock:
            return replace(self._state)

    def press(self, options: EStopPressOptions) -> EStopPressResult:
        with self._lock:
            if self._state.pressed:
                # Idempotent: re-press records audit but does not change state.
                self._record_event("estop_press", options)
                return EStopPressResult(state=replace(self._state))

            self._state = EStopState(
                pressed=True,
                pressed_at=_iso_now(),
                pressed_reason=options.reason,
                pressed_operator_id=options.operator_id,
            )
            self.halt_event.set()
            self._record_event("estop_press", options)
            self._fire_notification("estop_press", options)
            return EStopPressResult(state=replace(self._state))

    def clear(self, options: EStopClearOptions) -> EStopClearResult:
        with self._lock:
            if not self._state.pressed:
                return EStopClearResult(state=replace(self._state))

            self._state = EStopState(
                pressed=False,
                cleared_at=_iso_now(),
            )
            # halt_event stays set per SPEC §5.3.
            self._record_event("estop_clear", options)
            self._fire_notification("estop_clear", options)
            return EStopClearResult(state=replace(self._state))

    # ---- internal ---------------------------------------------------------

    def _record_event(
        self,
        kind: str,
        options: EStopPressOptions | EStopClearOptions,
    ) -> None:
        if self._audit is None:
            return
        detail: dict[str, object] = dict(options.detail)
        if isinstance(options, EStopPressOptions):
            detail["reason"] = options.reason
        if options.operator_id is not None:
            detail["operator_id"] = options.operator_id
        self._audit.append(
            {
                "kind": kind,  # type: ignore[typeddict-item]
                "status": "halted" if kind == "estop_press" else "approved",
                "initiator": options.initiator,
                "detail": detail,
            }
        )

    def _fire_notification(
        self,
        kind: str,
        options: EStopPressOptions | EStopClearOptions,
    ) -> None:
        if self._notifier is None:
            return
        summary: dict[str, object] = dict(options.detail)
        if isinstance(options, EStopPressOptions):
            summary["reason"] = options.reason
        if options.operator_id is not None:
            summary["operator_id"] = options.operator_id
        self._notifier.notify(
            {
                "kind": kind,  # type: ignore[typeddict-item]
                "agent_id": "",
                "ts": _iso_now(),
                "source": "local",
                "summary": summary,
            }
        )


def _iso_now() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
