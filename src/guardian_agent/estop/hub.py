"""EStopHub — hub-coordinated emergency-stop adapter. SPEC §5.4.

Pluggable state store (in-memory by default; consumers supply SQL/Redis/etc).
Per-user scoping. 1-second cache TTL on is_pressed reads. Notifier fan-out on
press AND clear.

Python equivalent of the TS EStopHub. All async methods of the TS impl
become sync here — the state store, notifier, and broadcast adapters are
expected to be sync (a future asyncio variant can come later).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Protocol

from ..audit.writer import AuditLogWriter
from ..notify.types import NotificationEvent, NotificationKind
from .types import EStopClearOptions, EStopClearResult, EStopPressOptions, EStopPressResult, EStopState

DEFAULT_CACHE_TTL_MS = 1000


class EStopStateStore(Protocol):
    """Backing store for hub state. In-memory by default."""

    def get(self, user_id: str) -> Optional[EStopState]:
        ...

    def set(self, user_id: str, state: EStopState) -> None:
        ...


class EStopBroadcastChannel(Protocol):
    """Push-side channel that fans out press/clear to live daemons."""

    def broadcast_press(self, user_id: str, state: EStopState) -> None:
        ...

    def broadcast_clear(self, user_id: str, state: EStopState) -> None:
        ...


@dataclass
class EStopActorContext:
    source: str = "hub"
    ip: Optional[str] = None
    user_agent: Optional[str] = None


NotifierFn = Callable[[NotificationEvent], None]
RecentAuthCheck = Callable[[str, EStopClearOptions], bool]


@dataclass
class EStopHubOptions:
    state: EStopStateStore
    audit: AuditLogWriter
    notifier: Optional[NotifierFn] = None
    broadcast: Optional[EStopBroadcastChannel] = None
    cache_ttl_ms: int = DEFAULT_CACHE_TTL_MS
    recent_auth_check: Optional[RecentAuthCheck] = None
    canonical_clear_url: Optional[str] = None


class EStopHub:
    """Per-user emergency-stop coordinator. SPEC §5.4."""

    def __init__(self, options: EStopHubOptions) -> None:
        self._state = options.state
        self._audit = options.audit
        self._notifier = options.notifier
        self._broadcast = options.broadcast
        self._cache_ttl_ms = options.cache_ttl_ms
        self._recent_auth_check = options.recent_auth_check
        self._canonical_clear_url = options.canonical_clear_url
        self._cache_lock = threading.Lock()
        self._cache: dict[str, tuple[bool, float]] = {}  # user_id → (pressed, expires_at_ms)

    def is_pressed(self, user_id: str) -> bool:
        """Cached hot-path check used by the middleware."""
        now_ms = time.monotonic() * 1000.0
        with self._cache_lock:
            entry = self._cache.get(user_id)
            if entry is not None and entry[1] > now_ms:
                return entry[0]
        state = self._state.get(user_id)
        pressed = bool(state and state.pressed)
        with self._cache_lock:
            self._cache[user_id] = (pressed, now_ms + self._cache_ttl_ms)
        return pressed

    def status(self, user_id: str) -> EStopState:
        return self._state.get(user_id) or EStopState()

    def press(
        self,
        user_id: str,
        options: EStopPressOptions,
        actor: Optional[EStopActorContext] = None,
    ) -> EStopPressResult:
        actor = actor or EStopActorContext()
        initiator = options.initiator
        existing = self._state.get(user_id) or EStopState()
        new_state = existing
        if not existing.pressed:
            new_state = EStopState(
                pressed=True,
                pressed_at=_iso_now(),
                pressed_reason=options.reason,
                pressed_operator_id=options.operator_id,
            )
            self._state.set(user_id, new_state)
            self.invalidate_cache(user_id)

        detail: dict[str, Any] = {
            "user_id": user_id,
            "source": actor.source,
            "reason": options.reason,
        }
        if options.operator_id is not None:
            detail["operator_id"] = options.operator_id
        if actor.ip is not None:
            detail["ip"] = actor.ip
        if actor.user_agent is not None:
            detail["user_agent"] = actor.user_agent
        if options.detail:
            detail.update(options.detail)
        self._audit.append(
            {"kind": "estop_press", "status": "halted", "initiator": initiator, "detail": detail}
        )

        if self._broadcast is not None and not existing.pressed:
            self._broadcast.broadcast_press(user_id, new_state)

        self._fire_notification(
            "estop_press", user_id, actor,
            {
                "reason": options.reason,
                **({"operator_id": options.operator_id} if options.operator_id is not None else {}),
                **(options.detail or {}),
            },
        )
        return EStopPressResult(state=new_state)

    def clear(
        self,
        user_id: str,
        options: EStopClearOptions,
        actor: Optional[EStopActorContext] = None,
    ) -> EStopClearResult:
        actor = actor or EStopActorContext()
        initiator = options.initiator
        if initiator == "agent":
            # SPEC §7: agent-initiated clear MUST be rejected.
            current = self._state.get(user_id) or EStopState()
            return EStopClearResult(state=current, auth_required=False)

        if self._recent_auth_check is not None:
            if not self._recent_auth_check(user_id, options):
                current = self._state.get(user_id) or EStopState()
                return EStopClearResult(state=current, auth_required=True)

        existing = self._state.get(user_id) or EStopState()
        if not existing.pressed:
            return EStopClearResult(state=existing)

        cleared = EStopState(pressed=False, cleared_at=_iso_now())
        self._state.set(user_id, cleared)
        self.invalidate_cache(user_id)

        detail: dict[str, Any] = {"user_id": user_id, "source": actor.source}
        if options.operator_id is not None:
            detail["operator_id"] = options.operator_id
        if actor.ip is not None:
            detail["ip"] = actor.ip
        if actor.user_agent is not None:
            detail["user_agent"] = actor.user_agent
        if options.detail:
            detail.update(options.detail)
        self._audit.append(
            {"kind": "estop_clear", "status": "approved", "initiator": initiator, "detail": detail}
        )

        if self._broadcast is not None:
            self._broadcast.broadcast_clear(user_id, cleared)

        self._fire_notification(
            "estop_clear", user_id, actor,
            {
                **({"operator_id": options.operator_id} if options.operator_id is not None else {}),
                **(options.detail or {}),
            },
        )
        return EStopClearResult(state=cleared)

    def invalidate_cache(self, user_id: str) -> None:
        with self._cache_lock:
            self._cache.pop(user_id, None)

    def invalidate_all_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    def _fire_notification(
        self,
        kind: NotificationKind,
        user_id: str,
        actor: EStopActorContext,
        summary: dict[str, Any],
    ) -> None:
        if self._notifier is None:
            return
        event: NotificationEvent = {  # type: ignore[assignment]
            "kind": kind,
            "user_id": user_id,
            "agent_id": "",
            "ts": _iso_now(),
            "source": actor.source,
            "summary": summary,
        }
        if self._canonical_clear_url is not None:
            event["canonical_clear_url"] = self._canonical_clear_url
        try:
            self._notifier(event)
        except BaseException:  # noqa: BLE001 — notifier failure never blocks press/clear
            pass


class InMemoryEStopStateStore:
    """Reference in-memory state store. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: dict[str, EStopState] = {}

    def get(self, user_id: str) -> Optional[EStopState]:
        with self._lock:
            return self._states.get(user_id)

    def set(self, user_id: str, state: EStopState) -> None:
        with self._lock:
            self._states[user_id] = state


def _iso_now() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
