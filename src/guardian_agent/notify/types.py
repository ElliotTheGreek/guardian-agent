"""Notification types. SPEC §6."""

from __future__ import annotations

from typing import Any, Literal, Protocol, TypedDict

NotificationKind = Literal[
    "estop_press",
    "estop_clear",
    "policy_breach",
    "gate_denied",
]


class NotificationEvent(TypedDict, total=False):
    """Payload delivered to a notifier."""

    kind: NotificationKind
    user_id: str
    agent_id: str
    ts: str
    source: str
    summary: dict[str, Any]
    canonical_clear_url: str


class Notifier(Protocol):
    """Notifier interface. SPEC §6.1."""

    def notify(self, event: NotificationEvent) -> None:
        """Dispatch the event. May be async via host application's discretion;
        the library's reference adapters are synchronous."""
        ...
