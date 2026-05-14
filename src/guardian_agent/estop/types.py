"""EStop types. SPEC §5."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..types import AuditRecordInitiator


@dataclass
class EStopPressOptions:
    """Options to runtime.estop() / hub.press()."""

    reason: str
    operator_id: str | None = None
    initiator: AuditRecordInitiator = "operator"
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class EStopClearOptions:
    """Options to hub.clear() / local.clear()."""

    operator_id: str | None = None
    initiator: AuditRecordInitiator = "operator"
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class EStopState:
    """Press/cleared state of a single user (hub) or runtime (local)."""

    pressed: bool = False
    pressed_at: str | None = None
    pressed_reason: str | None = None
    pressed_operator_id: str | None = None
    cleared_at: str | None = None


@dataclass
class EStopPressResult:
    state: EStopState


@dataclass
class EStopClearResult:
    state: EStopState
    auth_required: bool = False
