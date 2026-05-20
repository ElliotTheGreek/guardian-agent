"""Gate request/response types. SPEC §4.

The Python reference impl is synchronous: gate adapters are plain callables
returning a response. Hosts that need async can wrap their async function and
call .result() on the future, or use a queue-based callback gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

from ..types import ModelAttribution

GateGranularity = Literal["tool", "toolkit", "category"]
GateDecision = Literal["allow", "allow_session", "allow_forever", "deny", "ban_forever"]

VALID_DECISIONS: tuple[str, ...] = (
    "allow", "allow_session", "allow_forever", "deny", "ban_forever",
)
VALID_GRANULARITIES: tuple[str, ...] = ("tool", "toolkit", "category")


@dataclass
class GateRequest:
    event_id: str
    tool_name: str
    tool_args: dict[str, Any]
    agent_id: str
    session_id: str
    granularity: GateGranularity = "tool"
    model: Optional[ModelAttribution] = None
    context: Optional[str] = None
    timeout_ms: Optional[int] = None


@dataclass
class GateResponse:
    decision: GateDecision
    granularity: GateGranularity
    reason: Optional[str] = None
    operator_id: Optional[str] = None


ApprovalGate = Callable[[GateRequest], GateResponse]
"""Synchronous gate callable. Implementations may block as long as they want."""
