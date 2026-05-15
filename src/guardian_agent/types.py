"""Shared types matching SPEC §2.

Wire-format field names use snake_case throughout to match the canonical
spec; the TypeScript impl uses the same wire names by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict

SPEC_VERSION = "0.5.0"

AuditRecordKind = Literal[
    "session_open",
    "tool_call",
    "gate_request",
    "gate_response",
    "policy_check",
    "tool_result",
    "estop_press",
    "estop_clear",
    "session_close",
]

AuditRecordStatus = Literal[
    "pending",
    "approved",
    "denied",
    "executed",
    "errored",
    "halted",
]

AuditRecordInitiator = Literal["operator", "agent", "system"]


@dataclass
class ModelAttribution:
    """Identifies which model issued a tool call.  SPEC §2.3."""

    provider: str
    id: str
    input_tokens: int | None = None
    output_tokens: int | None = None


class AuditRecordTool(TypedDict, total=False):
    """Tool sub-object on relevant event kinds."""

    name: str
    args: dict[str, Any]
    result: Any
    duration_ms: float


class AuditRecordModel(TypedDict, total=False):
    """Model sub-object as serialized on the wire (snake_case)."""

    provider: str
    id: str
    input_tokens: int
    output_tokens: int


class AuditRecord(TypedDict, total=False):
    """Audit record matching SPEC §2.2 wire format."""

    v: str
    event_id: str
    ts: str
    agent_id: str
    session_id: str
    kind: AuditRecordKind
    tool: AuditRecordTool
    model: AuditRecordModel
    status: AuditRecordStatus
    initiator: AuditRecordInitiator
    prev_hash: str
    signature: str | None
    detail: dict[str, Any]


class AuditRecordInput(TypedDict, total=False):
    """Fields a caller supplies; the writer fills in v/event_id/ts/prev_hash."""

    agent_id: str
    session_id: str
    kind: AuditRecordKind
    tool: AuditRecordTool
    model: AuditRecordModel
    status: AuditRecordStatus
    initiator: AuditRecordInitiator
    detail: dict[str, Any]
