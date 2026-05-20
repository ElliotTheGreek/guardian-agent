"""Shared types matching SPEC §2.

Wire-format field names use snake_case throughout to match the canonical
spec; the TypeScript impl uses the same wire names by design.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, TypedDict, Union

SPEC_VERSION = "0.5.0"

# Closed enum of the SPEC §2.4 standard kinds. Extension kinds (SPEC §10) use
# the `x_` prefix and are typed as plain `str`; the union below admits both.
AuditRecordKindStandard = Literal[
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

# AuditRecordKind admits the closed standard set plus any `x_*` extension
# string. We model the extension as plain `str` since Literal cannot express
# "starts with x_". Validation lives at write sites (see writer._validate_kind).
AuditRecordKind = Union[AuditRecordKindStandard, str]

AuditRecordStatus = Literal[
    "pending",
    "approved",
    "denied",
    "executed",
    "errored",
    "halted",
    # SPEC §4.5 (v0.4+): tool dispatch suspended awaiting operator confirmation.
    "pending_operator",
]

AuditRecordInitiator = Literal["operator", "agent", "system"]


@dataclass
class ModelAttribution:
    """Identifies which model issued a tool call. SPEC §2.3 (v0.7+).

    `surface` and `aggregator` extend the basic `provider/id` pair with the
    chain that delivered the call. Rendered as `surface/aggregator/provider/id`
    for glob-based policy rules (see `policy/attribution.py`). Missing
    segments render as `*`.
    """

    provider: str
    id: str
    surface: str | None = None
    aggregator: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


class AuditRecordTool(TypedDict, total=False):
    """Tool sub-object on relevant event kinds."""

    name: str
    args: dict[str, Any]
    result: Any
    duration_ms: float
    # SPEC §13.1 (v0.3+): capability classes for the dispatched tool. Recorded
    # on tool_call and forwarded on tool_result so audit consumers can
    # correlate a call with its declared capabilities without an external table.
    capabilities: list[str]


class AuditRecordModel(TypedDict, total=False):
    """Model sub-object as serialized on the wire (snake_case)."""

    provider: str
    id: str
    surface: str
    aggregator: str
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


def is_extension_kind(kind: str) -> bool:
    """Return True if `kind` is a SPEC §10 `x_*` extension kind."""
    return isinstance(kind, str) and kind.startswith("x_")


# The full list of standard kinds, useful for validation and tests.
STANDARD_KINDS: frozenset[str] = frozenset(AuditRecordKindStandard.__args__)  # type: ignore[attr-defined]
