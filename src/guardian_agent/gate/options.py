"""Gate option sets. SPEC §4 (extension).

The fixed 5-button `GateDecision` enum is preserved for back-compat. This
module adds a parallel configurable-option-set system: consumers declare
which buttons to show, with their own ids/labels, and the library carries
the chosen-option id through gate responses + audit records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional

from ..policy.types import PolicyScope
from .types import GateGranularity


@dataclass
class GateOption:
    """One button in an approval prompt."""

    id: str
    scope: PolicyScope
    decision: Literal["allow", "deny"]
    label: Optional[str] = None
    granularity: GateGranularity = "tool"


@dataclass
class GateOptionSet:
    """A named, ordered collection of GateOptions."""

    id: str
    options: list[GateOption] = field(default_factory=list)
    description: Optional[str] = None


FLOWDOT_FIVE = GateOptionSet(
    id="flowdot-five",
    description="FlowDot voice/live tool-call approval (5 buttons).",
    options=[
        GateOption(id="once", label="Allow once", scope="once", decision="allow"),
        GateOption(id="session", label="Allow for this session",
                   scope="session", decision="allow"),
        GateOption(id="tool", label="Always allow this tool",
                   scope="forever", decision="allow"),
        GateOption(id="toolkit", label="Always allow this toolkit",
                   scope="forever", decision="allow", granularity="toolkit"),
        GateOption(id="deny", label="Deny", scope="once", decision="deny"),
    ],
)

CLASSIC_FOUR = GateOptionSet(
    id="classic-four",
    description="FlowDot file-permission scopes (once/session/forever/banned).",
    options=[
        GateOption(id="once", label="Allow once", scope="once", decision="allow"),
        GateOption(id="session", label="Allow for this session",
                   scope="session", decision="allow"),
        GateOption(id="forever", label="Always allow",
                   scope="forever", decision="allow"),
        GateOption(id="banned", label="Never allow",
                   scope="banned", decision="deny"),
    ],
)


def define_gate_option_set(
    id: str,
    options: list[GateOption],
    description: Optional[str] = None,
) -> GateOptionSet:
    """Build a custom option set. Validates non-empty + unique ids."""
    if not options:
        raise ValueError("define_gate_option_set: options must be non-empty")
    seen: set[str] = set()
    for o in options:
        if o.id in seen:
            raise ValueError(f"define_gate_option_set: duplicate option id {o.id!r}")
        seen.add(o.id)
    return GateOptionSet(id=id, options=list(options), description=description)


def find_option(option_set: GateOptionSet, option_id: str) -> Optional[GateOption]:
    """Find an option by id. Returns None when no match."""
    for o in option_set.options:
        if o.id == option_id:
            return o
    return None


def resolve_option(option_set: GateOptionSet, option_id: str) -> GateOption:
    """Resolve a chosen option id; raise on typo."""
    found = find_option(option_set, option_id)
    if found is None:
        valid = ", ".join(o.id for o in option_set.options)
        raise ValueError(
            f"Unknown gate option {option_id!r} for set {option_set.id!r}. Valid: {valid}."
        )
    return found
