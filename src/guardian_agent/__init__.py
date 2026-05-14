"""guardian-agent — a runtime supervisor for tool-using LLM agents.

Pre-alpha. The public surface here matches the README quickstart and SPEC.md
v0.1.0 contract, but the implementation is a stub. Calling into the runtime
today raises NotImplementedError with a pointer at the relevant spec section.

Land order (see ROADMAP.md):
    v0.1.0  audit log writer (this file's TODOs)
    v0.2.0  policy enforcement
    v0.3.0  HITL approval gate adapters
    v0.4.0  emergency-stop + guardian-eval companion
    v0.5.0  signed audit logs
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Optional

__version__ = "0.1.0"
__spec_version__ = "0.1.0"

__all__ = [
    "GuardianRuntime",
    "GuardianHalted",
    "Policy",
    "GateRequest",
    "GateResponse",
    "ModelAttribution",
    "cli_approval_gate",
    "async_callback_gate",
    "programmatic_gate",
]


class GuardianHalted(Exception):
    """Raised inside a wrapped tool call after `runtime.estop()` fires.

    See SPEC.md §5 (Emergency-stop).
    """


@dataclass
class ModelAttribution:
    """Identifies which model issued a given tool call.  SPEC.md §2.3."""

    provider: str
    id: str
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None


@dataclass
class GateRequest:
    """Payload presented to an approval gate.  SPEC.md §4.1."""

    event_id: str
    tool_name: str
    tool_args: dict[str, Any]
    agent_id: str
    session_id: str
    model: Optional[ModelAttribution] = None
    context: Optional[str] = None


@dataclass
class GateResponse:
    """Operator decision returned from an approval gate.  SPEC.md §4.1-§4.2."""

    decision: Literal["allow", "allow_session", "always_allow", "deny"]
    reason: Optional[str] = None
    operator_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class Policy:
    """Tool-permission policy loaded from YAML.  See SPEC.md §3."""

    def __init__(self) -> None:
        # TODO(v0.2): populate from parsed YAML
        self._raw: dict[str, Any] = {}

    @classmethod
    def from_yaml(cls, path: str) -> "Policy":
        # TODO(v0.2): real YAML parse + schema validation
        p = cls()
        p._raw = {"_path": str(Path(path))}
        return p


# ---------------------------------------------------------------------------
# Approval gate adapters
# ---------------------------------------------------------------------------


def cli_approval_gate(request: GateRequest) -> GateResponse:
    """Synchronous stdin-based approval gate.  SPEC.md §4.3."""
    raise NotImplementedError(
        "cli_approval_gate lands in v0.3.0. See ROADMAP.md."
    )


def async_callback_gate(url: str) -> Callable[[GateRequest], GateResponse]:
    """Returns an approval-gate callable that POSTs requests to `url`."""
    raise NotImplementedError(
        "async_callback_gate lands in v0.3.0. See ROADMAP.md."
    )


def programmatic_gate(
    handler: Callable[[GateRequest], GateResponse],
) -> Callable[[GateRequest], GateResponse]:
    """Wraps a Python callable as an approval gate adapter."""
    raise NotImplementedError(
        "programmatic_gate lands in v0.3.0. See ROADMAP.md."
    )


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------


class GuardianRuntime:
    """The runtime supervisor.

    Wraps tool functions, enforces policy, optionally invokes the approval
    gate, writes audit-log records per SPEC.md §2, and honors emergency-stop
    per SPEC.md §5.

    Pre-alpha: this is a stub.  v0.1.0 will implement the audit log path.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        session_id: str,
        audit_log: str,
        policy: Policy,
        approval_gate: Optional[Callable[[GateRequest], GateResponse]] = None,
    ) -> None:
        self.agent_id = agent_id
        self.session_id = session_id
        self.audit_log_path = audit_log
        self.policy = policy
        self.approval_gate = approval_gate
        # TODO(v0.1): open audit log; emit session_open event

    def tool(self, fn: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator that places a tool function under runtime supervision."""

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # TODO(v0.1): emit tool_call event; emit tool_result event
            # TODO(v0.2): consult policy; emit policy_check; possibly deny
            # TODO(v0.3): if mode == gate, invoke approval_gate
            # TODO(v0.4): check halt flag; raise GuardianHalted if set
            raise NotImplementedError(
                "runtime.tool wrapper lands in v0.1.0. See ROADMAP.md."
            )

        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        return wrapper

    def estop(
        self,
        reason: str,
        operator_id: Optional[str] = None,
    ) -> None:
        """Trip the emergency-stop primitive.  SPEC.md §5."""
        # TODO(v0.4): set halt flag; emit estop event; flush log
        raise NotImplementedError(
            "estop lands in v0.4.0. See ROADMAP.md."
        )
