"""Two-key operator authorization. SPEC §4.5 (v0.4+).

For tool dispatches that require fresh operator confirmation, the runtime
suspends the call, writes a policy_check { status: pending_operator } row
with a unique `gate_id`, and calls the configured OperatorConfirmationGate.
The gate's response — approved or denied — resolves the suspended call. A
timeout is treated as denied (fail-closed).

The library defines the suspend/resume + timeout mechanism. The actual
transport (HTTP webhook, IPC, LiveKit data channel, Hub password.confirm) is
consumer-supplied. The library ships:

  - OperatorConfirmationGate Protocol (one method: request)
  - callback_operator_gate(fn) — wrap a plain Python callable
  - deny_all_operator_gate() — defensive fallback
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional, Protocol

try:
    from ulid import ULID

    def _ulid() -> str:
        return str(ULID())
except ImportError:  # pragma: no cover
    import uuid

    def _ulid() -> str:
        return uuid.uuid4().hex.upper()

from ..policy.types import PolicyRule, PolicyScope, PolicyWhen

OperatorDecision = Literal["approved", "denied"]


# ---------------------------------------------------------------------------
# Drill-down context + persistence intent (policy_prompt path, v0.2+)
# ---------------------------------------------------------------------------


@dataclass
class PolicyDrilldownContext:
    """Suggested drill-down axes for a policy-prompt gate request."""

    category: str
    exact_identifier: str
    policy_identifier: str
    drilldown_axes: list[dict[str, str]] = field(default_factory=list)
    """Each axis is {"key": ..., "pattern": ..., "label": ...}."""


@dataclass
class PolicyPersistDecision:
    """Operator's persistence intent — mirrors PolicyRule."""

    tool: str
    scope: PolicyScope
    decision: Optional[Literal["allow", "deny"]] = None
    when: Optional[PolicyWhen] = None
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Request + response shapes
# ---------------------------------------------------------------------------


@dataclass
class OperatorConfirmationRequest:
    """Supplied to the gate when a suspended call asks for confirmation."""

    gate_id: str
    tool_name: str
    tool_args: dict[str, Any]
    reason: str
    timeout_ms: int
    agent_id: str
    session_id: str
    policy_context: Optional[PolicyDrilldownContext] = None


@dataclass
class OperatorConfirmationResponse:
    """Returned by the gate. On timeout the library synthesizes denied/timeout."""

    decision: OperatorDecision
    operator_id: Optional[str] = None
    reason: Optional[str] = None
    persist_as: Optional[PolicyPersistDecision] = None


# ---------------------------------------------------------------------------
# Gate protocol + reference adapters
# ---------------------------------------------------------------------------


class OperatorConfirmationGate(Protocol):
    """The contract a consumer implements. One method."""

    def request(self, req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:
        ...


@dataclass
class _CallbackGate:
    fn: Callable[[OperatorConfirmationRequest], OperatorConfirmationResponse]

    def request(self, req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:
        return self.fn(req)


def callback_operator_gate(
    fn: Callable[[OperatorConfirmationRequest], OperatorConfirmationResponse],
) -> OperatorConfirmationGate:
    """Wrap a Python callable as an OperatorConfirmationGate."""
    return _CallbackGate(fn=fn)


@dataclass
class _DenyAllGate:
    reason: str

    def request(self, req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:  # noqa: ARG002
        return OperatorConfirmationResponse(decision="denied", reason=self.reason)


def deny_all_operator_gate(reason: str = "no operator gate configured") -> OperatorConfirmationGate:
    """Reference gate that denies every request. Defensive fallback."""
    return _DenyAllGate(reason=reason)


def new_gate_id() -> str:
    """Generate a fresh gate_id."""
    return "gt_" + _ulid()


def await_with_timeout(
    gate: OperatorConfirmationGate,
    request: OperatorConfirmationRequest,
) -> OperatorConfirmationResponse:
    """Run gate.request(req) on a worker thread; enforce request.timeout_ms.

    Synthesizes `denied / timeout` if the gate didn't respond in time. The
    worker thread is daemon — its overrun work is abandoned.
    """
    result: dict[str, Any] = {}
    done = threading.Event()

    def worker() -> None:
        try:
            result["response"] = gate.request(request)
        except BaseException as exc:  # noqa: BLE001
            result["exception"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    signaled = done.wait(timeout=request.timeout_ms / 1000.0)
    if not signaled:
        return OperatorConfirmationResponse(decision="denied", reason="timeout")
    if "exception" in result:
        return OperatorConfirmationResponse(
            decision="denied",
            reason=f"operator_gate_error:{result['exception']}",
        )
    return result["response"]
