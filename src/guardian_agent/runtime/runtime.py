"""GuardianRuntime — the orchestrator. SPEC §4 / §5.

v0.2+ wires every safety primitive in the library:

  - Honeytokens (SPEC §11): args + tool-name scanned BEFORE estop check; hit
    → x_honeytoken_triggered + estop press + GuardianHaltedError.
  - EStop (SPEC §5): pressed → policy_check halted + GuardianHaltedError.
  - Two-key operator gate (SPEC §4.5): tool marked
    requiresOperatorConfirmation suspends with pending_operator until the
    operator gate responds. Timeout treated as denied (fail-closed).
  - Capability window (SPEC §4 ext): every dispatched call recorded; rule
    matches emit x_capability_yellow (v0.8: no behavior change).
  - Policy gate (SPEC §3): when configured + policy_identifier_fn provided,
    evaluate(allow/deny/prompt). Prompt routes through operator gate with a
    drill-down policy_context; response may carry persist_as to persist a
    new rule before resuming.

The runtime is sync (matches the Python writer + estop model). Each method
calls in sequence; concurrency is the caller's responsibility.
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Protocol, TypeVar

try:
    from ulid import ULID

    def _ulid() -> str:
        return str(ULID())
except ImportError:  # pragma: no cover
    import uuid

    def _ulid() -> str:
        return uuid.uuid4().hex.upper()

from ..audit.writer import AuditLogWriter
from ..errors import GuardianHaltedError, PolicyDenialError
from ..estop.local import EStopLocal
from ..gate.two_key import (
    OperatorConfirmationGate,
    OperatorConfirmationRequest,
    PolicyDrilldownContext,
    await_with_timeout,
    new_gate_id,
)
from ..policy.types import PolicyEvaluation, PolicyRule
from ..types import AuditRecordInitiator, ModelAttribution
from .capability import (
    CapabilityClass,
    CapabilityRule,
    CapabilityWindow,
    CapabilityWindowOptions,
)
from .honeytokens import HoneytokenSet, check_honeytoken

F = TypeVar("F", bound=Callable[..., Any])


class PolicyGate(Protocol):
    """The shape the runtime consumes. See policy/gate_adapter.py."""

    def evaluate(
        self, tool_name: str, model: Optional[ModelAttribution] = None
    ) -> PolicyEvaluation:
        ...

    def persist(self, rule: PolicyRule) -> None:  # optional
        ...


PolicyIdentifierFn = Callable[["PolicyIdentifierCall"], Optional[str]]


@dataclass
class PolicyIdentifierCall:
    name: str
    args: dict[str, Any]
    model: Optional[ModelAttribution]


@dataclass
class ToolOptions:
    """Options for a wrapped tool."""

    name: Optional[str] = None
    model: Optional[ModelAttribution] = None
    capabilities: Optional[list[CapabilityClass]] = None
    requires_operator_confirmation: bool = False
    operator_confirmation_reason: Optional[str] = None
    operator_confirmation_timeout_ms: Optional[int] = None


@dataclass
class GuardianRuntimeOptions:
    """Constructor options for GuardianRuntime."""

    agent_id: str
    audit: AuditLogWriter
    session_id: Optional[str] = None
    estop: Optional[EStopLocal] = None
    default_model: Optional[ModelAttribution] = None
    honeytokens: Optional[HoneytokenSet] = None
    capability_rules: Optional[list[CapabilityRule]] = None
    operator_gate: Optional[OperatorConfirmationGate] = None
    operator_timeout_ms: int = 5 * 60 * 1000
    policy: Optional[PolicyGate] = None
    policy_identifier: Optional[PolicyIdentifierFn] = None


class GuardianRuntime:
    """Orchestrator that wraps tool calls with audit + safety enforcement."""

    def __init__(self, options: GuardianRuntimeOptions) -> None:
        self.agent_id = options.agent_id
        self.session_id = options.session_id or "sess_" + _ulid()
        self.audit = options.audit
        self.estop = options.estop
        self.default_model = options.default_model
        self.honeytokens = options.honeytokens
        self.capability_window: Optional[CapabilityWindow] = None
        if options.capability_rules:
            self.capability_window = CapabilityWindow(
                CapabilityWindowOptions(rules=list(options.capability_rules))
            )
        self.operator_gate = options.operator_gate
        self.operator_timeout_ms = options.operator_timeout_ms
        self.policy = options.policy
        self.policy_identifier = options.policy_identifier
        self._session_opened = False
        self._closed = False

    def open_session(self) -> None:
        """Emit session_open. Idempotent."""
        if self._session_opened:
            return
        self._session_opened = True
        self.audit.append(
            {"kind": "session_open", "status": "approved", "initiator": "system"}
        )

    def tool(
        self,
        fn: Optional[F] = None,
        *,
        name: Optional[str] = None,
        model: Optional[ModelAttribution] = None,
        capabilities: Optional[list[CapabilityClass]] = None,
        requires_operator_confirmation: bool = False,
        operator_confirmation_reason: Optional[str] = None,
        operator_confirmation_timeout_ms: Optional[int] = None,
    ) -> Any:
        """Wrap a function as a supervised tool. Usable as decorator or factory."""
        opts = ToolOptions(
            name=name,
            model=model,
            capabilities=capabilities,
            requires_operator_confirmation=requires_operator_confirmation,
            operator_confirmation_reason=operator_confirmation_reason,
            operator_confirmation_timeout_ms=operator_confirmation_timeout_ms,
        )
        if fn is None:
            def wrapper(inner_fn: F) -> F:
                return self._wrap_tool(inner_fn, opts)  # type: ignore[return-value]
            return wrapper
        return self._wrap_tool(fn, opts)

    def _wrap_tool(self, fn: Callable[..., Any], opts: ToolOptions) -> Callable[..., Any]:
        tool_name = opts.name if opts.name is not None else fn.__name__
        if not tool_name:
            raise ValueError("tool() requires a name (either fn.__name__ or opts.name)")
        if (
            tool_name.startswith("guardian.")
            or tool_name.startswith("runtime.")
            or tool_name.startswith("internal.")
        ):
            raise ValueError(f'tool name "{tool_name}" uses a reserved prefix')

        model = opts.model or self.default_model
        capabilities = list(opts.capabilities) if opts.capabilities is not None else ["unknown"]

        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not self._session_opened:
                self.open_session()
            args_obj = _args_to_object(args, kwargs)

            # 1. Honeytoken check — fires BEFORE estop. A hit is itself a halt trigger.
            if self.honeytokens is not None:
                hit = check_honeytoken(self.honeytokens, tool_name, args_obj)
                if hit is not None:
                    detail: dict[str, Any] = {
                        "set_id": self.honeytokens.id,
                        "hit_kind": hit.kind,
                    }
                    if hit.kind == "value_in_args" and hit.token_id is not None:
                        detail["token_id"] = hit.token_id
                    if hit.kind == "phantom_tool" and hit.tool_name is not None:
                        detail["tool_name"] = hit.tool_name
                    self.audit.append(
                        {
                            "kind": "x_honeytoken_triggered",
                            "status": "halted",
                            "initiator": "system",
                            "tool": {"name": tool_name, "args": args_obj, "capabilities": capabilities},
                            "detail": detail,
                        }
                    )
                    if self.estop is not None:
                        from ..estop.types import EStopPressOptions
                        reason = (
                            f"honeytoken:{hit.token_id}"
                            if hit.kind == "value_in_args"
                            else f"honeytoken:phantom_tool:{hit.tool_name}"
                        )
                        self.estop.press(EStopPressOptions(reason=reason, initiator="system"))
                    raise GuardianHaltedError(
                        f"tool call rejected: honeytoken triggered ({hit.kind})",
                        reason="honeytoken",
                    )

            # 2. EStop check — refuse before any audit churn.
            if self.estop is not None and self.estop.is_pressed():
                self.audit.append(
                    {
                        "kind": "policy_check",
                        "status": "halted",
                        "initiator": "system",
                        "tool": {"name": tool_name, "args": args_obj, "capabilities": capabilities},
                        "detail": {"reason": "estop"},
                    }
                )
                raise GuardianHaltedError(
                    "tool call rejected: emergency stop active",
                    reason=self.estop.state().pressed_reason,
                )

            # 3. Two-key operator authorization (requires_operator_confirmation=True).
            if opts.requires_operator_confirmation:
                if self.operator_gate is None:
                    raise RuntimeError(
                        f"tool {tool_name!r} requires operator confirmation "
                        "but no operator_gate is configured on the runtime"
                    )
                gate_id = new_gate_id()
                timeout_ms = (
                    opts.operator_confirmation_timeout_ms
                    if opts.operator_confirmation_timeout_ms is not None
                    else self.operator_timeout_ms
                )
                reason = opts.operator_confirmation_reason or "unspecified"
                self.audit.append(
                    {
                        "kind": "policy_check",
                        "status": "pending_operator",
                        "initiator": "system",
                        "tool": {"name": tool_name, "args": args_obj, "capabilities": capabilities},
                        "detail": {"gate_id": gate_id, "timeout_ms": timeout_ms, "reason": reason},
                    }
                )
                response = await_with_timeout(
                    self.operator_gate,
                    OperatorConfirmationRequest(
                        gate_id=gate_id,
                        tool_name=tool_name,
                        tool_args=args_obj,
                        reason=reason,
                        timeout_ms=timeout_ms,
                        agent_id=self.agent_id,
                        session_id=self.session_id,
                    ),
                )
                resolution_detail: dict[str, Any] = {"gate_id": gate_id}
                if response.operator_id is not None:
                    resolution_detail["operator_id"] = response.operator_id
                if response.reason is not None:
                    resolution_detail["reason"] = response.reason
                self.audit.append(
                    {
                        "kind": "policy_check",
                        "status": response.decision,
                        "initiator": "operator",
                        "tool": {"name": tool_name, "args": args_obj, "capabilities": capabilities},
                        "detail": resolution_detail,
                    }
                )
                if response.decision == "denied":
                    raise GuardianHaltedError(
                        f"tool call rejected: operator "
                        f"{'confirmation timed out' if response.reason == 'timeout' else 'denied'}",
                        reason=f"operator:{response.reason or 'denied'}",
                    )

            # Build the shared tool sub-object so capabilities flow onto every
            # subsequent record for this dispatch.
            tool_base: dict[str, Any] = {
                "name": tool_name,
                "args": args_obj,
                "capabilities": capabilities,
            }

            # 4. tool_call (pending)
            call_input: dict[str, Any] = {
                "kind": "tool_call",
                "status": "pending",
                "initiator": "agent",
                "tool": tool_base,
            }
            if model is not None:
                call_input["model"] = _model_to_wire(model)
            call_record = self.audit.append(call_input)  # type: ignore[arg-type]

            # 5. Capability window: record + emit any yellow-line matches.
            if self.capability_window is not None:
                matches = self.capability_window.record(capabilities, call_record["event_id"])  # type: ignore[index]
                for match in matches:
                    self.audit.append(
                        {
                            "kind": (
                                "x_capability_yellow"
                                if match.level == "yellow"
                                else "x_capability_redline"
                            ),
                            "status": "approved",
                            "initiator": "system",
                            "tool": tool_base,
                            "detail": {
                                "rule_id": match.rule_id,
                                "combination": match.combination,
                                "window_ms": match.window_ms,
                                "contributing_event_ids": match.contributing_event_ids,
                                "tool_capabilities": capabilities,
                            },
                        }
                    )
                    # v0.8: yellow does NOT change behavior. Red-line auto-stop ships later.

            # 6. policy_check — real gate when configured; v0.1 fail-open otherwise.
            policy_identifier: Optional[str] = None
            if self.policy is not None and self.policy_identifier is not None:
                policy_identifier = self.policy_identifier(
                    PolicyIdentifierCall(name=tool_name, args=args_obj, model=model)
                )

            if self.policy is not None and policy_identifier is not None:
                evaluation = self.policy.evaluate(policy_identifier, model)
                category, identifier = _split_policy_identifier(policy_identifier)

                if evaluation.decision == "allow":
                    self.audit.append(
                        {
                            "kind": "policy_check",
                            "status": "approved",
                            "initiator": "system",
                            "tool": tool_base,
                            "detail": _policy_detail(policy_identifier, category, identifier, evaluation),
                        }
                    )
                elif evaluation.decision == "deny":
                    self.audit.append(
                        {
                            "kind": "policy_check",
                            "status": "denied",
                            "initiator": "system",
                            "tool": tool_base,
                            "detail": _policy_detail(policy_identifier, category, identifier, evaluation),
                        }
                    )
                    raise PolicyDenialError(
                        f"policy denied tool call {tool_name!r} "
                        f"(policy {policy_identifier!r}, scope {evaluation.scope})",
                        category=category,
                        identifier=identifier,
                        policy_identifier=policy_identifier,
                        scope=str(evaluation.scope),
                        rule_tool=evaluation.matched_rule.tool if evaluation.matched_rule else None,
                    )
                else:
                    # decision == "prompt" → operator drill-down
                    if self.operator_gate is None:
                        self.audit.append(
                            {
                                "kind": "policy_check",
                                "status": "denied",
                                "initiator": "system",
                                "tool": tool_base,
                                "detail": {
                                    **_policy_detail(policy_identifier, category, identifier, evaluation),
                                    "reason": "no_operator_gate",
                                },
                            }
                        )
                        raise PolicyDenialError(
                            f"policy prompted for tool call {tool_name!r} "
                            "but no operator_gate is configured on the runtime",
                            category=category,
                            identifier=identifier,
                            policy_identifier=policy_identifier,
                            scope="prompt",
                        )
                    gate_id = new_gate_id()
                    policy_context = PolicyDrilldownContext(
                        category=category,
                        exact_identifier=identifier,
                        policy_identifier=policy_identifier,
                        drilldown_axes=_default_drilldown_axes(category, identifier),
                    )
                    reason = f"policy_prompt:{category}"
                    self.audit.append(
                        {
                            "kind": "policy_check",
                            "status": "pending_operator",
                            "initiator": "system",
                            "tool": tool_base,
                            "detail": {
                                **_policy_detail(policy_identifier, category, identifier, evaluation),
                                "gate_id": gate_id,
                                "reason": reason,
                                "timeout_ms": self.operator_timeout_ms,
                            },
                        }
                    )
                    gate_request = OperatorConfirmationRequest(
                        gate_id=gate_id,
                        tool_name=tool_name,
                        tool_args=args_obj,
                        reason=reason,
                        timeout_ms=self.operator_timeout_ms,
                        agent_id=self.agent_id,
                        session_id=self.session_id,
                        policy_context=policy_context,
                    )
                    response = await_with_timeout(self.operator_gate, gate_request)
                    # Persist BEFORE deciding so "Always deny" lands a banned rule
                    if response.persist_as is not None and hasattr(self.policy, "persist"):
                        persist = response.persist_as
                        rule = PolicyRule(tool=persist.tool, scope=persist.scope)
                        if persist.decision is not None:
                            rule.decision = persist.decision
                        if persist.notes is not None:
                            rule.notes = persist.notes
                        if persist.when is not None:
                            rule.when = persist.when
                        self.policy.persist(rule)
                    resolution_detail2: dict[str, Any] = {
                        **_policy_detail(policy_identifier, category, identifier, evaluation),
                        "gate_id": gate_id,
                    }
                    if response.operator_id is not None:
                        resolution_detail2["operator_id"] = response.operator_id
                    if response.reason is not None:
                        resolution_detail2["reason"] = response.reason
                    if response.persist_as is not None:
                        resolution_detail2["persisted"] = {
                            "tool": response.persist_as.tool,
                            "scope": response.persist_as.scope,
                            "decision": response.persist_as.decision or "allow",
                        }
                    self.audit.append(
                        {
                            "kind": "policy_check",
                            "status": response.decision,
                            "initiator": "operator",
                            "tool": tool_base,
                            "detail": resolution_detail2,
                        }
                    )
                    if response.decision == "denied":
                        raise PolicyDenialError(
                            f"policy denied tool call {tool_name!r} "
                            f"(operator {'timed out' if response.reason == 'timeout' else 'denied'})",
                            category=category,
                            identifier=identifier,
                            policy_identifier=policy_identifier,
                            scope="operator",
                        )
            else:
                # v0.1 fail-open path preserved.
                self.audit.append(
                    {
                        "kind": "policy_check",
                        "status": "approved",
                        "initiator": "system",
                        "tool": tool_base,
                        "detail": {"matched_at": "default"},
                    }
                )

            # 7. execute
            start_ms = time.monotonic_ns() // 1_000_000
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:
                duration_ms = (time.monotonic_ns() // 1_000_000) - start_ms
                self.audit.append(
                    {
                        "kind": "tool_result",
                        "status": "errored",
                        "initiator": "system",
                        "tool": {**tool_base, "duration_ms": duration_ms},
                        "detail": {"error": str(exc)},
                    }
                )
                raise

            duration_ms = (time.monotonic_ns() // 1_000_000) - start_ms
            self.audit.append(
                {
                    "kind": "tool_result",
                    "status": "executed",
                    "initiator": "system",
                    "tool": {**tool_base, "result": result, "duration_ms": duration_ms},
                }
            )
            return result

        return wrapped

    def press_estop(self, reason: str, operator_id: Optional[str] = None) -> None:
        """Trip the local estop. Raises if no EStopLocal was supplied."""
        if self.estop is None:
            raise RuntimeError("GuardianRuntime constructed without an EStopLocal")
        from ..estop.types import EStopPressOptions

        self.estop.press(EStopPressOptions(reason=reason, operator_id=operator_id))

    def close(self) -> None:
        """Emit session_close + close the audit. Idempotent."""
        if self._closed:
            return
        self._closed = True
        if self._session_opened:
            self.audit.append(
                {"kind": "session_close", "status": "approved", "initiator": "system"}
            )
        self.audit.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _args_to_object(args: tuple, kwargs: dict) -> dict[str, Any]:
    """Wrap positional args as {"0": ..., ...} + merge kwargs."""
    out: dict[str, Any] = {str(i): v for i, v in enumerate(args)}
    out.update(kwargs)
    return out


def _model_to_wire(model: ModelAttribution) -> dict[str, Any]:
    out: dict[str, Any] = {"provider": model.provider, "id": model.id}
    if model.surface is not None:
        out["surface"] = model.surface
    if model.aggregator is not None:
        out["aggregator"] = model.aggregator
    if model.input_tokens is not None:
        out["input_tokens"] = model.input_tokens
    if model.output_tokens is not None:
        out["output_tokens"] = model.output_tokens
    return out


def _split_policy_identifier(id_str: str) -> tuple[str, str]:
    """Split <category>:<identifier> into parts. No colon → ('', whole_string)."""
    colon = id_str.find(":")
    if colon < 0:
        return ("", id_str)
    return (id_str[:colon], id_str[colon + 1:])


def _policy_detail(
    policy_identifier: str,
    category: str,
    identifier: str,
    evaluation: PolicyEvaluation,
) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "policy_identifier": policy_identifier,
        "category": category,
        "identifier": identifier,
        "decision": evaluation.decision,
        "matched_at": evaluation.matched_at,
        "scope": evaluation.scope,
    }
    if evaluation.matched_rule is not None:
        detail["rule_tool"] = evaluation.matched_rule.tool
    return detail


def _default_drilldown_axes(category: str, identifier: str) -> list[dict[str, str]]:
    """Default drill-down axes: exact + container-wide + category-wide."""
    axes: list[dict[str, str]] = [
        {"key": "exact", "pattern": f"{category}:{identifier}", "label": "this exact target"},
    ]
    slash = identifier.find("/")
    if slash > 0:
        container = identifier[:slash]
        axes.append(
            {
                "key": "container",
                "pattern": f"{category}:{container}/*",
                "label": _container_label(category, container),
            }
        )
    axes.append({"key": "category", "pattern": f"{category}:*", "label": f"any {category}"})
    return axes


def _container_label(category: str, container: str) -> str:
    if category == "mcp.tool":
        return f'any tool on MCP server "{container}"'
    if category == "toolkit.tool":
        return f'any tool in toolkit "{container}"'
    if category == "llm.call":
        return f'any model on "{container}"'
    return f'any in "{container}"'
