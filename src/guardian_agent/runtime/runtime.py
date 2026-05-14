"""GuardianRuntime — Python reference impl.

v0.1.0 scope: tool wrapping + audit emission + EStopLocal coordination.
"""

from __future__ import annotations

import functools
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar

try:
    from ulid import ULID

    def _ulid() -> str:
        return str(ULID())
except ImportError:  # pragma: no cover
    import uuid

    def _ulid() -> str:
        return uuid.uuid4().hex.upper()

from ..audit.writer import AuditLogWriter
from ..errors import GuardianHaltedError
from ..estop.local import EStopLocal
from ..types import AuditRecordInitiator, ModelAttribution

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class ToolOptions:
    """Options on a wrapped tool."""

    name: str | None = None
    model: ModelAttribution | None = None


@dataclass
class GuardianRuntimeOptions:
    """Constructor options for GuardianRuntime."""

    agent_id: str
    audit: AuditLogWriter
    session_id: str | None = None
    estop: EStopLocal | None = None
    default_model: ModelAttribution | None = None


class GuardianRuntime:
    """Orchestrator that wraps tool calls with audit + halt enforcement."""

    def __init__(self, options: GuardianRuntimeOptions) -> None:
        self.agent_id = options.agent_id
        self.session_id = options.session_id or "sess_" + _ulid()
        self.audit = options.audit
        self.estop = options.estop
        self.default_model = options.default_model
        self._session_opened = False
        self._closed = False

    def open_session(self) -> None:
        """Emit session_open. Idempotent."""
        if self._session_opened:
            return
        self._session_opened = True
        self.audit.append(
            {
                "kind": "session_open",
                "status": "approved",
                "initiator": "system",
            }
        )

    def tool(self, fn: F | None = None, *, name: str | None = None, model: ModelAttribution | None = None) -> Any:
        """Decorator that places a tool under runtime supervision.

        Usage:
          @runtime.tool
          def my_tool(...): ...

          @runtime.tool(name="custom_name", model=...)
          def my_tool(...): ...
        """

        if fn is None:
            # Called with options: @runtime.tool(name="x")
            def wrapper(inner_fn: F) -> F:
                return self._wrap_tool(inner_fn, name, model)  # type: ignore[return-value]
            return wrapper

        # Called as plain decorator: @runtime.tool
        return self._wrap_tool(fn, name, model)

    def _wrap_tool(
        self,
        fn: Callable[..., Any],
        opt_name: str | None,
        opt_model: ModelAttribution | None,
    ) -> Callable[..., Any]:
        tool_name = opt_name if opt_name is not None else fn.__name__
        if not tool_name:
            raise ValueError("tool() requires a name (either fn.__name__ or opts.name)")
        if (
            tool_name.startswith("guardian.")
            or tool_name.startswith("runtime.")
            or tool_name.startswith("internal.")
        ):
            raise ValueError(f'tool name "{tool_name}" uses a reserved prefix')

        model = opt_model or self.default_model

        @functools.wraps(fn)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not self._session_opened:
                self.open_session()

            args_obj = _args_to_object(args, kwargs)

            if self.estop is not None and self.estop.is_pressed():
                self.audit.append(
                    {
                        "kind": "policy_check",
                        "status": "halted",
                        "initiator": "system",
                        "tool": {"name": tool_name, "args": args_obj},
                        "detail": {"reason": "estop"},
                    }
                )
                raise GuardianHaltedError(
                    "tool call rejected: emergency stop active",
                    reason=self.estop.state().pressed_reason,
                )

            # 1. tool_call (pending)
            tool_call_input: dict[str, Any] = {
                "kind": "tool_call",
                "status": "pending",
                "initiator": "agent",
                "tool": {"name": tool_name, "args": args_obj},
            }
            if model is not None:
                tool_call_input["model"] = _model_to_wire(model)
            self.audit.append(tool_call_input)  # type: ignore[arg-type]

            # 2. policy_check (approved) — v0.1 fail-open
            self.audit.append(
                {
                    "kind": "policy_check",
                    "status": "approved",
                    "initiator": "system",
                    "tool": {"name": tool_name, "args": args_obj},
                    "detail": {"matched_at": "default"},
                }
            )

            # 3. execute
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
                        "tool": {
                            "name": tool_name,
                            "args": args_obj,
                            "duration_ms": duration_ms,
                        },
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
                    "tool": {
                        "name": tool_name,
                        "args": args_obj,
                        "result": result,
                        "duration_ms": duration_ms,
                    },
                }
            )
            return result

        return wrapped

    def press_estop(self, reason: str, operator_id: str | None = None) -> None:
        """Trip the local estop. Raises if no EStopLocal was supplied."""
        if self.estop is None:
            raise RuntimeError("GuardianRuntime constructed without an EStopLocal")
        from ..estop.types import EStopPressOptions

        self.estop.press(EStopPressOptions(reason=reason, operator_id=operator_id))

    def close(self) -> None:
        """Emit session_close and close the audit. Idempotent."""
        if self._closed:
            return
        self._closed = True
        if self._session_opened:
            self.audit.append(
                {
                    "kind": "session_close",
                    "status": "approved",
                    "initiator": "system",
                }
            )
        self.audit.close()


def _args_to_object(args: tuple, kwargs: dict) -> dict[str, Any]:
    """Serialize positional args as {"0": ..., "1": ...} and merge kwargs."""
    out: dict[str, Any] = {str(i): v for i, v in enumerate(args)}
    out.update(kwargs)
    return out


def _model_to_wire(model: ModelAttribution) -> dict[str, Any]:
    out: dict[str, Any] = {"provider": model.provider, "id": model.id}
    if model.input_tokens is not None:
        out["input_tokens"] = model.input_tokens
    if model.output_tokens is not None:
        out["output_tokens"] = model.output_tokens
    return out
