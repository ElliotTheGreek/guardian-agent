"""data_channel_gate — frame encode/decode for LiveKit-style data channels.

SPEC §4.3 / §4.4. The wire shape matches FlowDot's voice/live agent worker:
  { kind: 'tool_permission_request',  requestId, toolName, toolArgs, ... }
  { kind: 'tool_permission_response', requestId, decision, granularity, ... }

The library doesn't own the transport; it provides encode/decode + a gate
factory that takes (send, on_response) callables.

Python uses a `threading.Event` per pending request to wait for the response;
the wait blocks the caller's thread until either the response arrives or the
timeout fires (returning a synthetic `deny / gate_timeout`).
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .types import (
    VALID_DECISIONS,
    VALID_GRANULARITIES,
    ApprovalGate,
    GateRequest,
    GateResponse,
)

DEFAULT_GATE_TIMEOUT_MS = 600_000

SendFn = Callable[[bytes], None]
OnResponseSubscribe = Callable[[Callable[[bytes], None]], Callable[[], None]]
"""subscribe(handler) → returns an unsubscribe callable."""


@dataclass
class DataChannelGateOptions:
    send: SendFn
    on_response: OnResponseSubscribe
    timeout_ms: int = DEFAULT_GATE_TIMEOUT_MS


def encode_request(request: GateRequest) -> bytes:
    """Encode a GateRequest to a UTF-8 JSON frame."""
    payload: dict[str, Any] = {
        "kind": "tool_permission_request",
        "requestId": request.event_id,
        "toolName": request.tool_name,
        "toolArgs": request.tool_args,
        "agentId": request.agent_id,
        "sessionId": request.session_id,
        "granularity": request.granularity,
    }
    if request.model is not None:
        import dataclasses
        payload["model"] = dataclasses.asdict(request.model)
    if request.context is not None:
        payload["context"] = request.context
    if request.timeout_ms is not None:
        payload["timeoutMs"] = request.timeout_ms
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_response(frame: bytes) -> Optional[tuple[str, GateResponse]]:
    """Decode a wire frame. Returns (request_id, response) or None on invalid input."""
    try:
        parsed = json.loads(frame.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(parsed, dict):
        return None
    if parsed.get("kind") != "tool_permission_response":
        return None
    request_id = parsed.get("requestId")
    if not isinstance(request_id, str):
        return None
    decision = parsed.get("decision")
    if not isinstance(decision, str) or decision not in VALID_DECISIONS:
        return None
    granularity = parsed.get("granularity")
    if not isinstance(granularity, str) or granularity not in VALID_GRANULARITIES:
        return None
    reason = parsed.get("reason")
    if reason is not None and not isinstance(reason, str):
        return None
    operator_id = parsed.get("operatorId")
    if operator_id is not None and not isinstance(operator_id, str):
        return None
    response = GateResponse(
        decision=decision,  # type: ignore[arg-type]
        granularity=granularity,  # type: ignore[arg-type]
        reason=reason if isinstance(reason, str) else None,
        operator_id=operator_id if isinstance(operator_id, str) else None,
    )
    return (request_id, response)


class _DataChannelGate:
    """Gate that owns a subscription + pending-request map."""

    def __init__(self, options: DataChannelGateOptions) -> None:
        self._send = options.send
        self._default_timeout_ms = options.timeout_ms
        self._pending_lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._unsubscribe = options.on_response(self._on_frame)

    def __call__(self, request: GateRequest) -> GateResponse:
        timeout_ms = request.timeout_ms if request.timeout_ms is not None else self._default_timeout_ms
        timeout_seconds = timeout_ms / 1000.0

        pending = _Pending(granularity=request.granularity)
        with self._pending_lock:
            self._pending[request.event_id] = pending

        try:
            self._send(encode_request(request))
        except BaseException as exc:  # noqa: BLE001
            with self._pending_lock:
                self._pending.pop(request.event_id, None)
            return GateResponse(
                decision="deny",
                granularity=request.granularity,
                reason=f"data_channel_send_error:{exc}",
            )

        signaled = pending.event.wait(timeout=timeout_seconds)
        with self._pending_lock:
            self._pending.pop(request.event_id, None)

        if not signaled or pending.response is None:
            return GateResponse(
                decision="deny",
                granularity=request.granularity,
                reason="gate_timeout",
            )
        return pending.response

    def _on_frame(self, frame: bytes) -> None:
        decoded = decode_response(frame)
        if decoded is None:
            return
        request_id, response = decoded
        with self._pending_lock:
            pending = self._pending.get(request_id)
        if pending is not None:
            pending.response = response
            pending.event.set()

    def dispose(self) -> None:
        """Detach the underlying subscription."""
        try:
            self._unsubscribe()
        except BaseException:  # noqa: BLE001
            pass


@dataclass
class _Pending:
    granularity: str
    response: Optional[GateResponse] = None
    event: threading.Event = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.event = threading.Event()


def data_channel_gate(options: DataChannelGateOptions) -> ApprovalGate:
    """Build a data-channel approval gate.

    The returned callable carries a `dispose()` attribute that the host may
    call to unsubscribe from the transport.
    """
    gate = _DataChannelGate(options)
    return gate
