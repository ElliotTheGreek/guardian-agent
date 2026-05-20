"""async_callback_gate — POST a GateRequest, await a GateResponse. SPEC §4.3.

Despite the name (kept for parity with the TS impl), this gate is sync. The
"async" refers to the request/response decoupling — the operator's UI lives
out-of-process and may take minutes to respond.
"""

from __future__ import annotations

import dataclasses
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from .types import (
    VALID_DECISIONS,
    VALID_GRANULARITIES,
    ApprovalGate,
    GateRequest,
    GateResponse,
)

DEFAULT_GATE_TIMEOUT_MS = 600_000  # 10 minutes (SPEC §4.6)

PostFn = Callable[[str, bytes, dict[str, str], float], tuple[int, bytes]]


@dataclass
class AsyncCallbackGateOptions:
    url: str
    timeout_ms: int = DEFAULT_GATE_TIMEOUT_MS
    headers: dict[str, str] = field(default_factory=dict)
    post: Optional[PostFn] = None
    """Override transport (for testing). Must return (status, body_bytes)."""


def async_callback_gate(options: AsyncCallbackGateOptions) -> ApprovalGate:
    post = options.post or _default_post

    def gate(request: GateRequest) -> GateResponse:
        timeout_ms = request.timeout_ms if request.timeout_ms is not None else options.timeout_ms
        timeout_seconds = timeout_ms / 1000.0
        body = json.dumps(_request_to_wire(request), sort_keys=True, separators=(",", ":")).encode("utf-8")
        headers = {"content-type": "application/json", **options.headers}
        try:
            status, response_bytes = post(options.url, body, headers, timeout_seconds)
        except _GateTimeout:
            return _deny(request, "gate_timeout")
        except BaseException as exc:  # noqa: BLE001 — fail-closed on any error
            return _deny(request, f"callback_error:{exc}")
        if not (200 <= status < 300):
            return _deny(request, f"callback_status_{status}")
        try:
            parsed = json.loads(response_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return _deny(request, "callback_invalid_response")
        if not _is_gate_response(parsed):
            return _deny(request, "callback_invalid_response")
        return GateResponse(
            decision=parsed["decision"],
            granularity=parsed["granularity"],
            reason=parsed.get("reason"),
            operator_id=parsed.get("operator_id"),
        )

    return gate


class _GateTimeout(Exception):
    """Sentinel raised by the transport when the request exceeds timeout."""


def _default_post(url: str, body: bytes, headers: dict[str, str], timeout_seconds: float) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() if exc.fp is not None else b""
    except TimeoutError as exc:  # urllib raises TimeoutError on socket timeout
        raise _GateTimeout(str(exc)) from exc
    except urllib.error.URLError as exc:
        # urllib wraps socket.timeout in URLError.reason
        if "timed out" in str(exc.reason).lower():
            raise _GateTimeout(str(exc.reason)) from exc
        raise


def _request_to_wire(request: GateRequest) -> dict[str, Any]:
    """Serialize a GateRequest to a JSON-safe dict."""
    wire: dict[str, Any] = {
        "event_id": request.event_id,
        "tool_name": request.tool_name,
        "tool_args": request.tool_args,
        "agent_id": request.agent_id,
        "session_id": request.session_id,
        "granularity": request.granularity,
    }
    if request.model is not None:
        wire["model"] = dataclasses.asdict(request.model)
    if request.context is not None:
        wire["context"] = request.context
    if request.timeout_ms is not None:
        wire["timeout_ms"] = request.timeout_ms
    return wire


def _deny(request: GateRequest, reason: str) -> GateResponse:
    return GateResponse(decision="deny", granularity=request.granularity, reason=reason)


def _is_gate_response(v: Any) -> bool:
    if not isinstance(v, dict):
        return False
    decision = v.get("decision")
    if not isinstance(decision, str) or decision not in VALID_DECISIONS:
        return False
    granularity = v.get("granularity")
    if not isinstance(granularity, str) or granularity not in VALID_GRANULARITIES:
        return False
    reason = v.get("reason")
    if reason is not None and not isinstance(reason, str):
        return False
    operator_id = v.get("operator_id")
    if operator_id is not None and not isinstance(operator_id, str):
        return False
    return True
