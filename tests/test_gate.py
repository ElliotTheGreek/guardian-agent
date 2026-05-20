"""Tests for the gate subsystem (types, options, 5 adapters, two-key). SPEC §4."""

from __future__ import annotations

import io
import json
import threading
import time
from typing import Any, Callable

import pytest

from guardian_agent.gate import (
    CLASSIC_FOUR,
    FLOWDOT_FIVE,
    AsyncCallbackGateOptions,
    CliGateOptions,
    DataChannelGateOptions,
    GateOption,
    GateRequest,
    GateResponse,
    OperatorConfirmationGate,
    OperatorConfirmationRequest,
    OperatorConfirmationResponse,
    async_callback_gate,
    await_with_timeout,
    callback_operator_gate,
    cli_approval_gate,
    data_channel_gate,
    decode_response,
    define_gate_option_set,
    deny_all_operator_gate,
    encode_request,
    find_option,
    new_gate_id,
    parse_cli_answer,
    programmatic_gate,
    resolve_option,
)


def _request(**overrides: Any) -> GateRequest:
    base: dict[str, Any] = {
        "event_id": "evt_1",
        "tool_name": "list_accounts",
        "tool_args": {"broker": "schwab"},
        "agent_id": "agent_demo",
        "session_id": "sess_demo",
        "granularity": "tool",
    }
    base.update(overrides)
    return GateRequest(**base)


# ---- options ------------------------------------------------------------


def test_flowdot_five_has_five_options_ordered():
    ids = [o.id for o in FLOWDOT_FIVE.options]
    assert ids == ["once", "session", "tool", "toolkit", "deny"]


def test_classic_four_has_four_options_with_banned():
    ids = [o.id for o in CLASSIC_FOUR.options]
    assert ids == ["once", "session", "forever", "banned"]


def test_define_gate_option_set_rejects_empty_and_duplicates():
    with pytest.raises(ValueError, match="non-empty"):
        define_gate_option_set("x", [])
    with pytest.raises(ValueError, match="duplicate"):
        define_gate_option_set("x", [
            GateOption(id="a", scope="once", decision="allow"),
            GateOption(id="a", scope="session", decision="allow"),
        ])


def test_find_and_resolve_option():
    assert find_option(FLOWDOT_FIVE, "deny").id == "deny"
    assert find_option(FLOWDOT_FIVE, "nope") is None
    assert resolve_option(FLOWDOT_FIVE, "session").scope == "session"
    with pytest.raises(ValueError, match="Unknown gate option"):
        resolve_option(FLOWDOT_FIVE, "nope")


# ---- programmatic_gate --------------------------------------------------


def test_programmatic_gate_passes_response_through():
    gate = programmatic_gate(
        lambda req: GateResponse(decision="allow_session", granularity=req.granularity)
    )
    out = gate(_request())
    assert out.decision == "allow_session"


def test_programmatic_gate_downgrades_granularity_escalation():
    # Caller asks for "tool" granularity but handler returns "toolkit" — must downgrade.
    gate = programmatic_gate(
        lambda req: GateResponse(decision="allow", granularity="toolkit")
    )
    out = gate(_request(granularity="tool"))
    assert out.granularity == "tool"


# ---- cli_approval_gate --------------------------------------------------


def test_parse_cli_answer_known_inputs():
    assert parse_cli_answer("1") == "allow"
    assert parse_cli_answer("once") == "allow"
    assert parse_cli_answer("yes") == "allow"
    assert parse_cli_answer("2") == "allow_session"
    assert parse_cli_answer("session") == "allow_session"
    assert parse_cli_answer("3") == "allow_forever"
    assert parse_cli_answer("forever") == "allow_forever"
    assert parse_cli_answer("5") == "ban_forever"
    assert parse_cli_answer("ban") == "ban_forever"
    # default-deny
    assert parse_cli_answer("4") == "deny"
    assert parse_cli_answer("deny") == "deny"
    assert parse_cli_answer("garbage") == "deny"


def test_cli_approval_gate_reads_from_stream():
    in_buf = io.StringIO("1\n")
    out_buf = io.StringIO()
    gate = cli_approval_gate(CliGateOptions(input_stream=in_buf, output_stream=out_buf, operator_id="op-7"))
    response = gate(_request())
    assert response.decision == "allow"
    assert response.operator_id == "op-7"
    assert "guardian-agent approval required" in out_buf.getvalue()
    assert "list_accounts" in out_buf.getvalue()


# ---- async_callback_gate ------------------------------------------------


def test_async_callback_gate_posts_and_parses_response():
    captured: dict[str, Any] = {}

    def fake_post(url: str, body: bytes, headers: dict[str, str], timeout: float) -> tuple[int, bytes]:
        captured["url"] = url
        captured["body"] = body
        captured["timeout"] = timeout
        return 200, json.dumps({"decision": "allow_session", "granularity": "tool", "operator_id": "op-x"}).encode("utf-8")

    gate = async_callback_gate(AsyncCallbackGateOptions(url="https://h/gate", post=fake_post))
    response = gate(_request())
    assert response.decision == "allow_session"
    assert response.operator_id == "op-x"
    sent = json.loads(captured["body"])
    assert sent["tool_name"] == "list_accounts"


def test_async_callback_gate_denies_on_non_2xx():
    def fake_post(*_a: Any, **_kw: Any) -> tuple[int, bytes]:
        return 500, b""
    gate = async_callback_gate(AsyncCallbackGateOptions(url="https://h", post=fake_post))
    response = gate(_request())
    assert response.decision == "deny"
    assert response.reason == "callback_status_500"


def test_async_callback_gate_denies_on_invalid_response_shape():
    def fake_post(*_a: Any, **_kw: Any) -> tuple[int, bytes]:
        return 200, b'{"decision":"yolo","granularity":"tool"}'
    gate = async_callback_gate(AsyncCallbackGateOptions(url="https://h", post=fake_post))
    response = gate(_request())
    assert response.decision == "deny"
    assert response.reason == "callback_invalid_response"


def test_async_callback_gate_denies_on_transport_error():
    def fake_post(*_a: Any, **_kw: Any) -> tuple[int, bytes]:
        raise RuntimeError("network down")
    gate = async_callback_gate(AsyncCallbackGateOptions(url="https://h", post=fake_post))
    response = gate(_request())
    assert response.decision == "deny"
    assert "network down" in (response.reason or "")


# ---- data_channel_gate --------------------------------------------------


def test_data_channel_encode_decode_round_trip():
    req = _request()
    frame = encode_request(req)
    decoded_frame = json.loads(frame.decode("utf-8"))
    assert decoded_frame["kind"] == "tool_permission_request"
    assert decoded_frame["requestId"] == "evt_1"
    assert decoded_frame["toolName"] == "list_accounts"

    # Build a matching response frame
    resp_frame = json.dumps({
        "kind": "tool_permission_response",
        "requestId": "evt_1",
        "decision": "allow",
        "granularity": "tool",
        "operatorId": "op-y",
    }).encode("utf-8")
    parsed = decode_response(resp_frame)
    assert parsed is not None
    request_id, response = parsed
    assert request_id == "evt_1"
    assert response.decision == "allow"
    assert response.operator_id == "op-y"


def test_decode_response_returns_none_on_invalid_input():
    assert decode_response(b"not json") is None
    assert decode_response(b'{"kind":"other"}') is None
    assert decode_response(b'{"kind":"tool_permission_response","requestId":1}') is None  # bad type
    assert decode_response(b'{"kind":"tool_permission_response","requestId":"x","decision":"nope","granularity":"tool"}') is None


def test_data_channel_gate_resolves_on_matching_response_frame():
    sent_frames: list[bytes] = []
    response_handler: list[Callable[[bytes], None]] = []

    def fake_send(frame: bytes) -> None:
        sent_frames.append(frame)

    def fake_on_response(handler: Callable[[bytes], None]) -> Callable[[], None]:
        response_handler.append(handler)
        return lambda: None

    gate = data_channel_gate(DataChannelGateOptions(send=fake_send, on_response=fake_on_response))

    # Fire the response from a worker thread after a short delay
    def deliver() -> None:
        time.sleep(0.05)
        response_handler[0](json.dumps({
            "kind": "tool_permission_response",
            "requestId": "evt_1",
            "decision": "allow_session",
            "granularity": "tool",
        }).encode("utf-8"))

    threading.Thread(target=deliver, daemon=True).start()
    response = gate(_request(timeout_ms=2000))
    assert response.decision == "allow_session"
    assert len(sent_frames) == 1


def test_data_channel_gate_times_out_with_deny():
    def fake_send(_frame: bytes) -> None:
        pass

    def fake_on_response(_handler: Callable[[bytes], None]) -> Callable[[], None]:
        return lambda: None

    gate = data_channel_gate(DataChannelGateOptions(send=fake_send, on_response=fake_on_response))
    response = gate(_request(timeout_ms=50))
    assert response.decision == "deny"
    assert response.reason == "gate_timeout"


def test_data_channel_gate_denies_on_send_error():
    def fake_send(_frame: bytes) -> None:
        raise RuntimeError("channel closed")

    def fake_on_response(_handler: Callable[[bytes], None]) -> Callable[[], None]:
        return lambda: None

    gate = data_channel_gate(DataChannelGateOptions(send=fake_send, on_response=fake_on_response))
    response = gate(_request())
    assert response.decision == "deny"
    assert "channel closed" in (response.reason or "")


# ---- two-key operator gate ----------------------------------------------


def _confirm_req(**overrides: Any) -> OperatorConfirmationRequest:
    base: dict[str, Any] = {
        "gate_id": new_gate_id(),
        "tool_name": "wire_transfer",
        "tool_args": {"amount": 100},
        "reason": "sensitive_action",
        "timeout_ms": 1000,
        "agent_id": "agent_demo",
        "session_id": "sess_demo",
    }
    base.update(overrides)
    return OperatorConfirmationRequest(**base)


def test_new_gate_id_format():
    gid = new_gate_id()
    assert gid.startswith("gt_")
    assert len(gid) > 5


def test_callback_operator_gate_invokes_fn():
    seen: list[OperatorConfirmationRequest] = []

    def fn(req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:
        seen.append(req)
        return OperatorConfirmationResponse(decision="approved", operator_id="op-1")

    gate = callback_operator_gate(fn)
    response = gate.request(_confirm_req())
    assert response.decision == "approved"
    assert response.operator_id == "op-1"
    assert len(seen) == 1


def test_deny_all_operator_gate_always_denies():
    gate = deny_all_operator_gate("nope")
    response = gate.request(_confirm_req())
    assert response.decision == "denied"
    assert response.reason == "nope"


def test_await_with_timeout_passes_through_quick_response():
    gate = callback_operator_gate(
        lambda req: OperatorConfirmationResponse(decision="approved", operator_id="o")
    )
    out = await_with_timeout(gate, _confirm_req(timeout_ms=2000))
    assert out.decision == "approved"


def test_await_with_timeout_synthesizes_denial_on_timeout():
    def slow(req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:
        time.sleep(0.5)
        return OperatorConfirmationResponse(decision="approved")

    gate = callback_operator_gate(slow)
    out = await_with_timeout(gate, _confirm_req(timeout_ms=50))
    assert out.decision == "denied"
    assert out.reason == "timeout"


def test_await_with_timeout_synthesizes_denial_on_exception():
    def explode(req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:
        raise RuntimeError("ipc gone")

    gate = callback_operator_gate(explode)
    out = await_with_timeout(gate, _confirm_req(timeout_ms=500))
    assert out.decision == "denied"
    assert out.reason is not None and "ipc gone" in out.reason
