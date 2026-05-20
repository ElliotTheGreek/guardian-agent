"""HITL approval gate subsystem. SPEC §4 and §4.5."""

from .async_callback import (
    DEFAULT_GATE_TIMEOUT_MS,
    AsyncCallbackGateOptions,
    async_callback_gate,
)
from .cli import CliGateOptions, cli_approval_gate, parse_cli_answer
from .data_channel import (
    DataChannelGateOptions,
    data_channel_gate,
    decode_response,
    encode_request,
)
from .options import (
    CLASSIC_FOUR,
    FLOWDOT_FIVE,
    GateOption,
    GateOptionSet,
    define_gate_option_set,
    find_option,
    resolve_option,
)
from .programmatic import programmatic_gate
from .two_key import (
    OperatorConfirmationGate,
    OperatorConfirmationRequest,
    OperatorConfirmationResponse,
    PolicyDrilldownContext,
    PolicyPersistDecision,
    await_with_timeout,
    callback_operator_gate,
    deny_all_operator_gate,
    new_gate_id,
)
from .types import (
    ApprovalGate,
    GateDecision,
    GateGranularity,
    GateRequest,
    GateResponse,
)

__all__ = [
    "ApprovalGate",
    "AsyncCallbackGateOptions",
    "CLASSIC_FOUR",
    "CliGateOptions",
    "DEFAULT_GATE_TIMEOUT_MS",
    "DataChannelGateOptions",
    "FLOWDOT_FIVE",
    "GateDecision",
    "GateGranularity",
    "GateOption",
    "GateOptionSet",
    "GateRequest",
    "GateResponse",
    "OperatorConfirmationGate",
    "OperatorConfirmationRequest",
    "OperatorConfirmationResponse",
    "PolicyDrilldownContext",
    "PolicyPersistDecision",
    "async_callback_gate",
    "await_with_timeout",
    "callback_operator_gate",
    "cli_approval_gate",
    "data_channel_gate",
    "decode_response",
    "define_gate_option_set",
    "deny_all_operator_gate",
    "encode_request",
    "find_option",
    "new_gate_id",
    "parse_cli_answer",
    "programmatic_gate",
    "resolve_option",
]
