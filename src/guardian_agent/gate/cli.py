"""cli_approval_gate — synchronous stdin prompt. SPEC §4.3."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import IO, Optional

from .types import ApprovalGate, GateDecision, GateRequest, GateResponse


@dataclass
class CliGateOptions:
    input_stream: Optional[IO[str]] = None  # defaults to sys.stdin
    output_stream: Optional[IO[str]] = None  # defaults to sys.stderr
    operator_id: Optional[str] = None


def cli_approval_gate(options: Optional[CliGateOptions] = None) -> ApprovalGate:
    """Build a CLI approval gate. Not concurrency-safe (one prompt at a time)."""
    opts = options or CliGateOptions()

    def gate(request: GateRequest) -> GateResponse:
        input_stream = opts.input_stream if opts.input_stream is not None else sys.stdin
        output_stream = opts.output_stream if opts.output_stream is not None else sys.stderr
        _write_prompt(output_stream, request)
        output_stream.write("> ")
        try:
            output_stream.flush()
        except (OSError, ValueError):
            pass
        answer = input_stream.readline()
        decision = parse_cli_answer(answer.strip())
        response = GateResponse(decision=decision, granularity=request.granularity)
        if opts.operator_id is not None:
            response.operator_id = opts.operator_id
        return response

    return gate


def _write_prompt(out: IO[str], request: GateRequest) -> None:
    lines = [
        "",
        "── guardian-agent approval required ──",
        f"Tool:      {request.tool_name}",
        f"Agent:     {request.agent_id}",
        f"Session:   {request.session_id}",
        f"Args:      {json.dumps(request.tool_args, sort_keys=True)}",
    ]
    if request.model is not None:
        lines.append(f"Model:     {request.model.provider}/{request.model.id}")
    if request.context is not None:
        lines.append(f"Context:   {request.context}")
    lines.append("Choose:    1=once, 2=session, 3=forever, 4=deny, 5=ban")
    lines.append("")
    out.write("\n".join(lines) + "\n")


def parse_cli_answer(answer: str) -> GateDecision:
    """Parse user input. Fails closed (deny) on unknown input."""
    a = answer.lower()
    if a in {"1", "once", "allow", "y", "yes"}:
        return "allow"
    if a in {"2", "session"}:
        return "allow_session"
    if a in {"3", "forever", "always", "always_allow"}:
        return "allow_forever"
    if a in {"5", "ban", "never", "ban_forever"}:
        return "ban_forever"
    # Default: deny (fail-closed). Includes "4", "deny", "no", and unknown.
    return "deny"
