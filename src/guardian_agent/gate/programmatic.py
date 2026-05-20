"""programmatic_gate — wrap an arbitrary handler. SPEC §4.3.

Use when the host has its own UI (Electron renderer, mobile RN modal, etc.)
and the gate is "just call this function and wait."
"""

from __future__ import annotations

import dataclasses
from typing import Callable

from .types import ApprovalGate, GateRequest, GateResponse


def programmatic_gate(handler: Callable[[GateRequest], GateResponse]) -> ApprovalGate:
    def gate(request: GateRequest) -> GateResponse:
        response = handler(request)
        if response.granularity != request.granularity:
            # SPEC §4.3: gate may not escalate granularity. Defend by
            # downgrading any wider response — preserves liveness.
            return dataclasses.replace(response, granularity=request.granularity)
        return response

    return gate
