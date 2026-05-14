"""guardian-agent quickstart example.

Runs a tiny synthetic "trading agent" against a fake brokerage tool, with all
four supervisor primitives engaged: audit log, policy enforcement, HITL gate,
and emergency-stop.

This file is illustrative — the reference implementation is pre-alpha and the
runtime classes referenced below are stubs in v0.1.0. The example shows the
intended public API; the spec at SPEC.md is the canonical contract.

Run (once v0.1.0 lands):
    pip install -e .
    python examples/quickstart.py
"""

from __future__ import annotations

from pathlib import Path

from guardian_agent import (
    GuardianHalted,
    GuardianRuntime,
    Policy,
    cli_approval_gate,
)


HERE = Path(__file__).parent
POLICY_PATH = HERE / "permissions.yaml"
AUDIT_LOG = HERE / "audit.jsonl"


def main() -> None:
    runtime = GuardianRuntime(
        agent_id="agent_demo",
        session_id="sess_quickstart",
        audit_log=str(AUDIT_LOG),
        policy=Policy.from_yaml(str(POLICY_PATH)),
        approval_gate=cli_approval_gate,
    )

    # Tools wrapped with @runtime.tool are intercepted: every call is policy-
    # checked, optionally gated, recorded to the audit log, and bounded by the
    # emergency-stop primitive.

    @runtime.tool
    def list_brokerage_accounts(broker: str) -> list[dict]:
        """A pretend brokerage call."""
        return [
            {"id": "acct_001", "broker": broker, "balance_usd": 12_345.67},
            {"id": "acct_002", "broker": broker, "balance_usd": 89_012.34},
        ]

    @runtime.tool
    def get_positions(account_id: str) -> list[dict]:
        """A pretend positions call."""
        return [
            {"symbol": "VTI",  "shares": 42, "market_value_usd": 11_000.00},
            {"symbol": "AAPL", "shares": 10, "market_value_usd":  2_345.67},
        ]

    @runtime.tool
    def place_order(account_id: str, symbol: str, side: str, qty: int) -> dict:
        """A pretend trade call.  Policy denies this in permissions.yaml."""
        return {"status": "filled", "fill_price_usd": 195.42}

    print("guardian-agent quickstart")
    print(f"  audit log: {AUDIT_LOG}")
    print(f"  policy:    {POLICY_PATH}")
    print()

    try:
        # Step 1 — allowed by policy (mode: allow). No gate prompt.
        accounts = list_brokerage_accounts(broker="schwab")
        print(f"accounts: {accounts}")

        # Step 2 — gated by policy (mode: gate). CLI prompt appears here.
        positions = get_positions(account_id=accounts[0]["id"])
        print(f"positions: {positions}")

        # Step 3 — denied by policy (mode: deny). Logged, not executed.
        place_order(
            account_id=accounts[0]["id"],
            symbol="AAPL",
            side="buy",
            qty=1,
        )

    except GuardianHalted as halt:
        print(f"halted: {halt}")

    print()
    print(f"audit events written to {AUDIT_LOG}")
    print("verify with: guardian-verify", AUDIT_LOG)


if __name__ == "__main__":
    main()
