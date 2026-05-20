"""End-to-end runtime tests: honeytokens + capability rules + operator gate +
policy gate all wired together. Mirrors guardian-agent-ts supervisor-v08/v09 tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from guardian_agent.audit.reader import AuditLogReader
from guardian_agent.audit.signature import (
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
)
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.errors import GuardianHaltedError, PolicyDenialError
from guardian_agent.estop.local import EStopLocal
from guardian_agent.gate.two_key import (
    OperatorConfirmationGate,
    OperatorConfirmationRequest,
    OperatorConfirmationResponse,
    callback_operator_gate,
    deny_all_operator_gate,
)
from guardian_agent.policy.evaluator import PolicyEvaluator
from guardian_agent.policy.gate_adapter import PolicyStoreGate
from guardian_agent.policy.store import PolicyStore, PolicyStoreOptions
from guardian_agent.policy.types import Policy, PolicyDefaults, PolicyRule
from guardian_agent.runtime import (
    CapabilityRule,
    GuardianRuntime,
    GuardianRuntimeOptions,
    Honeytoken,
    PolicyIdentifierCall,
    define_honeytoken_set,
)


def _runtime(tmp_path: Path, **kw: Any) -> GuardianRuntime:
    priv_pem, _ = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    audit = AuditLogWriter(AuditLogWriterOptions(
        path=str(tmp_path / "audit.jsonl"),
        agent_id="agent-int",
        session_id="sess-int",
        sign_with=priv,
    ))
    return GuardianRuntime(GuardianRuntimeOptions(
        agent_id="agent-int",
        session_id="sess-int",
        audit=audit,
        estop=EStopLocal(audit=audit),
        **kw,
    ))


def _records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    return [json.loads(l) for l in text.splitlines() if l]


# ---- honeytoken integration --------------------------------------------


def test_honeytoken_value_in_args_halts(tmp_path: Path):
    honey = define_honeytoken_set(
        "test",
        [Honeytoken(id="aws-fake", value="AKIA00DECOY00")],
    )
    rt = _runtime(tmp_path, honeytokens=honey)
    callable_tool = rt.tool(lambda **kw: kw, name="read_secret")
    with pytest.raises(GuardianHaltedError, match="honeytoken"):
        callable_tool(key="AKIA00DECOY00")
    rt.close()
    rows = _records(tmp_path / "audit.jsonl")
    kinds = [r["kind"] for r in rows]
    assert "x_honeytoken_triggered" in kinds
    # estop must have been pressed (subsequent calls would refuse)
    halt_row = next(r for r in rows if r["kind"] == "x_honeytoken_triggered")
    assert halt_row["status"] == "halted"
    assert halt_row["detail"]["set_id"] == "test"


def test_honeytoken_phantom_tool_halts(tmp_path: Path):
    honey = define_honeytoken_set(
        "test",
        [Honeytoken(id="dummy", value="never_appears")],
        phantom_tools=["delete_account_unsafe"],
    )
    rt = _runtime(tmp_path, honeytokens=honey)
    bait = rt.tool(lambda **kw: kw, name="delete_account_unsafe")
    with pytest.raises(GuardianHaltedError):
        bait(target="me")
    rt.close()
    rows = _records(tmp_path / "audit.jsonl")
    hit = next(r for r in rows if r["kind"] == "x_honeytoken_triggered")
    assert hit["detail"]["hit_kind"] == "phantom_tool"
    assert hit["detail"]["tool_name"] == "delete_account_unsafe"


# ---- capability tags + yellow rule -------------------------------------


def test_capability_yellow_rule_fires_on_combination(tmp_path: Path):
    rule = CapabilityRule(
        id="exfil-shape",
        combination=["credential", "network-egress", "write"],
        window_ms=60_000,
    )
    rt = _runtime(tmp_path, capability_rules=[rule])
    cred = rt.tool(lambda: "ok", name="read_credential", capabilities=["credential"])
    net = rt.tool(lambda: "ok", name="http_get", capabilities=["network-egress"])
    write = rt.tool(lambda: "ok", name="kb_write", capabilities=["write"])

    cred()
    net()
    write()
    rt.close()

    rows = _records(tmp_path / "audit.jsonl")
    yellows = [r for r in rows if r["kind"] == "x_capability_yellow"]
    assert len(yellows) == 1
    assert yellows[0]["detail"]["rule_id"] == "exfil-shape"
    # Each tool_call carries the per-tool capabilities
    tool_calls = [r for r in rows if r["kind"] == "tool_call"]
    assert tool_calls[0]["tool"]["capabilities"] == ["credential"]
    assert tool_calls[1]["tool"]["capabilities"] == ["network-egress"]
    assert tool_calls[2]["tool"]["capabilities"] == ["write"]


# ---- requires_operator_confirmation -----------------------------------


def test_operator_confirmation_approved_proceeds(tmp_path: Path):
    seen: list[OperatorConfirmationRequest] = []

    def gate_fn(req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:
        seen.append(req)
        return OperatorConfirmationResponse(decision="approved", operator_id="alice")

    rt = _runtime(tmp_path, operator_gate=callback_operator_gate(gate_fn))
    wire = rt.tool(
        lambda **kw: {"sent": kw},
        name="wire_transfer",
        capabilities=["network-egress", "credential"],
        requires_operator_confirmation=True,
        operator_confirmation_reason="sensitive_action",
        operator_confirmation_timeout_ms=2000,
    )
    out = wire(amount=100)
    assert out == {"sent": {"amount": 100}}
    assert len(seen) == 1
    rt.close()
    rows = _records(tmp_path / "audit.jsonl")
    pending = next(r for r in rows if r.get("status") == "pending_operator")
    approved = next(r for r in rows if r.get("status") == "approved" and r.get("initiator") == "operator")
    assert pending["detail"]["gate_id"] == approved["detail"]["gate_id"]


def test_operator_confirmation_denied_throws(tmp_path: Path):
    rt = _runtime(tmp_path, operator_gate=deny_all_operator_gate("nope"))
    wire = rt.tool(
        lambda: "done",
        name="wire_transfer",
        requires_operator_confirmation=True,
        operator_confirmation_timeout_ms=500,
    )
    with pytest.raises(GuardianHaltedError, match="denied"):
        wire()


def test_operator_confirmation_required_without_gate_raises(tmp_path: Path):
    rt = _runtime(tmp_path)  # no operator_gate
    wire = rt.tool(
        lambda: "done",
        name="wire_transfer",
        requires_operator_confirmation=True,
    )
    with pytest.raises(RuntimeError, match="operator_gate"):
        wire()


# ---- policy gate (allow / deny / prompt) ------------------------------


def _store_with_rule(tmp_path: Path, rule: PolicyRule) -> PolicyStoreGate:
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="agent-int"))
    store.add_rule(rule)
    return PolicyStoreGate(store)


def test_policy_allow_passes_dispatch(tmp_path: Path):
    gate = _store_with_rule(tmp_path, PolicyRule(tool="ls", scope="forever", decision="allow"))
    rt = _runtime(
        tmp_path,
        policy=gate,
        policy_identifier=lambda call: call.name,
    )
    out = rt.tool(lambda: ["a", "b"], name="ls")()
    assert out == ["a", "b"]


def test_policy_deny_raises(tmp_path: Path):
    gate = _store_with_rule(tmp_path, PolicyRule(tool="rm", scope="banned"))
    rt = _runtime(tmp_path, policy=gate, policy_identifier=lambda call: call.name)
    with pytest.raises(PolicyDenialError) as exc_info:
        rt.tool(lambda: "deleted", name="rm")()
    assert exc_info.value.scope == "banned"


def test_policy_prompt_without_operator_gate_denies(tmp_path: Path):
    # Empty policy defaults to prompt; no operator gate → deny
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="agent-int"))
    gate = PolicyStoreGate(store)
    rt = _runtime(tmp_path, policy=gate, policy_identifier=lambda call: call.name)
    with pytest.raises(PolicyDenialError, match="no operator_gate"):
        rt.tool(lambda: "ok", name="unknown_tool")()


def test_policy_prompt_with_operator_gate_routes_through(tmp_path: Path):
    seen: list[OperatorConfirmationRequest] = []

    def gate_fn(req: OperatorConfirmationRequest) -> OperatorConfirmationResponse:
        seen.append(req)
        return OperatorConfirmationResponse(decision="approved", operator_id="op-1")

    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="agent-int"))
    pgate = PolicyStoreGate(store)
    rt = _runtime(
        tmp_path,
        policy=pgate,
        policy_identifier=lambda call: f"mcp.tool:{call.name}",
        operator_gate=callback_operator_gate(gate_fn),
        operator_timeout_ms=2000,
    )
    out = rt.tool(lambda: "ok", name="youtube/list_videos")()
    assert out == "ok"
    assert len(seen) == 1
    assert seen[0].policy_context is not None
    axes = seen[0].policy_context.drilldown_axes
    # default axes include exact + container + category
    keys = {a["key"] for a in axes}
    assert keys == {"exact", "container", "category"}


def test_policy_identifier_split_with_no_colon(tmp_path: Path):
    """Identifier without a colon → category='' + identifier=whole."""
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="agent-int"))
    store.add_rule(PolicyRule(tool="ls", scope="forever", decision="allow"))
    rt = _runtime(tmp_path, policy=PolicyStoreGate(store), policy_identifier=lambda c: "ls")
    rt.tool(lambda: "ok", name="ls")()


# ---- tool_call carries capabilities on every record ------------------


def test_tool_call_record_includes_capabilities(tmp_path: Path):
    rt = _runtime(tmp_path)
    rt.tool(lambda x: x * 2, name="double", capabilities=["read", "execute"])(5)
    rt.close()
    rows = _records(tmp_path / "audit.jsonl")
    tc = next(r for r in rows if r["kind"] == "tool_call")
    pc = next(r for r in rows if r["kind"] == "policy_check")
    tr = next(r for r in rows if r["kind"] == "tool_result")
    for r in (tc, pc, tr):
        assert r["tool"]["capabilities"] == ["read", "execute"]
