"""v0.8 negative-corpus harness — the load-bearing 'no false E-stops, ever' test.

Mirrors `guardian-agent-ts/tests/safety/no-false-trip.test.ts` line-for-line.
Replays REAL audit logs from FlowDot's running surfaces through every v0.8
detector at default thresholds and asserts ZERO false positives.

If this test fails, the detector or its thresholds ship as Yellow-only (or
do not ship). Per the plan: 'A mechanism that can't be calibrated to zero
false positives on real data does not ship as an E-stop trigger.'

Fixtures live in `tests/fixtures/negative-corpus-{cli,mcp,py}.jsonl`:
they are snapshots of `~/.flowdot/audit/{cli,mcp,mcp-py}.jsonl` from real
workflow sessions. NEVER hand-edit fixtures — they only have signal as
observed-reality.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from guardian_agent.runtime.capability import (
    CapabilityClass,
    CapabilityRule,
    CapabilityWindow,
    CapabilityWindowOptions,
)
from guardian_agent.runtime.honeytokens import (
    Honeytoken,
    check_honeytoken,
    define_honeytoken_set,
)
from guardian_agent.runtime.multi_rate_limiter import (
    BucketConfig,
    ConsumeDenied,
    DEFAULT_BUCKETS,
    MultiRateLimiter,
    MultiRateLimiterOptions,
)
from guardian_agent.types import AuditRecord

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures"
CORPUS_FILES = [
    "negative-corpus-cli.jsonl",
    "negative-corpus-mcp.jsonl",
    "negative-corpus-py.jsonl",
]


def _load_corpus(file_name: str) -> list[AuditRecord]:
    path = FIXTURE_DIR / file_name
    text = path.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.split("\n") if line.strip()]


# Representative honeytoken set used for the negative-corpus harness. These
# are PLAUSIBLE-but-FAKE tokens — they should not appear in any legitimate
# tool call. The corpus replay verifies that.
NEGATIVE_HONEYTOKENS = define_honeytoken_set(
    "negative-test",
    tokens=[
        Honeytoken(id="fake-aws", pattern=r"AKIA[0-9A-Z]{16}"),
        Honeytoken(id="fake-openai", value="sk-canary-do-not-use-x9q3z7m2p4n6"),
        Honeytoken(id="fake-fd-mcp", value="fd_mcp_honey_DO_NOT_USE_xyz789"),
        Honeytoken(id="fake-bearer-marker", value="BEARER_HONEYTOKEN_MARKER_a1b2c3"),
        Honeytoken(id="fake-path", value="/home/canary/secrets-honey.txt"),
    ],
)

PHANTOM_TOOLS = define_honeytoken_set(
    "phantom-test",
    tokens=[Honeytoken(id="dummy", value="__never_matches__")],
    phantom_tools=[
        "delete_user_account_unsafe",
        "exfiltrate_all_credentials",
        "rm_rf_root",
    ],
)


# ===========================================================================
# Per-corpus replays
# ===========================================================================


@pytest.mark.parametrize("corpus_file", CORPUS_FILES)
def test_fixture_non_trivially_populated(corpus_file: str):
    records = _load_corpus(corpus_file)
    assert len(records) > 0, f"fixture {corpus_file} is empty"


@pytest.mark.parametrize("corpus_file", CORPUS_FILES)
def test_honeytoken_matcher_zero_hits_on_real_args(corpus_file: str):
    records = _load_corpus(corpus_file)
    hits: list[dict[str, Any]] = []
    for r in records:
        tool = r.get("tool")
        if not isinstance(tool, dict) or "args" not in tool or "name" not in tool:
            continue
        hit = check_honeytoken(NEGATIVE_HONEYTOKENS, tool["name"], tool.get("args", {}))
        if hit is not None and hit.kind == "value_in_args":
            hits.append({
                "event_id": r.get("event_id"),
                "tool": tool.get("name"),
                "token_id": hit.token_id,
            })
    assert hits == [], f"unexpected honeytoken hits in {corpus_file}: {hits}"


@pytest.mark.parametrize("corpus_file", CORPUS_FILES)
def test_phantom_tool_matcher_zero_hits_on_real_tool_names(corpus_file: str):
    records = _load_corpus(corpus_file)
    hits: list[str] = []
    for r in records:
        tool = r.get("tool")
        if not isinstance(tool, dict) or "name" not in tool:
            continue
        hit = check_honeytoken(PHANTOM_TOOLS, tool["name"], tool.get("args", {}))
        if hit is not None and hit.kind == "phantom_tool":
            hits.append(tool["name"])
    assert hits == [], f"unexpected phantom-tool hits in {corpus_file}: {hits}"


@pytest.mark.parametrize("corpus_file", CORPUS_FILES)
def test_default_buckets_zero_breaches_when_replaying_real_timing(corpus_file: str):
    """MultiRateLimiter with DEFAULT_BUCKETS produces ZERO breaches.

    Mirrors the TS check exactly. We don't have capability tags on most
    historical records, so every call hits the default bucket (50/s — generous).
    This is the most conservative check; once surfaces are tagging fully,
    this test gets tighter.
    """
    records = _load_corpus(corpus_file)
    tool_calls = [r for r in records if r.get("kind") == "tool_call"]
    if not tool_calls:
        return  # nothing to replay

    from datetime import datetime

    def _ts_to_ms(ts: str) -> float:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0

    start_ts = _ts_to_ms(tool_calls[0].get("ts", "2026-01-01T00:00:00.000Z"))
    now_state = {"t": 0.0}
    limiter = MultiRateLimiter(MultiRateLimiterOptions(
        buckets={**DEFAULT_BUCKETS},
        default_bucket=BucketConfig(max_calls_per_second=50),
        now=lambda: now_state["t"],
    ))
    breaches: list[str] = []
    for r in tool_calls:
        ts = r.get("ts")
        if not isinstance(ts, str):
            continue
        now_state["t"] = _ts_to_ms(ts) - start_ts
        result = limiter.try_consume(["unknown"])
        if isinstance(result, ConsumeDenied):
            breaches.append(r.get("event_id", "?"))
    assert breaches == [], f"unexpected rate-limit breaches in {corpus_file}: {breaches}"


# ===========================================================================
# Aggregate sanity checks
# ===========================================================================


def test_no_corpus_contains_x_capability_redline_or_x_honeytoken_triggered():
    """Sanity check the corpus itself — a corrupt fixture would invalidate everything."""
    for f in CORPUS_FILES:
        for r in _load_corpus(f):
            k = r.get("kind", "")
            assert not k.startswith("x_capability_redline"), f"{f}: redline row found"
            assert not k.startswith("x_honeytoken_triggered"), f"{f}: honeytoken row found"


def test_no_corpus_contains_pending_operator_status():
    """v0.9: no surface has wired operator confirmation into real workflows yet."""
    for f in CORPUS_FILES:
        for r in _load_corpus(f):
            assert r.get("status") != "pending_operator", (
                f"{f}: pending_operator row found — refresh the corpus + tighten this check"
            )


def test_no_corpus_contains_heartbeat_missed_estop_press():
    """v0.9: heartbeat is opt-in. A heartbeat_missed estop_press would mean a surface
    enabled heartbeat without wiring heartbeat() calls — i.e., a false E-stop."""
    for f in CORPUS_FILES:
        offenders = [
            r for r in _load_corpus(f)
            if r.get("kind") == "estop_press"
            and r.get("detail", {}).get("reason") == "heartbeat_missed"
        ]
        assert offenders == [], f"{f}: heartbeat_missed estop_press rows present"


# ===========================================================================
# Capability-rule retroactive replay (the exfil-shape Yellow rule)
# ===========================================================================
#
# Historical tool_call records (cli + mcp corpora) pre-date capability tagging
# and carry no `tool.capabilities` field. To validate the proposed Yellow rule
# against real workflows we have to retro-tag using simplified replicas of
# the per-surface tagging tables.
#
# Drift risk: refresh these tables when the surface tables change.


def _retro_tag_mcp(tool_name: str) -> list[CapabilityClass]:
    exact: dict[str, list[CapabilityClass]] = {
        "whoami": ["read", "network-egress", "credential"],
        "agent_chat": ["execute", "network-egress", "credential"],
        "panic_status": ["read"],
        "panic_stop": ["execute", "credential"],
        "panic_clear": ["execute", "credential"],
        "email_send": ["write", "network-egress", "credential"],
        "email_reply": ["write", "network-egress", "credential"],
        "email_draft": ["write", "network-egress", "credential"],
        "email_archive": ["write", "network-egress", "credential"],
        "email_label": ["write", "network-egress", "credential"],
        "email_delete": ["delete", "network-egress", "credential"],
        "email_list_threads": ["read", "network-egress", "credential"],
        "email_search": ["read", "network-egress", "credential"],
        "email_read": ["read", "network-egress", "credential"],
        "search": ["read", "network-egress", "credential"],
        "send_notification": ["write", "network-egress", "credential"],
        "query_knowledge_base": ["read", "network-egress", "credential"],
    }
    # Strip mcp__<server>__ prefix if present (toolkit doubling).
    stripped = tool_name
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        if len(parts) >= 3:
            stripped = "__".join(parts[2:])
    if tool_name in exact:
        return list(exact[tool_name])
    if stripped in exact:
        return list(exact[stripped])

    write_prefixes = (
        "add_", "create_", "update_", "insert_", "append_", "prepend_", "patch_",
        "set_", "toggle_", "favorite_", "vote_", "link_", "unlink_", "move_",
        "transfer_", "publish_", "unpublish_", "reprocess_", "upload_", "clone_",
        "duplicate_", "fork_", "copy_", "complete_", "abandon_", "pause_",
        "resume_", "retry_", "share_", "install_", "checkpoint_", "restore_",
        "rename_", "edit_",
    )
    read_prefixes = (
        "list_", "get_", "search_", "browse_", "find_", "query_", "describe_",
        "validate_",
    )
    execute_prefixes = (
        "execute_", "cancel_", "stream_", "invoke_", "emit_", "test_", "check_",
    )
    if stripped.startswith("delete_"):
        return ["delete", "network-egress", "credential"]
    if stripped.startswith("uninstall_"):
        return ["delete", "network-egress", "credential"]
    for p in write_prefixes:
        if stripped.startswith(p):
            return ["write", "network-egress", "credential"]
    for p in read_prefixes:
        if stripped.startswith(p):
            return ["read", "network-egress", "credential"]
    for p in execute_prefixes:
        if stripped.startswith(p):
            return ["execute", "network-egress", "credential"]
    return ["unknown"]


def _retro_tag_cli(action: str) -> list[CapabilityClass]:
    builtin: dict[str, list[CapabilityClass]] = {
        "read": ["read"],
        "search": ["read"],
        "analyze": ["read"],
        "find-definition": ["read"],
        "edit-file": ["write"],
        "create-file": ["write"],
        "execute-command": ["execute", "system-path"],
        "web-search": ["read", "network-egress"],
        "fetch-url": ["read", "network-egress"],
        "query-knowledge-base": ["read", "network-egress", "credential"],
        "list-knowledge-documents": ["read", "network-egress", "credential"],
        "get-knowledge-document": ["read", "network-egress", "credential"],
        "get-knowledge-document-content": ["read", "network-egress", "credential"],
        "update-knowledge-document-content": ["write", "network-egress", "credential"],
        "patch-knowledge-document-section": ["write", "network-egress", "credential"],
        "list-knowledge-categories": ["read", "network-egress", "credential"],
        "create-knowledge-category": ["write", "network-egress", "credential"],
        "upload-knowledge-text": ["write", "network-egress", "credential"],
        "get-knowledge-storage": ["read", "network-egress", "credential"],
        "send-notification": ["write", "network-egress", "credential"],
    }
    return list(builtin.get(action, ["unknown"]))


def _retro_tag_py(tool_name: str) -> list[CapabilityClass]:
    """flowdot-mcp-py records DO carry tool.capabilities natively (post-Phase A),
    so this is only used if a record predates capability tagging. Mirrors
    flowdot-mcp-py/src/flowdot_mcp_py/supervisor/tool_capabilities.py.
    """
    mapping: dict[str, list[CapabilityClass]] = {
        "whoami": ["read", "credential"],
        "workflows.list": ["read", "network-egress"],
        "workflows.get": ["read", "network-egress"],
        "workflows.execute": ["execute", "network-egress"],
        "recipes.list": ["read", "network-egress"],
        "recipes.get": ["read", "network-egress"],
    }
    return list(mapping.get(tool_name, ["unknown"]))


def _retro_tag(record: AuditRecord) -> list[CapabilityClass]:
    tool = record.get("tool") or {}
    if not isinstance(tool, dict):
        return ["unknown"]
    # Prefer the natively-recorded capabilities if present (post-Phase A logs).
    declared = tool.get("capabilities")
    if isinstance(declared, list) and all(isinstance(c, str) for c in declared):
        return list(declared)
    name = tool.get("name", "")
    if not isinstance(name, str) or not name:
        return ["unknown"]
    agent_id = record.get("agent_id", "")
    if agent_id == "flowdot-cli":
        return _retro_tag_cli(name)
    if agent_id == "flowdot-mcp-py":
        return _retro_tag_py(name)
    return _retro_tag_mcp(name)


EXFIL_SHAPE_RULE = CapabilityRule(
    id="exfil-shape",
    combination=["credential", "network-egress", "write"],
    window_ms=60_000,
    level="yellow",
)


@pytest.mark.parametrize("corpus_file", CORPUS_FILES)
def test_exfil_shape_yellow_rule_zero_false_fires(corpus_file: str):
    records = _load_corpus(corpus_file)
    tool_calls = [r for r in records if r.get("kind") == "tool_call" and r.get("tool")]
    if not tool_calls:
        return  # nothing to replay (cli corpus is mostly session lifecycle)

    from datetime import datetime

    def _ts_to_ms(ts: str) -> float:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0

    clock_state = {"t": 0.0}
    window = CapabilityWindow(CapabilityWindowOptions(
        rules=[EXFIL_SHAPE_RULE],
        now=lambda: clock_state["t"],
    ))
    fires: list[dict[str, Any]] = []
    for r in tool_calls:
        ts = r.get("ts")
        if not isinstance(ts, str):
            continue
        clock_state["t"] = _ts_to_ms(ts)
        caps = _retro_tag(r)
        matches = window.record(caps, r.get("event_id", "?"))
        for m in matches:
            tool = r.get("tool") or {}
            fires.append({
                "event_id": r.get("event_id"),
                "tool": tool.get("name") if isinstance(tool, dict) else "?",
                "rule_id": m.rule_id,
            })

    # If this assertion fails, either (a) the corpus genuinely contains the
    # exfil-shape pattern (operator review needed) or (b) the proposed Yellow
    # rule is too broad and needs tightening before deployment. Per plan:
    # "no false E-stops, ever" applies to Yellow data feeding Red promotion too.
    assert fires == [], f"unexpected exfil-shape Yellow fires in {corpus_file}: {fires}"
