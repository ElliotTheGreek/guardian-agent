"""Tests for policy/attribution.py + policy/gate_adapter.py."""

from __future__ import annotations

from pathlib import Path

from guardian_agent.policy.attribution import (
    ATTRIBUTION_MISSING_SEGMENT,
    flat_glob_match,
    match_attribution_path,
    render_attribution_path,
)
from guardian_agent.policy.evaluator import PolicyEvaluator
from guardian_agent.policy.gate_adapter import (
    PolicyStoreGate,
    PolicyStoreGateOptions,
    policy_store_gate,
)
from guardian_agent.policy.store import PolicyStore, PolicyStoreOptions
from guardian_agent.policy.types import (
    Policy,
    PolicyDefaults,
    PolicyRule,
    PolicyWhen,
)
from guardian_agent.types import ModelAttribution


# ---- attribution rendering ---------------------------------------------


def test_render_attribution_path_fills_missing_segments_with_wildcard():
    a = ModelAttribution(provider="Anthropic", id="claude-opus-4.5")
    assert render_attribution_path(a) == "*/*/Anthropic/claude-opus-4.5"


def test_render_attribution_path_with_all_segments():
    a = ModelAttribution(
        surface="FlowDot", aggregator="RedPill",
        provider="Anthropic", id="claude-opus-4.5",
    )
    assert render_attribution_path(a) == "FlowDot/RedPill/Anthropic/claude-opus-4.5"


# ---- flat_glob_match ---------------------------------------------------


def test_flat_glob_star_matches_slashes():
    assert flat_glob_match("*claude-opus*", "FlowDot/RedPill/Anthropic/claude-opus-4.5") is True
    assert flat_glob_match("*/RedPill/*/*", "*/RedPill/Anthropic/claude-opus-4.5") is True


def test_flat_glob_anchors_full_string():
    assert flat_glob_match("claude", "claude-opus-4.5") is False
    assert flat_glob_match("claude-*", "claude-opus-4.5") is True


def test_flat_glob_question_mark_single_char():
    assert flat_glob_match("a?c", "abc") is True
    assert flat_glob_match("a?c", "abbc") is False


def test_flat_glob_character_class():
    assert flat_glob_match("v[12]-0", "v1-0") is True
    assert flat_glob_match("v[12]-0", "v3-0") is False


def test_flat_glob_negated_character_class():
    assert flat_glob_match("v[!12]-0", "v3-0") is True
    assert flat_glob_match("v[!12]-0", "v1-0") is False


def test_flat_glob_unterminated_bracket_treated_as_literal():
    # Pattern "v[12" never closes the class → entire pattern just becomes literal
    # for the unterminated portion. The opening `[` becomes literal.
    assert flat_glob_match("v[12", "v[12") is True


# ---- match_attribution_path -------------------------------------------


def test_match_attribution_constrains_specific_segment():
    a = ModelAttribution(
        surface="FlowDot", aggregator="RedPill",
        provider="Anthropic", id="claude-opus-4.5",
    )
    assert match_attribution_path("*/RedPill/*/*", a) is True
    assert match_attribution_path("*/OpenRouter/*/*", a) is False
    assert match_attribution_path("FlowDot/*/Anthropic/*", a) is True


def test_match_attribution_handles_missing_segments():
    a = ModelAttribution(provider="OpenAI", id="gpt-4o")
    # surface + aggregator both render as "*"
    assert match_attribution_path("*/*/OpenAI/*", a) is True
    assert match_attribution_path("FlowDot/*/OpenAI/*", a) is False


# ---- evaluator uses attribution_path -----------------------------------


def _policy_with_when(when: PolicyWhen) -> Policy:
    return Policy(
        version="1",
        agent_id="a",
        defaults=PolicyDefaults(scope="prompt"),
        rules=[
            PolicyRule(tool="wire_transfer", scope="forever", decision="deny", when=when),
        ],
    )


def test_evaluator_attribution_path_when_matches():
    pol = _policy_with_when(PolicyWhen(attribution_path="*/RedPill/*/*"))
    evaluator = PolicyEvaluator(pol)
    via_redpill = ModelAttribution(
        surface="FlowDot", aggregator="RedPill", provider="Anthropic", id="claude-opus-4.5",
    )
    via_openrouter = ModelAttribution(
        surface="FlowDot", aggregator="OpenRouter", provider="Anthropic", id="claude-opus-4.5",
    )
    assert evaluator.evaluate("wire_transfer", via_redpill).decision == "deny"
    assert evaluator.evaluate("wire_transfer", via_openrouter).decision == "prompt"


def test_evaluator_attribution_path_when_requires_model():
    pol = _policy_with_when(PolicyWhen(attribution_path="*/*/Anthropic/*"))
    evaluator = PolicyEvaluator(pol)
    assert evaluator.evaluate("wire_transfer", model=None).decision == "prompt"


# ---- policy_store_gate -------------------------------------------------


def _make_store(tmp_path: Path) -> PolicyStore:
    store = PolicyStore(PolicyStoreOptions(
        dir=str(tmp_path), agent_id="agent-test",
    ))
    return store


def test_policy_store_gate_evaluate_uses_store_policy(tmp_path: Path):
    store = _make_store(tmp_path)
    store.add_rule(PolicyRule(tool="ls", scope="forever", decision="allow"))
    gate = policy_store_gate(store)
    evaluation = gate.evaluate("ls")
    assert evaluation.decision == "allow"
    assert evaluation.matched_at == "exact"


def test_policy_store_gate_persist_forwards_to_store(tmp_path: Path):
    store = _make_store(tmp_path)
    gate = policy_store_gate(store)
    # No rule yet → defaults to prompt
    assert gate.evaluate("ls").decision == "prompt"
    gate.persist(PolicyRule(tool="ls", scope="session", decision="allow"))
    # New rule is visible immediately (cache off by default)
    assert gate.evaluate("ls").decision == "allow"


def test_policy_store_gate_cache_invalidate_path(tmp_path: Path):
    store = _make_store(tmp_path)
    gate = PolicyStoreGate(store, PolicyStoreGateOptions(cache=True))
    # First read populates cache; subsequent writes via store directly aren't visible
    assert gate.evaluate("ls").decision == "prompt"
    store.add_rule(PolicyRule(tool="ls", scope="forever", decision="allow"))
    # With cache=True and out-of-band write, the gate still returns the stale view
    assert gate.evaluate("ls").decision == "prompt"
    gate.invalidate()
    assert gate.evaluate("ls").decision == "allow"
