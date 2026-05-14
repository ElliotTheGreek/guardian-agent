"""Tests for policy/* modules."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest
import yaml

from guardian_agent.errors import GuardianConfigError, GuardianIntegrityError
from guardian_agent.policy.evaluator import PolicyEvaluator, glob_match
from guardian_agent.policy.integrity import sign_payload, verify_payload
from guardian_agent.policy.loader import parse_policy, validate_policy
from guardian_agent.policy.site_key import (
    SITE_KEY_BYTES,
    load_or_create_site_key,
    site_key_from_bytes,
)
from guardian_agent.policy.store import PolicyStore, PolicyStoreOptions
from guardian_agent.policy.types import Policy, PolicyDefaults, PolicyRule, PolicyWhen
from guardian_agent.types import ModelAttribution


# ============================================================================
# integrity
# ============================================================================


def test_integrity_round_trip():
    key = secrets.token_bytes(32)
    sig = sign_payload("hello world", key)
    assert verify_payload("hello world", sig, key) is True


def test_integrity_round_trip_bytes():
    key = secrets.token_bytes(32)
    data = b"hello buffer"
    sig = sign_payload(data, key)
    assert verify_payload(data, sig, key) is True


def test_integrity_rejects_wrong_key():
    a = secrets.token_bytes(32)
    b = secrets.token_bytes(32)
    sig = sign_payload("hi", a)
    assert verify_payload("hi", sig, b) is False


def test_integrity_rejects_tampered_data():
    key = secrets.token_bytes(32)
    sig = sign_payload("hi", key)
    assert verify_payload("ho", sig, key) is False


# ============================================================================
# site_key
# ============================================================================


def test_site_key_generated_when_missing(tmp_path):
    path = tmp_path / "site.key"
    k = load_or_create_site_key(str(path))
    assert len(k.bytes_) == SITE_KEY_BYTES
    assert Path(path).read_bytes() == k.bytes_


def test_site_key_loaded_when_present(tmp_path):
    path = tmp_path / "site.key"
    first = load_or_create_site_key(str(path))
    second = load_or_create_site_key(str(path))
    assert first.bytes_ == second.bytes_


def test_site_key_rejects_wrong_length(tmp_path):
    path = tmp_path / "site.key"
    path.write_bytes(b"short")
    with pytest.raises(GuardianConfigError):
        load_or_create_site_key(str(path))


def test_site_key_creates_parent_dir(tmp_path):
    path = tmp_path / "nested" / "deeper" / "site.key"
    k = load_or_create_site_key(str(path))
    assert len(k.bytes_) == SITE_KEY_BYTES


def test_site_key_from_bytes():
    k = site_key_from_bytes(b"\x07" * 32)
    assert len(k.bytes_) == 32


def test_site_key_from_bytes_rejects_wrong_length():
    with pytest.raises(GuardianConfigError):
        site_key_from_bytes(b"\x00" * 16)


# ============================================================================
# loader
# ============================================================================


def test_loader_parses_minimal_policy():
    p = parse_policy(
        """
version: "0.2"
agent_id: "agent_a"
defaults:
  scope: prompt
rules: []
"""
    )
    assert p.version == "0.2"
    assert p.agent_id == "agent_a"
    assert p.defaults.scope == "prompt"


def test_loader_parses_rules_in_order():
    p = parse_policy(
        """
version: "0.2"
agent_id: "a"
defaults: { scope: prompt }
rules:
  - tool: "filesystem.read"
    scope: forever
    decision: allow
  - tool: "filesystem.write"
    scope: banned
"""
    )
    assert len(p.rules) == 2
    assert p.rules[0].tool == "filesystem.read"


def test_loader_when_clause():
    p = parse_policy(
        """
version: "0.2"
agent_id: "a"
defaults: { scope: prompt }
rules:
  - tool: "t"
    scope: forever
    decision: allow
    when:
      "model.provider": "anthropic"
      "model.id": "claude-*-4.5*"
"""
    )
    assert p.rules[0].when.model_provider == "anthropic"
    assert p.rules[0].when.model_id == "claude-*-4.5*"


@pytest.mark.parametrize(
    "raw,match",
    [
        ("hello", r"object"),
        (None, r"object"),
        ({"agent_id": "a", "defaults": {"scope": "prompt"}}, r"version"),
        ({"version": "0.2", "defaults": {"scope": "prompt"}}, r"agent_id"),
        ({"version": "0.2", "agent_id": "a"}, r"defaults"),
        (
            {"version": "0.2", "agent_id": "a", "defaults": {"scope": "nope"}},
            r"defaults.scope",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt", "decision": "maybe"},
            },
            r"defaults.decision",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": "oops",
            },
            r"rules",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": ["oops"],
            },
            r"rule\[0\]",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"scope": "session"}],
            },
            r"tool",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"tool": "t", "scope": "oops"}],
            },
            r"scope",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"tool": "guardian.foo", "scope": "session"}],
            },
            r"reserved",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"tool": "t", "scope": "session", "decision": "oops"}],
            },
            r"decision",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"tool": "t", "scope": "session", "notes": 7}],
            },
            r"notes",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"tool": "t", "scope": "session", "when": 7}],
            },
            r"when",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"tool": "t", "scope": "session", "when": {"model.provider": 7}}],
            },
            r"model.provider",
        ),
        (
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [{"tool": "t", "scope": "session", "when": {"model.id": 7}}],
            },
            r"model.id",
        ),
    ],
)
def test_loader_rejection_paths(raw, match):
    with pytest.raises(GuardianConfigError, match=match):
        validate_policy(raw)


# ============================================================================
# evaluator
# ============================================================================


def _p(rules: list[PolicyRule], default_scope: str = "prompt") -> Policy:
    return Policy(
        version="0.2",
        agent_id="a",
        defaults=PolicyDefaults(scope=default_scope),
        rules=rules,
    )


def test_evaluator_banned_beats_forever_allow():
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(tool="x", scope="forever", decision="allow"),
                PolicyRule(tool="x", scope="banned"),
            ]
        )
    )
    r = ev.evaluate("x")
    assert r.decision == "deny"
    assert r.scope == "banned"


def test_evaluator_forever_beats_session():
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(tool="x", scope="session", decision="allow"),
                PolicyRule(tool="x", scope="forever", decision="allow"),
            ]
        )
    )
    assert ev.evaluate("x").scope == "forever"


def test_evaluator_exact_beats_wildcard():
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(tool="x.*", scope="forever", decision="allow"),
                PolicyRule(tool="x.specific", scope="session", decision="allow"),
            ]
        )
    )
    # forever wins over session even when exact match is session.
    assert ev.evaluate("x.specific").scope == "forever"


def test_evaluator_falls_through_to_default_prompt():
    ev = PolicyEvaluator(_p([]))
    r = ev.evaluate("unmatched")
    assert r.decision == "prompt"
    assert r.matched_at == "default"


def test_evaluator_default_scope_forever():
    ev = PolicyEvaluator(_p([], default_scope="forever"))
    assert ev.evaluate("u").decision == "allow"


def test_evaluator_default_scope_banned():
    ev = PolicyEvaluator(_p([], default_scope="banned"))
    assert ev.evaluate("u").decision == "deny"


def test_evaluator_wildcard_banned():
    ev = PolicyEvaluator(_p([PolicyRule(tool="x.*", scope="banned")]))
    r = ev.evaluate("x.something")
    assert r.decision == "deny"
    assert r.matched_at == "wildcard"


def test_evaluator_session_deny():
    ev = PolicyEvaluator(_p([PolicyRule(tool="x", scope="session", decision="deny")]))
    r = ev.evaluate("x")
    assert r.decision == "deny"
    assert r.scope == "session"


def test_evaluator_once_allow():
    ev = PolicyEvaluator(_p([PolicyRule(tool="x", scope="once", decision="allow")]))
    assert ev.evaluate("x").decision == "allow"


def test_evaluator_once_deny():
    ev = PolicyEvaluator(_p([PolicyRule(tool="x", scope="once", decision="deny")]))
    assert ev.evaluate("x").decision == "deny"


def test_evaluator_default_decision_override():
    p = Policy(
        version="0.2",
        agent_id="a",
        defaults=PolicyDefaults(scope="forever", decision="deny"),
        rules=[],
    )
    assert PolicyEvaluator(p).evaluate("u").decision == "deny"


# ---- model-aware ------------------------------------------------------------


CLAUDE_OPUS_45 = ModelAttribution(provider="anthropic", id="claude-opus-4.5")
CLAUDE_OPUS_4 = ModelAttribution(provider="anthropic", id="claude-opus-4")
GPT_5 = ModelAttribution(provider="openai", id="gpt-5")
OLLAMA_GEMMA = ModelAttribution(provider="ollama", id="gemma3:12b")


def test_evaluator_when_provider_match():
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(
                    tool="place_order",
                    scope="forever",
                    decision="deny",
                    when=PolicyWhen(model_provider="ollama"),
                )
            ]
        )
    )
    assert ev.evaluate("place_order", OLLAMA_GEMMA).decision == "deny"
    assert ev.evaluate("place_order", CLAUDE_OPUS_45).decision == "prompt"


def test_evaluator_when_model_id_glob():
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(
                    tool="place_order",
                    scope="forever",
                    decision="allow",
                    when=PolicyWhen(model_id="claude-*-4.5*"),
                )
            ]
        )
    )
    assert ev.evaluate("place_order", CLAUDE_OPUS_45).decision == "allow"
    assert ev.evaluate("place_order", CLAUDE_OPUS_4).decision == "prompt"


def test_evaluator_when_provider_and_id():
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(
                    tool="place_order",
                    scope="forever",
                    decision="allow",
                    when=PolicyWhen(model_provider="anthropic", model_id="claude-*-4.5*"),
                )
            ]
        )
    )
    assert ev.evaluate("place_order", CLAUDE_OPUS_45).decision == "allow"
    bad_provider = ModelAttribution(provider="fake", id="claude-opus-4.5")
    assert ev.evaluate("place_order", bad_provider).decision == "prompt"
    assert ev.evaluate("place_order", CLAUDE_OPUS_4).decision == "prompt"


def test_evaluator_when_no_model_provided():
    # Rule needs model.provider; if no model, rule doesn't match.
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(
                    tool="place_order",
                    scope="forever",
                    decision="deny",
                    when=PolicyWhen(model_provider="ollama"),
                )
            ]
        )
    )
    assert ev.evaluate("place_order").decision == "prompt"


def test_evaluator_when_only_model_id_no_model():
    ev = PolicyEvaluator(
        _p(
            [
                PolicyRule(
                    tool="place_order",
                    scope="forever",
                    decision="deny",
                    when=PolicyWhen(model_id="claude-*"),
                )
            ]
        )
    )
    assert ev.evaluate("place_order").decision == "prompt"


def test_evaluator_rule_without_when_matches_anything():
    ev = PolicyEvaluator(_p([PolicyRule(tool="t", scope="forever", decision="allow")]))
    assert ev.evaluate("t", GPT_5).decision == "allow"
    assert ev.evaluate("t").decision == "allow"


def test_glob_match():
    assert glob_match("a.*", "a.b") is True
    assert glob_match("*.b", "a.b") is True
    assert glob_match("*", "anything") is True
    assert glob_match("a.?", "a.b") is True
    assert glob_match("a.?", "a.bc") is False


# ============================================================================
# store
# ============================================================================


def test_store_empty_when_no_files(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    p = store.get_policy()
    assert p.rules == []
    assert p.defaults.scope == "prompt"


def test_store_persists_forever_signed(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(PolicyRule(tool="filesystem.read", scope="forever", decision="allow"))

    raw = (tmp_path / "permissions.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert "signature" in parsed
    assert "filesystem.read" in parsed["data"]

    re = store.get_policy()
    assert len(re.rules) == 1
    assert re.rules[0].tool == "filesystem.read"


def test_store_persists_session_unsigned(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(PolicyRule(tool="lookup", scope="session", decision="allow"))

    session_path = tmp_path / "session.yaml"
    assert session_path.exists()
    parsed = yaml.safe_load(session_path.read_text(encoding="utf-8"))
    assert "signature" not in parsed

    merged = store.get_policy()
    assert merged.rules[0].scope == "session"


def test_store_banned_rule(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(PolicyRule(tool="place_order", scope="banned"))
    assert store.get_policy().rules[0].scope == "banned"


def test_store_replaces_existing_rule(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(PolicyRule(tool="x", scope="forever", decision="allow"))
    store.add_rule(PolicyRule(tool="x", scope="forever", decision="deny"))
    p = store.get_policy()
    assert len(p.rules) == 1
    assert p.rules[0].decision == "deny"


def test_store_remove_rule(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(PolicyRule(tool="x", scope="forever", decision="allow"))
    store.remove_rule("x", "forever")
    assert store.get_policy().rules == []


def test_store_remove_session_rule(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(PolicyRule(tool="x", scope="session", decision="allow"))
    store.remove_rule("x", "session")
    assert store.get_policy().rules == []


def test_store_clear_session(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(PolicyRule(tool="x", scope="session", decision="allow"))
    assert (tmp_path / "session.yaml").exists()
    store.clear_session()
    assert not (tmp_path / "session.yaml").exists()


def test_store_clear_session_when_absent(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.clear_session()  # no-op
    assert not (tmp_path / "session.yaml").exists()


def test_store_rejects_bad_signature(tmp_path):
    path = tmp_path / "permissions.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "signed_at": "2026-01-01T00:00:00Z",
                "signature": "AA==",
                "data": yaml.safe_dump(
                    {
                        "version": "0.2",
                        "agent_id": "a",
                        "defaults": {"scope": "prompt"},
                        "rules": [],
                    }
                ),
            }
        )
    )
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    with pytest.raises(GuardianIntegrityError):
        store.get_policy()


def test_store_rejects_non_signed_file(tmp_path):
    path = tmp_path / "permissions.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": "0.2",
                "agent_id": "a",
                "defaults": {"scope": "prompt"},
                "rules": [],
            }
        )
    )
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    with pytest.raises(GuardianIntegrityError):
        store.get_policy()


def test_store_custom_default_scope(tmp_path):
    store = PolicyStore(
        PolicyStoreOptions(dir=str(tmp_path), agent_id="a", default_scope="forever")
    )
    assert store.get_policy().defaults.scope == "forever"


def test_store_close_idempotent(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.close()
    store.close()


def test_store_empty_session_file(tmp_path):
    (tmp_path / "session.yaml").write_text("", encoding="utf-8")
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    assert store.get_policy().rules == []


def test_store_persists_rule_with_when_and_notes(tmp_path):
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    store.add_rule(
        PolicyRule(
            tool="t",
            scope="forever",
            decision="allow",
            when=PolicyWhen(model_provider="anthropic", model_id="claude-*"),
            notes="conditional rule",
        )
    )
    p = store.get_policy()
    assert p.rules[0].when.model_provider == "anthropic"
    assert p.rules[0].when.model_id == "claude-*"
    assert p.rules[0].notes == "conditional rule"


def test_store_persists_policy_with_defaults_decision(tmp_path):
    """Cover the persist path that includes defaults.decision."""
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    # Bypass _read_persistent so the on-write policy carries defaults.decision.
    p = Policy(
        version="0.2",
        agent_id="a",
        defaults=PolicyDefaults(scope="forever", decision="allow"),
        rules=[],
    )
    store._read_persistent = lambda: p  # type: ignore[method-assign]
    store.add_rule(PolicyRule(tool="x", scope="forever", decision="allow"))
    raw = (tmp_path / "permissions.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert "decision: allow" in parsed["data"]


def test_store_rejects_non_dict_signed_file(tmp_path):
    """Cover the `not isinstance(v, dict)` branch in _is_signed_file."""
    (tmp_path / "permissions.yaml").write_text("just a string\n", encoding="utf-8")
    store = PolicyStore(PolicyStoreOptions(dir=str(tmp_path), agent_id="a"))
    with pytest.raises(GuardianIntegrityError):
        store.get_policy()
