"""PolicyEvaluator — resolution order + wildcards + model-aware rules.

SPEC §3.3, §3.4, §3.7 (categories), §3 v0.6 model-aware extension.
"""

from __future__ import annotations

import fnmatch

from ..types import ModelAttribution
from .types import Policy, PolicyEvaluation, PolicyRule, PolicyScope


class PolicyEvaluator:
    """Evaluate a tool name (and optional model attribution) against a policy."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(
        self,
        tool_name: str,
        model: ModelAttribution | None = None,
    ) -> PolicyEvaluation:
        # Banned (forever-deny) — exact then wildcard.
        banned = self._first_match(
            tool_name, lambda r: r.scope == "banned" and _when_matches(r, model)
        )
        if banned is not None:
            return PolicyEvaluation(
                decision="deny",
                matched_rule=banned[0],
                matched_at=banned[1],
                scope="banned",
            )

        for scope in ("forever", "session", "once"):
            allow_match = self._first_match(
                tool_name,
                lambda r, s=scope: r.scope == s
                and _effective_decision(r) == "allow"
                and _when_matches(r, model),
            )
            if allow_match is not None:
                return PolicyEvaluation(
                    decision="allow",
                    matched_rule=allow_match[0],
                    matched_at=allow_match[1],
                    scope=scope,
                )
            deny_match = self._first_match(
                tool_name,
                lambda r, s=scope: r.scope == s
                and _effective_decision(r) == "deny"
                and _when_matches(r, model),
            )
            if deny_match is not None:
                return PolicyEvaluation(
                    decision="deny",
                    matched_rule=deny_match[0],
                    matched_at=deny_match[1],
                    scope=scope,
                )

        d = self.policy.defaults
        if d.scope == "prompt":
            return PolicyEvaluation(
                decision="prompt",
                matched_rule=None,
                matched_at="default",
                scope="prompt",
            )
        decision = d.decision or ("deny" if d.scope == "banned" else "allow")
        return PolicyEvaluation(
            decision=decision,
            matched_rule=None,
            matched_at="default",
            scope=d.scope,
        )

    def _first_match(self, tool_name, pred):
        # Exact match first.
        for rule in self.policy.rules:
            if rule.tool == tool_name and pred(rule):
                return (rule, "exact")
        # Wildcard match (declaration order wins among multiple matches).
        for rule in self.policy.rules:
            if rule.tool == tool_name:
                continue
            if _contains_glob(rule.tool) and glob_match(rule.tool, tool_name) and pred(rule):
                return (rule, "wildcard")
        return None


def _effective_decision(rule: PolicyRule) -> str:
    if rule.scope == "banned":  # pragma: no cover — banned filtered upstream
        return "deny"
    return rule.decision or "allow"


def _when_matches(rule: PolicyRule, model: ModelAttribution | None) -> bool:
    if rule.when is None:
        return True
    if rule.when.model_provider is not None:
        if model is None:
            return False
        if not glob_match(rule.when.model_provider, model.provider):
            return False
    if rule.when.model_id is not None:
        if model is None:
            return False
        if not glob_match(rule.when.model_id, model.id):
            return False
    return True


def _contains_glob(s: str) -> bool:
    return "*" in s or "?" in s or "[" in s


def glob_match(pattern: str, name: str) -> bool:
    """Shell-style glob match. Uses fnmatch under the hood (matches TS impl)."""
    return fnmatch.fnmatchcase(name, pattern)
