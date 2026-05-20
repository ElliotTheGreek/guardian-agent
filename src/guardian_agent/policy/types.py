"""Policy types. SPEC §3."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

PolicyScope = Literal["once", "session", "forever", "banned"]
PolicyDecision = Literal["allow", "deny", "prompt"]
PolicyMatchedAt = Literal["exact", "wildcard", "category", "default"]


@dataclass
class PolicyWhen:
    """Conditional clause; rule only matches when these model attrs match.

    `attribution_path` (v0.7+) is a flat-glob pattern tested against the
    rendered 4-segment path `<surface>/<aggregator>/<provider>/<id>`. Missing
    segments render as `*`. See `policy/attribution.py`.
    """

    model_provider: str | None = None
    model_id: str | None = None
    attribution_path: str | None = None


@dataclass
class PolicyRule:
    """A single rule in the policy."""

    tool: str
    scope: PolicyScope
    decision: Literal["allow", "deny"] | None = None
    when: PolicyWhen | None = None
    notes: str | None = None


@dataclass
class PolicyDefaults:
    """defaults block of a policy."""

    scope: Literal["prompt"] | PolicyScope = "prompt"
    decision: Literal["allow", "deny"] | None = None


@dataclass
class Policy:
    """A loaded policy."""

    version: str
    agent_id: str
    defaults: PolicyDefaults
    rules: list[PolicyRule] = field(default_factory=list)


@dataclass
class PolicyEvaluation:
    """Result of evaluating a tool name against a policy."""

    decision: PolicyDecision
    matched_rule: PolicyRule | None
    matched_at: PolicyMatchedAt
    scope: PolicyScope | Literal["prompt"]
