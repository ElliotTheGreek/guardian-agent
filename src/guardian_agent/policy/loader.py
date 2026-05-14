"""Parse + validate a Policy. SPEC §3.1."""

from __future__ import annotations

from typing import Any

import yaml

from ..errors import GuardianConfigError
from .types import Policy, PolicyDefaults, PolicyRule, PolicyScope, PolicyWhen

VALID_SCOPES: tuple[PolicyScope, ...] = ("once", "session", "forever", "banned")
VALID_DEFAULT_SCOPES = ("prompt", *VALID_SCOPES)


def parse_policy(raw_yaml: str) -> Policy:
    """Parse a YAML string into a validated Policy."""
    return validate_policy(yaml.safe_load(raw_yaml))


def validate_policy(raw: Any) -> Policy:
    """Validate a parsed object as a Policy. Raises GuardianConfigError on issues."""
    if not isinstance(raw, dict):
        raise GuardianConfigError("policy must be an object")

    version = raw.get("version")
    if not isinstance(version, str) or not version:
        raise GuardianConfigError("policy.version must be a non-empty string")
    agent_id = raw.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        raise GuardianConfigError("policy.agent_id must be a non-empty string")

    defaults_raw = raw.get("defaults")
    if not isinstance(defaults_raw, dict):
        raise GuardianConfigError("policy.defaults must be an object")
    defaults_scope = defaults_raw.get("scope")
    if defaults_scope not in VALID_DEFAULT_SCOPES:
        raise GuardianConfigError(
            f"policy.defaults.scope must be one of {', '.join(VALID_DEFAULT_SCOPES)}"
        )
    defaults_decision = defaults_raw.get("decision")
    if defaults_decision is not None and defaults_decision not in ("allow", "deny"):
        raise GuardianConfigError(
            'policy.defaults.decision must be "allow" or "deny" if set'
        )

    rules_raw = raw.get("rules", [])
    if not isinstance(rules_raw, list):
        raise GuardianConfigError("policy.rules must be an array if present")

    rules = [_validate_rule(r, i) for i, r in enumerate(rules_raw)]

    return Policy(
        version=version,
        agent_id=agent_id,
        defaults=PolicyDefaults(scope=defaults_scope, decision=defaults_decision),
        rules=rules,
    )


def _validate_rule(raw: Any, index: int) -> PolicyRule:
    if not isinstance(raw, dict):
        raise GuardianConfigError(f"rule[{index}] must be an object")
    tool = raw.get("tool")
    if not isinstance(tool, str) or not tool:
        raise GuardianConfigError(f"rule[{index}].tool must be a non-empty string")
    if tool.startswith(("guardian.", "runtime.", "internal.")):
        raise GuardianConfigError(f"rule[{index}].tool uses a reserved prefix")

    scope = raw.get("scope")
    if scope not in VALID_SCOPES:
        raise GuardianConfigError(
            f"rule[{index}].scope must be one of {', '.join(VALID_SCOPES)}"
        )

    decision = raw.get("decision")
    if decision is not None and decision not in ("allow", "deny"):
        raise GuardianConfigError(
            f'rule[{index}].decision must be "allow" or "deny" if set'
        )

    notes = raw.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise GuardianConfigError(f"rule[{index}].notes must be a string if set")

    when_raw = raw.get("when")
    when: PolicyWhen | None = None
    if when_raw is not None:
        if not isinstance(when_raw, dict):
            raise GuardianConfigError(f"rule[{index}].when must be an object if set")
        when = PolicyWhen()
        if "model.provider" in when_raw:
            if not isinstance(when_raw["model.provider"], str):
                raise GuardianConfigError(
                    f"rule[{index}].when['model.provider'] must be a string"
                )
            when.model_provider = when_raw["model.provider"]
        if "model.id" in when_raw:
            if not isinstance(when_raw["model.id"], str):
                raise GuardianConfigError(
                    f"rule[{index}].when['model.id'] must be a string"
                )
            when.model_id = when_raw["model.id"]

    return PolicyRule(tool=tool, scope=scope, decision=decision, when=when, notes=notes)
