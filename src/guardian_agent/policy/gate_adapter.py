"""`policy_store_gate` — wrap a PolicyStore into the PolicyGate shape.

SPEC §3.5 + runtime integration (v0.2+).

The most common pattern is "evaluator over the policy the store holds, with
persist forwarding to store.add_rule". This adapter spares each surface from
writing that wrapper inline.

The adapter re-reads the policy on every evaluate() so operator-persisted
rules from earlier in the same session are visible immediately. Set
`cache=True` if the consumer manages invalidation explicitly.

`PolicyGate` itself is a Protocol declared in the runtime module (where the
runtime consumes it). We accept any object with the two methods rather than
importing it here to keep the policy module free of a runtime dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol

from ..types import ModelAttribution
from .evaluator import PolicyEvaluator
from .store import PolicyStore
from .types import Policy, PolicyEvaluation, PolicyRule


class PolicyGate(Protocol):
    """Shape the runtime consumes. Duplicated here to avoid a runtime import."""

    def evaluate(self, tool_name: str, model: Optional[ModelAttribution] = None) -> PolicyEvaluation:
        ...

    def persist(self, rule: PolicyRule) -> None:
        ...


@dataclass
class PolicyStoreGateOptions:
    cache: bool = False


class PolicyStoreGate:
    """A PolicyGate backed by a PolicyStore. Reads + writes go through the store."""

    def __init__(self, store: PolicyStore, options: Optional[PolicyStoreGateOptions] = None) -> None:
        self._store = store
        self._cache = (options or PolicyStoreGateOptions()).cache
        self._cached: Optional[Policy] = None

    def _get_policy(self) -> Policy:
        if self._cache and self._cached is not None:
            return self._cached
        fresh = self._store.get_policy()
        if self._cache:
            self._cached = fresh
        return fresh

    def evaluate(self, tool_name: str, model: Optional[ModelAttribution] = None) -> PolicyEvaluation:
        return PolicyEvaluator(self._get_policy()).evaluate(tool_name, model)

    def persist(self, rule: PolicyRule) -> None:
        self._store.add_rule(rule)
        self._cached = None

    def invalidate(self) -> None:
        self._cached = None


def policy_store_gate(
    store: PolicyStore,
    options: Optional[PolicyStoreGateOptions] = None,
) -> PolicyStoreGate:
    return PolicyStoreGate(store, options)
