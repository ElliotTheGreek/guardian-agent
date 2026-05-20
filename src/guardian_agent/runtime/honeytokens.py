"""Honeytoken detection. SPEC §11 (v0.3+).

Two zero-false-positive-by-construction defenses:

1. Value match — consumer registers decoy strings or regex patterns that
   should NEVER legitimately appear in a tool call's arguments. The matcher
   walks the canonical-JSON of every tool call's args; any hit means an
   agent has been probing.

2. Phantom tool — consumer registers a tool name that is documented
   internally as "do not call" — never advertised to legitimate agents.
   Any dispatch to that tool name → immediate fire.

Library ships NO DEFAULT TOKENS by design.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal, Optional, Pattern, Union

from ..audit.chain import canonical_json_string


@dataclass
class Honeytoken:
    """A single decoy. EXACTLY ONE of `value` or `pattern` must be set."""

    id: str
    value: Optional[str] = None
    pattern: Optional[Union[str, Pattern[str]]] = None
    description: Optional[str] = None


@dataclass
class HoneytokenSet:
    """A collection of honeytokens for one supervisor instance."""

    id: str
    tokens: list[Honeytoken] = field(default_factory=list)
    phantom_tools: list[str] = field(default_factory=list)
    description: Optional[str] = None


@dataclass
class HoneytokenHit:
    """One hit. `kind` is 'value_in_args' or 'phantom_tool'."""

    kind: Literal["value_in_args", "phantom_tool"]
    token_id: Optional[str] = None
    tool_name: Optional[str] = None


def define_honeytoken_set(
    id: str,
    tokens: list[Honeytoken],
    phantom_tools: Optional[list[str]] = None,
    description: Optional[str] = None,
) -> HoneytokenSet:
    """Build a honeytoken set with id-uniqueness + xor-validation enforced."""
    phantom_tools = list(phantom_tools or [])
    if not tokens and not phantom_tools:
        raise ValueError("define_honeytoken_set: provide at least one token or phantom tool")
    token_ids: set[str] = set()
    for t in tokens:
        if t.id in token_ids:
            raise ValueError(f"define_honeytoken_set: duplicate token id {t.id!r}")
        token_ids.add(t.id)
        has_value = t.value is not None
        has_pattern = t.pattern is not None
        if not has_value and not has_pattern:
            raise ValueError(
                f"define_honeytoken_set: token {t.id!r} must set either value or pattern"
            )
        if has_value and has_pattern:
            raise ValueError(
                f"define_honeytoken_set: token {t.id!r} sets both value and pattern; choose one"
            )
    phantom_seen: set[str] = set()
    for name in phantom_tools:
        if name in phantom_seen:
            raise ValueError(f"define_honeytoken_set: duplicate phantom tool {name!r}")
        phantom_seen.add(name)
    return HoneytokenSet(
        id=id, tokens=list(tokens), phantom_tools=phantom_tools, description=description,
    )


def match_phantom_tool(honeytoken_set: HoneytokenSet, tool_name: str) -> Optional[HoneytokenHit]:
    """Hit if `tool_name` is in the phantom list."""
    if tool_name in honeytoken_set.phantom_tools:
        return HoneytokenHit(kind="phantom_tool", tool_name=tool_name)
    return None


def match_honeytoken_in_args(honeytoken_set: HoneytokenSet, args: Any) -> Optional[HoneytokenHit]:
    """First-hit value/pattern scan of canonical-JSON(args)."""
    if not honeytoken_set.tokens:
        return None
    json_str = canonical_json_string(args)
    for t in honeytoken_set.tokens:
        if t.value is not None:
            if t.value in json_str:
                return HoneytokenHit(kind="value_in_args", token_id=t.id)
        elif t.pattern is not None:
            compiled = t.pattern if isinstance(t.pattern, re.Pattern) else re.compile(t.pattern)
            if compiled.search(json_str):
                return HoneytokenHit(kind="value_in_args", token_id=t.id)
    return None


def check_honeytoken(
    honeytoken_set: HoneytokenSet,
    tool_name: str,
    args: Any,
) -> Optional[HoneytokenHit]:
    """Compose phantom + value-in-args. Phantom wins when both would fire."""
    return match_phantom_tool(honeytoken_set, tool_name) or match_honeytoken_in_args(
        honeytoken_set, args
    )
