"""Model-attribution path rendering + flat-glob matching. SPEC §3 extension (v0.7+).

A ModelAttribution renders to a 4-segment path:

    surface / aggregator / provider / id

Missing segments render as `'*'`. Examples:

    ModelAttribution(provider="Anthropic", id="claude-opus-4.5")
      → "*/*/Anthropic/claude-opus-4.5"

    ModelAttribution(surface="FlowDot", aggregator="RedPill",
                     provider="Anthropic", id="claude-opus-4.5")
      → "FlowDot/RedPill/Anthropic/claude-opus-4.5"

Pattern matching is **flat-glob**: `*` matches any run of characters INCLUDING
`/`. This lets simple substring-style patterns like `*claude-opus*` match the
rendered path regardless of which provider, aggregator, or surface issued the
call. Authors who want to constrain a specific segment write the slashes
explicitly:

    "*/RedPill/*/*"               → anything routed through RedPill
    "FlowDot/*/Anthropic/*"       → any Anthropic model on the FlowDot surface
    "*/*/Anthropic/claude-*-4.5*" → any claude-*-4.5* from Anthropic
    "*claude-opus*"                → any claude-opus model, anywhere
"""

from __future__ import annotations

import re
from typing import Optional

from ..types import ModelAttribution

ATTRIBUTION_MISSING_SEGMENT = "*"


def render_attribution_path(attribution: ModelAttribution) -> str:
    """Render a ModelAttribution as a 4-segment path. Missing fields → '*'."""
    surface = attribution.surface or ATTRIBUTION_MISSING_SEGMENT
    aggregator = attribution.aggregator or ATTRIBUTION_MISSING_SEGMENT
    return f"{surface}/{aggregator}/{attribution.provider}/{attribution.id}"


def match_attribution_path(pattern: str, attribution: ModelAttribution) -> bool:
    """Test a flat-glob pattern against the rendered attribution path."""
    return flat_glob_match(pattern, render_attribution_path(attribution))


def flat_glob_match(pattern: str, value: str) -> bool:
    """Pattern matching against an arbitrary string.

    Pattern syntax:
      `*`     — any run of characters, including `/`
      `?`     — exactly one character (including `/`)
      `[seq]` — character class
      `[!seq]` — negated character class

    The pattern is anchored: it matches the full value, not a prefix.
    """
    return _flat_glob_to_regex(pattern).match(value) is not None


def _flat_glob_to_regex(pattern: str) -> re.Pattern[str]:
    out = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            out.append(".*")
            i += 1
        elif c == "?":
            out.append(".")
            i += 1
        elif c == "[":
            end = i + 1
            negate = False
            if end < len(pattern) and pattern[end] == "!":
                negate = True
                end += 1
            body_parts: list[str] = []
            while end < len(pattern) and pattern[end] != "]":
                body_parts.append(pattern[end])
                end += 1
            if end >= len(pattern):
                # Unterminated → treat the original `[` as a literal
                out.append(re.escape(c))
                i += 1
            else:
                body = "".join(body_parts)
                body = body.replace("\\", "\\\\").replace("]", "\\]")
                out.append("[" + ("^" if negate else "") + body + "]")
                i = end + 1
        else:
            out.append(re.escape(c))
            i += 1
    out.append("$")
    return re.compile("".join(out), re.DOTALL)
