"""Capability tags + sliding-window combination detection.

SPEC §4 extension (v0.3+). Each tool is tagged with capability classes. The
supervisor maintains a per-session sliding window of recent tool calls + their
capability sets. Rules describe "suspicious combinations" — class lists that,
if all observed within window_ms, fire an event.

v0.8 ships YELLOW ONLY: a combination match writes x_capability_yellow to
the audit log; dispatch is NOT blocked. Red-line auto-stop ships once Yellow
corpora justify thresholds.

Pure mechanism: tag lookup + set membership over a fixed-window event list.
Constant memory per session (oldest events drop as the window slides).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional

CapabilityClass = str

CAPABILITY_CLASSES_DOC = """\
Canonical capability classes:
  read            — pure read of agent-accessible data
  write           — local write
  delete          — destruction
  execute         — run a subprocess / arbitrary code
  network-egress  — outbound network call
  network-ingress — accept inbound network call
  credential      — read or write credentials
  system-path     — touch OS-level paths (/etc, ~/.ssh, etc.)
  bulk            — operation over many items
  unknown         — fallback for untagged tools

Consumers MAY register additional class strings; the matcher treats them as
opaque tags.
"""

RuleLevel = Literal["yellow", "red"]


@dataclass
class CapabilityRule:
    """One rule in the capability rule set."""

    id: str
    combination: list[CapabilityClass]
    window_ms: int
    level: RuleLevel = "yellow"
    description: Optional[str] = None


@dataclass
class CapabilityEvent:
    """Synthesized by the supervisor after every dispatched tool call."""

    ts: float
    classes: list[CapabilityClass]
    event_id: str


@dataclass
class CapabilityMatch:
    """Result of a rule firing on a recorded event."""

    rule_id: str
    level: RuleLevel
    combination: list[CapabilityClass]
    window_ms: int
    contributing_event_ids: list[str]


@dataclass
class CapabilityWindowOptions:
    rules: list[CapabilityRule] = field(default_factory=list)
    now: Optional[Callable[[], float]] = None
    """Time source returning ms. Defaults to time.monotonic()*1000."""
    max_events: int = 10_000


def _default_now_ms() -> float:
    return time.monotonic() * 1000.0


class CapabilityWindow:
    """Per-session sliding-window state. One instance per supervisor."""

    def __init__(self, options: CapabilityWindowOptions) -> None:
        self._rules = list(options.rules)
        self._now = options.now or _default_now_ms
        self._max_events = options.max_events
        self._max_window_ms: float = max((r.window_ms for r in self._rules), default=0)
        self._events: list[CapabilityEvent] = []
        for r in self._rules:
            if not r.combination:
                raise ValueError(f"CapabilityRule {r.id!r} has empty combination")
            if r.window_ms <= 0:
                raise ValueError(f"CapabilityRule {r.id!r} has non-positive window_ms")

    def record(self, classes: list[CapabilityClass], event_id: str) -> list[CapabilityMatch]:
        """Record a tool dispatch + evaluate all rules. Returns fires (often empty)."""
        ts = self._now()
        event = CapabilityEvent(ts=ts, classes=list(classes), event_id=event_id)
        self._events.append(event)

        if self._max_window_ms > 0:
            cutoff = ts - self._max_window_ms
            while self._events and self._events[0].ts < cutoff:
                self._events.pop(0)
        while len(self._events) > self._max_events:
            self._events.pop(0)

        matches: list[CapabilityMatch] = []
        for rule in self._rules:
            m = self._evaluate_rule(rule, ts)
            if m is not None:
                matches.append(m)
        return matches

    def buffered(self) -> list[CapabilityEvent]:
        """Snapshot of currently-buffered events (tests + introspection)."""
        return list(self._events)

    def _evaluate_rule(self, rule: CapabilityRule, now: float) -> Optional[CapabilityMatch]:
        cutoff = now - rule.window_ms
        required = set(rule.combination)
        contributors: dict[CapabilityClass, CapabilityEvent] = {}
        for ev in reversed(self._events):
            if ev.ts < cutoff:
                break
            for cls in ev.classes:
                if cls in required and cls not in contributors:
                    contributors[cls] = ev
            if len(contributors) == len(required):
                break
        if len(contributors) < len(required):
            return None
        sorted_events = sorted(contributors.values(), key=lambda e: e.ts)
        ids: list[str] = []
        for ev in sorted_events:
            if ev.event_id not in ids:
                ids.append(ev.event_id)
        return CapabilityMatch(
            rule_id=rule.id,
            level=rule.level,
            combination=list(rule.combination),
            window_ms=rule.window_ms,
            contributing_event_ids=ids,
        )
