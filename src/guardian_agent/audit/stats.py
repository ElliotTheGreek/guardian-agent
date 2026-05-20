"""Behavioral baselines + descriptive statistics on audit-record streams.

SPEC §13 (v0.5+). Used by the offline `guardian-baseline` CLI; NEVER consulted
by the supervisor in the hot path (that would re-introduce judgment).

All functions are pure: same input → same output. The "is this deviation
significant?" question is mathematically grounded (mean + σ thresholds) but
operationally judgment-laden, so the library produces descriptive reports
and lets the operator decide what to do.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, Sequence

from ..types import AuditRecord

PROFILE_SCHEMA_VERSION = "1"


# ===========================================================================
# AgentProfile
# ===========================================================================


@dataclass
class AgentProfile:
    """Per-agent statistical summary. SPEC §17.2."""

    agent_id: str
    session_count: int
    total_records: int
    tool_call_count: int
    avg_session_length_events: float
    stddev_session_length_events: float
    avg_session_duration_ms: float
    stddev_session_duration_ms: float
    tool_frequency: dict[str, int] = field(default_factory=dict)
    hour_of_day: list[int] = field(default_factory=lambda: [0] * 24)
    kind_frequency: dict[str, int] = field(default_factory=dict)
    status_frequency: dict[str, int] = field(default_factory=dict)
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None
    generated_at: str = ""
    v: str = PROFILE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Match the TS impl's serialization keys (snake_case)."""
        return {
            "agent_id": self.agent_id,
            "v": self.v,
            "session_count": self.session_count,
            "total_records": self.total_records,
            "tool_call_count": self.tool_call_count,
            "avg_session_length_events": self.avg_session_length_events,
            "stddev_session_length_events": self.stddev_session_length_events,
            "avg_session_duration_ms": self.avg_session_duration_ms,
            "stddev_session_duration_ms": self.stddev_session_duration_ms,
            "tool_frequency": dict(self.tool_frequency),
            "hour_of_day": list(self.hour_of_day),
            "kind_frequency": dict(self.kind_frequency),
            "status_frequency": dict(self.status_frequency),
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AgentProfile":
        return cls(
            agent_id=payload["agent_id"],
            v=payload.get("v", PROFILE_SCHEMA_VERSION),
            session_count=int(payload["session_count"]),
            total_records=int(payload["total_records"]),
            tool_call_count=int(payload["tool_call_count"]),
            avg_session_length_events=float(payload["avg_session_length_events"]),
            stddev_session_length_events=float(payload["stddev_session_length_events"]),
            avg_session_duration_ms=float(payload["avg_session_duration_ms"]),
            stddev_session_duration_ms=float(payload["stddev_session_duration_ms"]),
            tool_frequency=dict(payload.get("tool_frequency", {})),
            hour_of_day=list(payload.get("hour_of_day", [0] * 24)),
            kind_frequency=dict(payload.get("kind_frequency", {})),
            status_frequency=dict(payload.get("status_frequency", {})),
            first_ts=payload.get("first_ts"),
            last_ts=payload.get("last_ts"),
            generated_at=payload.get("generated_at", ""),
        )


def analyze_agent(records: Iterable[AuditRecord], agent_id: str) -> AgentProfile:
    """Build a profile for one agent_id from a flat record stream."""
    filtered = [r for r in records if r.get("agent_id") == agent_id]
    return _build_profile(filtered, agent_id)


def analyze_multi_agent(records: Iterable[AuditRecord]) -> dict[str, AgentProfile]:
    """Bucket by agent_id and produce one profile per agent."""
    groups: dict[str, list[AuditRecord]] = {}
    for r in records:
        aid = r.get("agent_id")
        if not isinstance(aid, str):
            continue
        groups.setdefault(aid, []).append(r)
    return {aid: _build_profile(group, aid) for aid, group in groups.items()}


def _build_profile(records: list[AuditRecord], agent_id: str) -> AgentProfile:
    sessions: dict[str, list[AuditRecord]] = {}
    for r in records:
        sid = r.get("session_id", "")
        sessions.setdefault(sid, []).append(r)

    events_per_session: list[float] = []
    durations_ms: list[float] = []
    for group in sessions.values():
        events_per_session.append(float(len(group)))
        if len(group) < 2:
            durations_ms.append(0.0)
            continue
        sorted_group = sorted(group, key=lambda r: r.get("ts", ""))
        first_ts = sorted_group[0].get("ts", "")
        last_ts = sorted_group[-1].get("ts", "")
        durations_ms.append(_iso_to_ms(last_ts) - _iso_to_ms(first_ts))

    tool_frequency: dict[str, int] = {}
    kind_frequency: dict[str, int] = {}
    status_frequency: dict[str, int] = {}
    hour_of_day: list[int] = [0] * 24
    tool_call_count = 0
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None

    for r in records:
        kind = r.get("kind", "")
        kind_frequency[kind] = kind_frequency.get(kind, 0) + 1
        status = r.get("status", "")
        status_frequency[status] = status_frequency.get(status, 0) + 1
        if kind == "tool_call":
            tool = r.get("tool") or {}
            name = tool.get("name") if isinstance(tool, dict) else None
            if isinstance(name, str):
                tool_call_count += 1
                tool_frequency[name] = tool_frequency.get(name, 0) + 1
        ts = r.get("ts")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                hour_of_day[dt.astimezone(timezone.utc).hour] += 1
            except ValueError:
                pass
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

    return AgentProfile(
        agent_id=agent_id,
        session_count=len(sessions),
        total_records=len(records),
        tool_call_count=tool_call_count,
        avg_session_length_events=mean(events_per_session),
        stddev_session_length_events=stddev(events_per_session),
        avg_session_duration_ms=mean(durations_ms),
        stddev_session_duration_ms=stddev(durations_ms),
        tool_frequency=tool_frequency,
        hour_of_day=hour_of_day,
        kind_frequency=kind_frequency,
        status_frequency=status_frequency,
        first_ts=first_ts,
        last_ts=last_ts,
        generated_at=_iso_now(),
    )


# ===========================================================================
# Deviation reporting
# ===========================================================================


@dataclass
class Deviation:
    """One metric-level deviation finding."""

    metric: str
    observed: float
    baseline: float
    sigma: Optional[float]
    note: str


@dataclass
class DeviationReport:
    agent_id: str
    candidate_first_ts: Optional[str]
    candidate_last_ts: Optional[str]
    deviations: list[Deviation] = field(default_factory=list)


@dataclass
class CompareOptions:
    sigma_threshold: float = 3.0
    min_baseline_sessions: int = 2


def compare_to_baseline(
    candidate: AgentProfile,
    baseline: AgentProfile,
    options: Optional[CompareOptions] = None,
) -> DeviationReport:
    """Compare a candidate profile against a saved baseline."""
    opts = options or CompareOptions()
    deviations: list[Deviation] = []

    if baseline.session_count >= opts.min_baseline_sessions:
        _push_if_deviated(
            deviations,
            "avg_session_length_events",
            candidate.avg_session_length_events,
            baseline.avg_session_length_events,
            baseline.stddev_session_length_events,
            opts.sigma_threshold,
        )
        _push_if_deviated(
            deviations,
            "avg_session_duration_ms",
            candidate.avg_session_duration_ms,
            baseline.avg_session_duration_ms,
            baseline.stddev_session_duration_ms,
            opts.sigma_threshold,
        )

    baseline_tools = set(baseline.tool_frequency.keys())
    for tool, count in candidate.tool_frequency.items():
        if tool not in baseline_tools:
            deviations.append(
                Deviation(
                    metric=f"tool_frequency.{tool}",
                    observed=float(count),
                    baseline=0.0,
                    sigma=None,
                    note="tool not present in baseline",
                )
            )

    deviations.sort(key=lambda d: d.metric)

    return DeviationReport(
        agent_id=candidate.agent_id,
        candidate_first_ts=candidate.first_ts,
        candidate_last_ts=candidate.last_ts,
        deviations=deviations,
    )


def _push_if_deviated(
    out: list[Deviation],
    metric: str,
    observed: float,
    baseline_mean: float,
    baseline_stddev: float,
    threshold: float,
) -> None:
    if baseline_stddev == 0:
        if observed != baseline_mean:
            out.append(
                Deviation(
                    metric=metric,
                    observed=observed,
                    baseline=baseline_mean,
                    sigma=None,
                    note="baseline σ=0; any difference is flagged",
                )
            )
        return
    sigma = abs(observed - baseline_mean) / baseline_stddev
    if sigma >= threshold:
        out.append(
            Deviation(
                metric=metric,
                observed=observed,
                baseline=baseline_mean,
                sigma=sigma,
                note=f"{sigma:.2f}σ from baseline mean {baseline_mean:.2f}",
            )
        )


# ===========================================================================
# Helpers
# ===========================================================================


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean. Returns 0 for empty input."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def stddev(values: Sequence[float]) -> float:
    """Population standard deviation. Returns 0 for inputs of length < 2."""
    if len(values) < 2:
        return 0.0
    m = mean(values)
    sum_sq = sum((v - m) ** 2 for v in values)
    return math.sqrt(sum_sq / len(values))


def _iso_to_ms(ts: str) -> float:
    """Parse an ISO-8601 timestamp into ms-since-epoch. Returns 0 on parse fail."""
    if not isinstance(ts, str):
        return 0.0
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0
    except ValueError:
        return 0.0


def _iso_now() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
