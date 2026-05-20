"""Cross-surface correlation. SPEC §14 (v0.5+).

Reads audit records from multiple sources (typically one per surface —
cli.jsonl, mcp.jsonl, py.jsonl, etc.) and looks for patterns that span
surfaces under the same `agent_id`:

  - Overlapping sessions: same agent_id, concurrent sessions on two surfaces.
  - Identical args: canonical-JSON-SHA256 of `tool.args` collides across
    surfaces within a configurable time window.
  - Sequence similarity: cosine similarity of per-session tool-frequency
    vectors above a configurable threshold.

All three are deterministic predicates on input. The library produces match
records; the operator decides what to do with them.

Read-only on source audit files. Output is written to a separate
correlations.jsonl log so source-log integrity (hash chain, signatures) is
never touched.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from ..types import AuditRecord
from .chain import canonical_json_string


# ===========================================================================
# Source = one audit file = one surface
# ===========================================================================


@dataclass
class AuditSource:
    """One surface's worth of records."""

    surface: str
    records: list[AuditRecord]


# ===========================================================================
# SessionSummary — per-session shape used by the matchers
# ===========================================================================


@dataclass
class ArgsHash:
    event_id: str
    ts: str
    tool_name: str
    args_hash: str


@dataclass
class SessionSummary:
    surface: str
    agent_id: str
    session_id: str
    start: str
    end: str
    duration_ms: float = 0.0
    tool_frequency: dict[str, int] = field(default_factory=dict)
    args_hashes: list[ArgsHash] = field(default_factory=list)


def summarize_sessions(source: AuditSource) -> list[SessionSummary]:
    """Summarize one source's records into per-(agent_id, session_id) entries."""
    map_: dict[tuple[str, str], SessionSummary] = {}
    for r in source.records:
        agent_id = r.get("agent_id")
        session_id = r.get("session_id")
        ts = r.get("ts")
        if not isinstance(agent_id, str) or not isinstance(session_id, str) or not isinstance(ts, str):
            continue
        key = (agent_id, session_id)
        s = map_.get(key)
        if s is None:
            s = SessionSummary(
                surface=source.surface,
                agent_id=agent_id,
                session_id=session_id,
                start=ts,
                end=ts,
            )
            map_[key] = s
        if ts < s.start:
            s.start = ts
        if ts > s.end:
            s.end = ts
        if r.get("kind") == "tool_call":
            tool = r.get("tool") or {}
            name = tool.get("name") if isinstance(tool, dict) else None
            if isinstance(name, str):
                s.tool_frequency[name] = s.tool_frequency.get(name, 0) + 1
                args = tool.get("args") if isinstance(tool, dict) else {}
                event_id = r.get("event_id", "")
                s.args_hashes.append(
                    ArgsHash(
                        event_id=event_id if isinstance(event_id, str) else "",
                        ts=ts,
                        tool_name=name,
                        args_hash=hash_args(args),
                    )
                )
    out = list(map_.values())
    for s in out:
        s.duration_ms = _iso_to_ms(s.end) - _iso_to_ms(s.start)
    return out


def hash_args(args: Any) -> str:
    canonical = canonical_json_string(args).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# ===========================================================================
# Matches
# ===========================================================================


@dataclass
class CorrelationMatch:
    """One correlation finding. Serializes to JSONL with kind=x_cross_surface_match."""

    agent_id: str
    match_type: str  # "overlapping_sessions" | "args_hash_collision" | "sequence_similarity"
    surfaces: tuple[str, str]
    session_ids: tuple[str, str]
    detail: dict[str, Any] = field(default_factory=dict)
    kind: str = "x_cross_surface_match"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "agent_id": self.agent_id,
            "match_type": self.match_type,
            "surfaces": list(self.surfaces),
            "session_ids": list(self.session_ids),
            "detail": dict(self.detail),
        }


@dataclass
class CorrelationOptions:
    args_hash_window_ms: int = 60_000
    similarity_threshold: float = 0.9
    similarity_window_ms: int = 600_000
    similarity_min_calls: int = 5


def correlate(
    sources: Iterable[AuditSource],
    options: Optional[CorrelationOptions] = None,
) -> list[CorrelationMatch]:
    """Run all three correlators across the given sources. Matches in
    insertion order (overlap → hash → similarity)."""
    opts = options or CorrelationOptions()
    summaries: list[SessionSummary] = []
    for src in sources:
        summaries.extend(summarize_sessions(src))
    by_agent: dict[str, list[SessionSummary]] = {}
    for s in summaries:
        by_agent.setdefault(s.agent_id, []).append(s)
    out: list[CorrelationMatch] = []
    for sessions in by_agent.values():
        out.extend(find_overlapping_sessions(sessions))
        out.extend(find_args_hash_collisions(sessions, opts.args_hash_window_ms))
        out.extend(find_sequence_similarity(sessions, opts))
    return out


def find_overlapping_sessions(sessions: list[SessionSummary]) -> list[CorrelationMatch]:
    """Pairs of sessions on different surfaces whose time windows overlap."""
    out: list[CorrelationMatch] = []
    for i in range(len(sessions)):
        for j in range(i + 1, len(sessions)):
            a, b = sessions[i], sessions[j]
            if a.surface == b.surface:
                continue
            a_start = _iso_to_ms(a.start)
            a_end = _iso_to_ms(a.end)
            b_start = _iso_to_ms(b.start)
            b_end = _iso_to_ms(b.end)
            if a_start <= b_end and b_start <= a_end:
                overlap_start = max(a_start, b_start)
                overlap_end = min(a_end, b_end)
                out.append(
                    CorrelationMatch(
                        agent_id=a.agent_id,
                        match_type="overlapping_sessions",
                        surfaces=(a.surface, b.surface),
                        session_ids=(a.session_id, b.session_id),
                        detail={
                            "overlap_start": _ms_to_iso(overlap_start),
                            "overlap_end": _ms_to_iso(overlap_end),
                            "overlap_ms": overlap_end - overlap_start,
                            "session_a_window": [a.start, a.end],
                            "session_b_window": [b.start, b.end],
                        },
                    )
                )
    return out


def find_args_hash_collisions(
    sessions: list[SessionSummary], window_ms: int
) -> list[CorrelationMatch]:
    """Identical canonical-JSON-SHA256(args) in two surfaces within window_ms."""
    out: list[CorrelationMatch] = []
    by_key: dict[tuple[str, str], list[tuple[ArgsHash, SessionSummary]]] = {}
    for session in sessions:
        for h in session.args_hashes:
            by_key.setdefault((h.tool_name, h.args_hash), []).append((h, session))
    for (tool_name, args_hash), entries in by_key.items():
        if len(entries) < 2:
            continue
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                (ha, sa), (hb, sb) = entries[i], entries[j]
                if sa.surface == sb.surface:
                    continue
                at = _iso_to_ms(ha.ts)
                bt = _iso_to_ms(hb.ts)
                delta = abs(at - bt)
                if delta > window_ms:
                    continue
                out.append(
                    CorrelationMatch(
                        agent_id=sa.agent_id,
                        match_type="args_hash_collision",
                        surfaces=(sa.surface, sb.surface),
                        session_ids=(sa.session_id, sb.session_id),
                        detail={
                            "tool_name": tool_name,
                            "args_hash": args_hash,
                            "event_id_a": ha.event_id,
                            "event_id_b": hb.event_id,
                            "delta_ms": delta,
                        },
                    )
                )
    return out


def find_sequence_similarity(
    sessions: list[SessionSummary], options: CorrelationOptions
) -> list[CorrelationMatch]:
    """Pairs of sessions on different surfaces with similar tool-frequency vectors."""
    out: list[CorrelationMatch] = []
    vocab: set[str] = set()
    for s in sessions:
        vocab.update(s.tool_frequency.keys())
    vocab_list = list(vocab)
    for i in range(len(sessions)):
        for j in range(i + 1, len(sessions)):
            a, b = sessions[i], sessions[j]
            if a.surface == b.surface:
                continue
            a_calls = sum(a.tool_frequency.values())
            b_calls = sum(b.tool_frequency.values())
            if a_calls < options.similarity_min_calls or b_calls < options.similarity_min_calls:
                continue
            dt = abs(_iso_to_ms(a.start) - _iso_to_ms(b.start))
            if dt > options.similarity_window_ms:
                continue
            sim = _cosine_similarity(a.tool_frequency, b.tool_frequency, vocab_list)
            if sim >= options.similarity_threshold:
                out.append(
                    CorrelationMatch(
                        agent_id=a.agent_id,
                        match_type="sequence_similarity",
                        surfaces=(a.surface, b.surface),
                        session_ids=(a.session_id, b.session_id),
                        detail={
                            "cosine_similarity": sim,
                            "window_dt_ms": dt,
                            "session_a_calls": a_calls,
                            "session_b_calls": b_calls,
                        },
                    )
                )
    return out


def _cosine_similarity(
    a: dict[str, int], b: dict[str, int], vocab: list[str]
) -> float:
    dot = 0.0
    mag_a = 0.0
    mag_b = 0.0
    for term in vocab:
        va = a.get(term, 0)
        vb = b.get(term, 0)
        dot += va * vb
        mag_a += va * va
        mag_b += vb * vb
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (math.sqrt(mag_a) * math.sqrt(mag_b))


def _iso_to_ms(ts: str) -> float:
    if not isinstance(ts, str):
        return 0.0
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000.0
    except ValueError:
        return 0.0


def _ms_to_iso(ms: float) -> str:
    from datetime import timezone

    dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
