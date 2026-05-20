"""Tests for audit/correlation.py — cross-surface match algorithms."""

from __future__ import annotations

from typing import Any

from guardian_agent.audit.correlation import (
    AuditSource,
    CorrelationOptions,
    correlate,
    find_args_hash_collisions,
    find_overlapping_sessions,
    find_sequence_similarity,
    hash_args,
    summarize_sessions,
)


def tool_call(agent: str, sess: str, tool: str, args: dict[str, Any],
              ts: str, event_id: str | None = None) -> dict[str, Any]:
    return {
        "agent_id": agent,
        "session_id": sess,
        "kind": "tool_call",
        "status": "pending",
        "initiator": "agent",
        "ts": ts,
        "prev_hash": "sha256:0",
        "v": "0.5.0",
        "event_id": event_id or f"evt_{agent}_{sess}_{tool}_{ts}",
        "tool": {"name": tool, "args": args},
    }


def session_open(agent: str, sess: str, ts: str) -> dict[str, Any]:
    return {
        "agent_id": agent,
        "session_id": sess,
        "kind": "session_open",
        "status": "approved",
        "initiator": "system",
        "ts": ts,
        "prev_hash": "sha256:0",
        "v": "0.5.0",
        "event_id": f"evt_open_{agent}_{sess}",
    }


# ---- hash_args ----------------------------------------------------------


def test_hash_args_is_deterministic_and_canonical():
    h1 = hash_args({"b": 1, "a": 2})
    h2 = hash_args({"a": 2, "b": 1})  # different insertion order
    assert h1 == h2
    assert h1.startswith("sha256:")


# ---- summarize_sessions -------------------------------------------------


def test_summarize_buckets_by_agent_and_session():
    source = AuditSource(surface="cli", records=[
        tool_call("a", "s1", "x", {}, "2026-05-20T00:00:00.000Z"),
        tool_call("a", "s1", "y", {}, "2026-05-20T00:00:05.000Z"),
        tool_call("a", "s2", "x", {}, "2026-05-20T01:00:00.000Z"),
        tool_call("b", "s1", "x", {}, "2026-05-20T00:00:00.000Z"),
    ])
    summaries = summarize_sessions(source)
    assert len(summaries) == 3
    s_a_s1 = next(s for s in summaries if s.agent_id == "a" and s.session_id == "s1")
    assert s_a_s1.duration_ms == 5000
    assert s_a_s1.tool_frequency == {"x": 1, "y": 1}
    assert len(s_a_s1.args_hashes) == 2


# ---- find_overlapping_sessions -----------------------------------------


def test_overlap_detected_for_different_surfaces_same_agent():
    cli = AuditSource(surface="cli", records=[
        tool_call("a", "s_cli", "x", {}, "2026-05-20T00:00:00.000Z"),
        tool_call("a", "s_cli", "x", {}, "2026-05-20T00:01:00.000Z"),
    ])
    mcp = AuditSource(surface="mcp", records=[
        tool_call("a", "s_mcp", "x", {}, "2026-05-20T00:00:30.000Z"),
        tool_call("a", "s_mcp", "x", {}, "2026-05-20T00:00:45.000Z"),
    ])
    matches = correlate([cli, mcp])
    overlap = [m for m in matches if m.match_type == "overlapping_sessions"]
    assert len(overlap) == 1
    assert set(overlap[0].surfaces) == {"cli", "mcp"}


def test_no_overlap_for_disjoint_sessions():
    cli = AuditSource(surface="cli", records=[
        tool_call("a", "s_cli", "x", {}, "2026-05-20T00:00:00.000Z"),
    ])
    mcp = AuditSource(surface="mcp", records=[
        tool_call("a", "s_mcp", "x", {}, "2026-05-20T05:00:00.000Z"),
    ])
    matches = [m for m in correlate([cli, mcp]) if m.match_type == "overlapping_sessions"]
    assert matches == []


def test_no_overlap_for_same_surface():
    """Two sessions on the same surface aren't a cross-surface signal."""
    src = AuditSource(surface="cli", records=[
        tool_call("a", "s1", "x", {}, "2026-05-20T00:00:00.000Z"),
        tool_call("a", "s1", "x", {}, "2026-05-20T00:00:10.000Z"),
        tool_call("a", "s2", "x", {}, "2026-05-20T00:00:05.000Z"),
        tool_call("a", "s2", "x", {}, "2026-05-20T00:00:08.000Z"),
    ])
    sums = summarize_sessions(src)
    assert find_overlapping_sessions(sums) == []


# ---- find_args_hash_collisions -----------------------------------------


def test_args_hash_collision_across_surfaces_within_window():
    cli = AuditSource(surface="cli", records=[
        tool_call("a", "s1", "place_order",
                  {"symbol": "AAPL", "qty": 100}, "2026-05-20T00:00:00.000Z",
                  event_id="evt_cli"),
    ])
    mcp = AuditSource(surface="mcp", records=[
        tool_call("a", "s2", "place_order",
                  {"symbol": "AAPL", "qty": 100}, "2026-05-20T00:00:30.000Z",
                  event_id="evt_mcp"),
    ])
    matches = [m for m in correlate([cli, mcp]) if m.match_type == "args_hash_collision"]
    assert len(matches) == 1
    assert matches[0].detail["delta_ms"] == 30_000


def test_no_args_collision_outside_window():
    cli = AuditSource(surface="cli", records=[
        tool_call("a", "s1", "place_order", {"a": 1}, "2026-05-20T00:00:00.000Z"),
    ])
    mcp = AuditSource(surface="mcp", records=[
        tool_call("a", "s2", "place_order", {"a": 1}, "2026-05-20T01:00:00.000Z"),
    ])
    matches = correlate([cli, mcp], CorrelationOptions(args_hash_window_ms=60_000))
    assert [m for m in matches if m.match_type == "args_hash_collision"] == []


# ---- find_sequence_similarity ------------------------------------------


def test_sequence_similarity_high_for_identical_vectors():
    cli_records = [
        tool_call("a", "s_cli", "x", {}, "2026-05-20T00:00:00.000Z"),
        tool_call("a", "s_cli", "x", {}, "2026-05-20T00:00:01.000Z"),
        tool_call("a", "s_cli", "y", {}, "2026-05-20T00:00:02.000Z"),
        tool_call("a", "s_cli", "y", {}, "2026-05-20T00:00:03.000Z"),
        tool_call("a", "s_cli", "z", {}, "2026-05-20T00:00:04.000Z"),
    ]
    mcp_records = [
        tool_call("a", "s_mcp", "x", {}, "2026-05-20T00:01:00.000Z"),
        tool_call("a", "s_mcp", "x", {}, "2026-05-20T00:01:01.000Z"),
        tool_call("a", "s_mcp", "y", {}, "2026-05-20T00:01:02.000Z"),
        tool_call("a", "s_mcp", "y", {}, "2026-05-20T00:01:03.000Z"),
        tool_call("a", "s_mcp", "z", {}, "2026-05-20T00:01:04.000Z"),
    ]
    cli = AuditSource(surface="cli", records=cli_records)
    mcp = AuditSource(surface="mcp", records=mcp_records)
    matches = [m for m in correlate([cli, mcp]) if m.match_type == "sequence_similarity"]
    assert len(matches) == 1
    assert matches[0].detail["cosine_similarity"] == 1.0


def test_sequence_similarity_skips_sessions_below_min_calls():
    cli = AuditSource(surface="cli", records=[
        tool_call("a", "s_cli", "x", {}, "2026-05-20T00:00:00.000Z"),
    ])
    mcp = AuditSource(surface="mcp", records=[
        tool_call("a", "s_mcp", "x", {}, "2026-05-20T00:00:01.000Z"),
    ])
    matches = correlate([cli, mcp], CorrelationOptions(similarity_min_calls=5))
    assert [m for m in matches if m.match_type == "sequence_similarity"] == []


def test_correlation_match_to_dict_shape():
    cli = AuditSource(surface="cli", records=[
        tool_call("a", "s_cli", "x", {"k": 1}, "2026-05-20T00:00:00.000Z"),
    ])
    mcp = AuditSource(surface="mcp", records=[
        tool_call("a", "s_mcp", "x", {"k": 1}, "2026-05-20T00:00:01.000Z"),
    ])
    matches = correlate([cli, mcp])
    d = matches[0].to_dict()
    assert d["kind"] == "x_cross_surface_match"
    assert d["match_type"] in {"overlapping_sessions", "args_hash_collision"}
    assert isinstance(d["surfaces"], list)
    assert isinstance(d["session_ids"], list)
    assert isinstance(d["detail"], dict)
