"""Tests for audit/stats.py — behavioral baselines + σ-deviation reports."""

from __future__ import annotations

from typing import Any

import pytest

from guardian_agent.audit.stats import (
    AgentProfile,
    CompareOptions,
    analyze_agent,
    analyze_multi_agent,
    compare_to_baseline,
    mean,
    stddev,
)


def rec(agent: str, sess: str, kind: str = "tool_call", status: str = "executed",
        tool_name: str = "list_accounts", ts: str = "2026-05-20T00:00:00.000Z") -> dict[str, Any]:
    r: dict[str, Any] = {
        "agent_id": agent,
        "session_id": sess,
        "kind": kind,
        "status": status,
        "initiator": "agent",
        "ts": ts,
        "prev_hash": "sha256:0",
        "v": "0.5.0",
        "event_id": f"evt_{agent}_{sess}",
    }
    if kind == "tool_call":
        r["tool"] = {"name": tool_name, "args": {}}
    return r


# ---- helpers ------------------------------------------------------------


def test_mean_returns_zero_for_empty():
    assert mean([]) == 0.0


def test_mean_computes_arithmetic_mean():
    assert mean([1.0, 2.0, 3.0, 4.0]) == 2.5


def test_stddev_returns_zero_for_short_input():
    assert stddev([]) == 0.0
    assert stddev([42.0]) == 0.0


def test_stddev_population():
    # var = ((1-3)^2 + (3-3)^2 + (5-3)^2) / 3 = 8/3 → σ = sqrt(8/3) ≈ 1.633
    assert abs(stddev([1.0, 3.0, 5.0]) - 1.632993) < 1e-5


# ---- analyze_agent ------------------------------------------------------


def test_analyze_agent_filters_by_agent_id():
    records = [rec("a", "s1"), rec("b", "s2"), rec("a", "s1", tool_name="other")]
    p = analyze_agent(records, "a")
    assert p.agent_id == "a"
    assert p.total_records == 2
    assert p.session_count == 1
    assert p.tool_frequency == {"list_accounts": 1, "other": 1}


def test_analyze_agent_counts_kinds_and_statuses():
    records = [
        rec("a", "s", kind="session_open", status="approved"),
        rec("a", "s", kind="tool_call", status="pending"),
        rec("a", "s", kind="tool_result", status="executed"),
        rec("a", "s", kind="session_close", status="approved"),
    ]
    p = analyze_agent(records, "a")
    assert p.kind_frequency == {
        "session_open": 1,
        "tool_call": 1,
        "tool_result": 1,
        "session_close": 1,
    }
    assert p.status_frequency == {"approved": 2, "pending": 1, "executed": 1}


def test_analyze_agent_computes_session_duration():
    records = [
        rec("a", "s1", ts="2026-05-20T00:00:00.000Z"),
        rec("a", "s1", ts="2026-05-20T00:00:05.000Z"),  # 5s duration
        rec("a", "s2", ts="2026-05-20T01:00:00.000Z"),
        rec("a", "s2", ts="2026-05-20T01:00:10.000Z"),  # 10s duration
    ]
    p = analyze_agent(records, "a")
    assert p.session_count == 2
    # avg = 7500ms, σ ≈ 2500
    assert abs(p.avg_session_duration_ms - 7500.0) < 1.0
    assert abs(p.stddev_session_duration_ms - 2500.0) < 1.0


def test_analyze_agent_hour_of_day():
    records = [
        rec("a", "s", ts="2026-05-20T03:00:00.000Z"),
        rec("a", "s", ts="2026-05-20T03:00:01.000Z"),
        rec("a", "s", ts="2026-05-20T14:00:00.000Z"),
    ]
    p = analyze_agent(records, "a")
    assert p.hour_of_day[3] == 2
    assert p.hour_of_day[14] == 1


def test_analyze_agent_tracks_first_and_last_ts():
    records = [
        rec("a", "s", ts="2026-05-20T05:00:00.000Z"),
        rec("a", "s", ts="2026-05-20T01:00:00.000Z"),
        rec("a", "s", ts="2026-05-20T09:00:00.000Z"),
    ]
    p = analyze_agent(records, "a")
    assert p.first_ts == "2026-05-20T01:00:00.000Z"
    assert p.last_ts == "2026-05-20T09:00:00.000Z"


# ---- analyze_multi_agent -----------------------------------------------


def test_analyze_multi_agent_buckets_by_agent_id():
    records = [rec("a", "s1"), rec("b", "s2"), rec("a", "s3")]
    profiles = analyze_multi_agent(records)
    assert set(profiles.keys()) == {"a", "b"}
    assert profiles["a"].session_count == 2
    assert profiles["b"].session_count == 1


# ---- compare_to_baseline -----------------------------------------------


def _profile(agent_id: str, avg_len: float, sd_len: float, avg_dur: float, sd_dur: float,
             sessions: int = 5, tools: dict[str, int] | None = None) -> AgentProfile:
    return AgentProfile(
        agent_id=agent_id,
        session_count=sessions,
        total_records=sessions * 10,
        tool_call_count=sessions * 3,
        avg_session_length_events=avg_len,
        stddev_session_length_events=sd_len,
        avg_session_duration_ms=avg_dur,
        stddev_session_duration_ms=sd_dur,
        tool_frequency=tools or {"list_accounts": 5, "place_order": 3},
    )


def test_compare_flags_sigma_deviation_in_session_length():
    baseline = _profile("a", avg_len=10.0, sd_len=2.0, avg_dur=5000.0, sd_dur=1000.0)
    candidate = _profile("a", avg_len=20.0, sd_len=0.0, avg_dur=5000.0, sd_dur=0.0, sessions=1)
    report = compare_to_baseline(candidate, baseline, CompareOptions(sigma_threshold=3.0))
    metrics = [d.metric for d in report.deviations]
    assert "avg_session_length_events" in metrics
    dev = next(d for d in report.deviations if d.metric == "avg_session_length_events")
    assert dev.sigma == 5.0
    assert dev.observed == 20.0
    assert dev.baseline == 10.0


def test_compare_flags_unseen_tool_in_candidate():
    baseline = _profile("a", 10.0, 2.0, 5000.0, 1000.0, tools={"known": 3})
    candidate = _profile("a", 10.0, 0.0, 5000.0, 0.0, sessions=1,
                         tools={"known": 3, "new_dangerous_tool": 2})
    report = compare_to_baseline(candidate, baseline)
    assert any(d.metric == "tool_frequency.new_dangerous_tool" for d in report.deviations)


def test_compare_skips_sigma_when_baseline_too_thin():
    baseline = _profile("a", 10.0, 2.0, 5000.0, 1000.0, sessions=1)
    candidate = _profile("a", 50.0, 0.0, 5000.0, 0.0, sessions=1)
    report = compare_to_baseline(candidate, baseline, CompareOptions(min_baseline_sessions=2))
    # min_baseline_sessions=2 means no σ check; only unseen-tool check could fire
    metric_names = {d.metric for d in report.deviations}
    assert "avg_session_length_events" not in metric_names


def test_compare_zero_sigma_baseline_flags_any_difference():
    baseline = _profile("a", 10.0, 0.0, 5000.0, 0.0)
    candidate = _profile("a", 10.5, 0.0, 5000.0, 0.0, sessions=1)
    report = compare_to_baseline(candidate, baseline)
    dev = next(d for d in report.deviations if d.metric == "avg_session_length_events")
    assert dev.sigma is None
    assert "σ=0" in dev.note


# ---- to_dict / from_dict roundtrip --------------------------------------


def test_profile_roundtrip_through_dict():
    records = [rec("a", "s1"), rec("a", "s1", kind="tool_result", status="executed"),
               rec("a", "s2"), rec("a", "s2", kind="tool_result", status="executed")]
    p = analyze_agent(records, "a")
    d = p.to_dict()
    p2 = AgentProfile.from_dict(d)
    assert p2.to_dict() == d
