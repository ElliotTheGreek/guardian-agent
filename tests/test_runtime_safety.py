"""Tests for runtime safety primitives: rate limiter, capability window, honeytokens."""

from __future__ import annotations

import re

import pytest

from guardian_agent.runtime import (
    BucketConfig,
    CapabilityRule,
    CapabilityWindow,
    CapabilityWindowOptions,
    ConsumeAllowed,
    ConsumeDenied,
    DEFAULT_BUCKETS,
    Honeytoken,
    MultiRateLimiter,
    MultiRateLimiterOptions,
    check_honeytoken,
    define_honeytoken_set,
    match_honeytoken_in_args,
    match_phantom_tool,
)


# ---- MultiRateLimiter --------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_rate_limiter_allows_within_capacity():
    clock = FakeClock()
    limiter = MultiRateLimiter(MultiRateLimiterOptions(
        buckets={"read": BucketConfig(max_calls_per_second=5)},
        now=clock,
    ))
    for _ in range(5):
        assert isinstance(limiter.try_consume(["read"]), ConsumeAllowed)
    # 6th immediate call exhausts the bucket
    result = limiter.try_consume(["read"])
    assert isinstance(result, ConsumeDenied)
    assert result.cls == "read"


def test_rate_limiter_refills_over_time():
    clock = FakeClock()
    limiter = MultiRateLimiter(MultiRateLimiterOptions(
        buckets={"read": BucketConfig(max_calls_per_second=10)},
        now=clock,
    ))
    for _ in range(10):
        assert isinstance(limiter.try_consume(["read"]), ConsumeAllowed)
    assert isinstance(limiter.try_consume(["read"]), ConsumeDenied)
    # Advance 1 second → bucket fully refills
    clock.t += 1000
    assert isinstance(limiter.try_consume(["read"]), ConsumeAllowed)


def test_rate_limiter_multi_class_first_denial_wins():
    clock = FakeClock()
    limiter = MultiRateLimiter(MultiRateLimiterOptions(
        buckets={
            "read": BucketConfig(max_calls_per_second=10),
            "credential": BucketConfig(max_calls_per_second=2),
        },
        now=clock,
    ))
    # First two multi-class calls succeed
    for _ in range(2):
        result = limiter.try_consume(["read", "credential"])
        assert isinstance(result, ConsumeAllowed)
    # Third call: credential bucket empty → denied
    result = limiter.try_consume(["read", "credential"])
    assert isinstance(result, ConsumeDenied)
    assert result.cls == "credential"


def test_rate_limiter_no_policy_class_passes_through():
    clock = FakeClock()
    limiter = MultiRateLimiter(MultiRateLimiterOptions(
        buckets={"credential": BucketConfig(max_calls_per_second=1)},
        now=clock,
    ))
    # "weird-class" has no bucket → allowed
    for _ in range(100):
        assert isinstance(limiter.try_consume(["weird-class"]), ConsumeAllowed)


def test_rate_limiter_default_bucket_applies_when_class_missing():
    clock = FakeClock()
    limiter = MultiRateLimiter(MultiRateLimiterOptions(
        buckets={},
        default_bucket=BucketConfig(max_calls_per_second=1),
        now=clock,
    ))
    assert isinstance(limiter.try_consume(["unknown"]), ConsumeAllowed)
    assert isinstance(limiter.try_consume(["unknown"]), ConsumeDenied)


def test_rate_limiter_snapshot_includes_default():
    limiter = MultiRateLimiter(MultiRateLimiterOptions(
        buckets={"read": BucketConfig(max_calls_per_second=5)},
        default_bucket=BucketConfig(max_calls_per_second=10),
    ))
    snap = limiter.snapshot()
    assert "read" in snap
    assert "_default" in snap


def test_default_buckets_include_canonical_classes():
    for cls in ["read", "write", "delete", "execute", "credential", "network-egress"]:
        assert cls in DEFAULT_BUCKETS


# ---- CapabilityWindow --------------------------------------------------


def test_capability_window_rejects_empty_combination():
    with pytest.raises(ValueError, match="empty combination"):
        CapabilityWindow(CapabilityWindowOptions(rules=[
            CapabilityRule(id="bad", combination=[], window_ms=1000),
        ]))


def test_capability_window_rejects_non_positive_window():
    with pytest.raises(ValueError, match="non-positive window_ms"):
        CapabilityWindow(CapabilityWindowOptions(rules=[
            CapabilityRule(id="bad", combination=["read"], window_ms=0),
        ]))


def test_capability_window_fires_when_all_classes_observed_in_window():
    clock = FakeClock()
    win = CapabilityWindow(CapabilityWindowOptions(
        rules=[CapabilityRule(
            id="exfil-shape",
            combination=["credential", "network-egress", "write"],
            window_ms=60_000,
        )],
        now=clock,
    ))
    assert win.record(["credential"], "e1") == []
    clock.t += 1000
    assert win.record(["network-egress"], "e2") == []
    clock.t += 1000
    matches = win.record(["write"], "e3")
    assert len(matches) == 1
    assert matches[0].rule_id == "exfil-shape"
    assert matches[0].level == "yellow"
    assert set(matches[0].contributing_event_ids) == {"e1", "e2", "e3"}


def test_capability_window_does_not_fire_when_window_lapses():
    clock = FakeClock()
    win = CapabilityWindow(CapabilityWindowOptions(
        rules=[CapabilityRule(
            id="r", combination=["a", "b"], window_ms=1000,
        )],
        now=clock,
    ))
    win.record(["a"], "e1")
    clock.t += 2000  # > window
    assert win.record(["b"], "e2") == []


def test_capability_window_dedupes_contributing_events_for_multi_class():
    clock = FakeClock()
    win = CapabilityWindow(CapabilityWindowOptions(
        rules=[CapabilityRule(id="r", combination=["x", "y"], window_ms=10_000)],
        now=clock,
    ))
    # One event satisfies both required classes — should appear once in contributors.
    matches = win.record(["x", "y"], "e1")
    assert len(matches) == 1
    assert matches[0].contributing_event_ids == ["e1"]


def test_capability_window_prunes_old_events():
    clock = FakeClock()
    win = CapabilityWindow(CapabilityWindowOptions(
        rules=[CapabilityRule(id="r", combination=["a"], window_ms=100)],
        now=clock,
    ))
    for i in range(5):
        win.record(["x"], f"e{i}")
        clock.t += 200  # outside window
    assert len(win.buffered()) <= 1  # pruned aggressively


def test_capability_window_hard_cap_max_events():
    clock = FakeClock()
    win = CapabilityWindow(CapabilityWindowOptions(
        rules=[CapabilityRule(id="r", combination=["a"], window_ms=1_000_000)],
        now=clock,
        max_events=10,
    ))
    for i in range(50):
        win.record(["irrelevant"], f"e{i}")
    assert len(win.buffered()) == 10


# ---- Honeytokens -------------------------------------------------------


def test_define_set_requires_at_least_one_token_or_phantom():
    with pytest.raises(ValueError, match="at least one"):
        define_honeytoken_set("empty", [])


def test_define_set_rejects_token_with_neither_value_nor_pattern():
    with pytest.raises(ValueError, match="either value or pattern"):
        define_honeytoken_set("x", [Honeytoken(id="t")])


def test_define_set_rejects_token_with_both_value_and_pattern():
    with pytest.raises(ValueError, match="choose one"):
        define_honeytoken_set("x", [Honeytoken(id="t", value="v", pattern=r"v")])


def test_define_set_rejects_duplicate_token_ids():
    with pytest.raises(ValueError, match="duplicate token"):
        define_honeytoken_set("x", [
            Honeytoken(id="t", value="a"),
            Honeytoken(id="t", value="b"),
        ])


def test_define_set_rejects_duplicate_phantom_tool_names():
    with pytest.raises(ValueError, match="duplicate phantom"):
        define_honeytoken_set("x", [], phantom_tools=["a", "a"])


def test_phantom_tool_fires_on_call():
    s = define_honeytoken_set("p", [Honeytoken(id="t", value="x")],
                              phantom_tools=["never_call_this"])
    hit = match_phantom_tool(s, "never_call_this")
    assert hit is not None
    assert hit.kind == "phantom_tool"
    assert hit.tool_name == "never_call_this"


def test_value_in_args_fires_on_substring_match():
    s = define_honeytoken_set("p", [Honeytoken(id="fake-aws", value="AKIA00FAKE00")])
    hit = match_honeytoken_in_args(s, {"nested": {"secret": "value-AKIA00FAKE00-tail"}})
    assert hit is not None
    assert hit.token_id == "fake-aws"


def test_pattern_fires_on_regex_match():
    s = define_honeytoken_set("p", [Honeytoken(id="aws-shape", pattern=r"AKIA[0-9A-Z]{16}")])
    hit = match_honeytoken_in_args(s, {"k": "AKIAABCDEFGHIJKLMNOP"})
    assert hit is not None
    assert hit.token_id == "aws-shape"


def test_pattern_accepts_precompiled_regex():
    s = define_honeytoken_set("p", [
        Honeytoken(id="aws-shape", pattern=re.compile(r"AKIA[0-9A-Z]{16}")),
    ])
    hit = match_honeytoken_in_args(s, {"k": "AKIAABCDEFGHIJKLMNOP"})
    assert hit is not None


def test_no_hit_on_clean_args():
    s = define_honeytoken_set("p", [Honeytoken(id="t", value="DECOY_VALUE")])
    assert match_honeytoken_in_args(s, {"safe": "data"}) is None


def test_check_honeytoken_phantom_wins_over_value():
    s = define_honeytoken_set("p", [Honeytoken(id="v", value="x")],
                              phantom_tools=["never_call_this"])
    # Args have value match too — but phantom_tool wins
    hit = check_honeytoken(s, "never_call_this", {"x": "x"})
    assert hit is not None
    assert hit.kind == "phantom_tool"


def test_check_honeytoken_returns_none_when_nothing_matches():
    s = define_honeytoken_set("p", [Honeytoken(id="v", value="DECOY")])
    assert check_honeytoken(s, "safe_tool", {"k": "v"}) is None
