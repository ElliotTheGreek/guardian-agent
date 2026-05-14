"""Tests for audit/chain.py — SPEC §2.5."""

from __future__ import annotations

import math

import pytest

from guardian_agent.audit.chain import (
    GENESIS_HASH,
    canonical_json_string,
    canonicalize_for_hash,
    compute_record_hash,
)
from guardian_agent.types import SPEC_VERSION


def base_record(**overrides):
    rec = {
        "v": SPEC_VERSION,
        "event_id": "evt_01HXYZ",
        "ts": "2026-05-13T23:45:12.345Z",
        "agent_id": "a",
        "session_id": "s",
        "kind": "tool_call",
        "status": "pending",
        "initiator": "agent",
        "prev_hash": GENESIS_HASH,
        "signature": None,
    }
    rec.update(overrides)
    return rec


class TestCanonicalJsonString:
    def test_primitives(self):
        assert canonical_json_string(None) == "null"
        assert canonical_json_string(True) == "true"
        assert canonical_json_string(False) == "false"
        assert canonical_json_string(42) == "42"
        assert canonical_json_string("hi") == '"hi"'

    def test_sorts_object_keys(self):
        assert canonical_json_string({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_arrays_preserve_order(self):
        assert canonical_json_string([3, 2, 1]) == "[3,2,1]"

    def test_rejects_non_finite_numbers(self):
        with pytest.raises(TypeError):
            canonical_json_string(math.nan)
        with pytest.raises(TypeError):
            canonical_json_string(math.inf)

    def test_rejects_unsupported_types(self):
        with pytest.raises(TypeError):
            canonical_json_string(lambda: 0)
        with pytest.raises(TypeError):
            canonical_json_string(object())

    def test_emits_null_for_none_values(self):
        # Top-level None → "null"
        assert canonical_json_string(None) == "null"
        # None inside a dict → "null"
        assert canonical_json_string({"a": None}) == '{"a":null}'


class TestCanonicalizeForHash:
    def test_strips_signature(self):
        r = base_record(signature="ed25519:xxx")
        assert b"signature" not in canonicalize_for_hash(r)

    def test_stable_bytes(self):
        a = base_record()
        b = dict(a)
        assert canonicalize_for_hash(a) == canonicalize_for_hash(b)


class TestComputeRecordHash:
    def test_deterministic(self):
        r = base_record()
        assert compute_record_hash(r) == compute_record_hash(r)
        assert compute_record_hash(r).startswith("sha256:")
        assert len(compute_record_hash(r)) == 7 + 64

    def test_changes_when_field_changes(self):
        a = base_record()
        b = base_record(status="executed")
        assert compute_record_hash(a) != compute_record_hash(b)

    def test_unchanged_when_signature_changes(self):
        unsigned = base_record(signature=None)
        signed = base_record(signature="ed25519:abc")
        assert compute_record_hash(unsigned) == compute_record_hash(signed)


def test_genesis_constant():
    assert GENESIS_HASH == "sha256:0"
