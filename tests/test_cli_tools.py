"""Tests for the three offline CLI tools: guardian-verify, guardian-baseline, guardian-correlator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from guardian_agent.audit.signature import (
    generate_ed25519_keypair,
    load_private_key,
)
from guardian_agent.audit.writer import AuditLogWriter, AuditLogWriterOptions
from guardian_agent.cli.guardian_baseline import (
    BaselineArgs,
    parse_args as parse_baseline_args,
    run_baseline,
)
from guardian_agent.cli.guardian_correlator import (
    CorrelatorArgs,
    parse_args as parse_correlator_args,
    run_correlator,
)
from guardian_agent.cli.guardian_verify import (
    VerifyArgs,
    parse_args as parse_verify_args,
    run_verify,
)


def _signed_writer(path: Path) -> tuple[AuditLogWriter, bytes]:
    priv_pem, pub_pem = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(path), agent_id="agent-cli", session_id="sess-cli", sign_with=priv,
    ))
    return w, pub_pem


def _emit_session(tmp_path: Path, agent: str = "agent-cli", n_tools: int = 3) -> tuple[Path, bytes]:
    log = tmp_path / f"{agent}.jsonl"
    priv_pem, pub_pem = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(log), agent_id=agent, session_id=f"sess-{agent}", sign_with=priv,
    ))
    w.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    for i in range(n_tools):
        w.append({
            "kind": "tool_call", "status": "pending", "initiator": "agent",
            "tool": {"name": "list_accounts", "args": {"i": i}},
        })
        w.append({
            "kind": "tool_result", "status": "executed", "initiator": "system",
            "tool": {"name": "list_accounts", "args": {"i": i}, "result": {"ok": True}},
        })
    w.append({"kind": "session_close", "status": "approved", "initiator": "system"})
    w.close()
    return log, pub_pem


# =====================================================================
# guardian-verify
# =====================================================================


def test_verify_parse_args_path_only():
    parsed = parse_verify_args(["audit.jsonl"])
    assert parsed is not None
    assert parsed.path == "audit.jsonl"
    assert parsed.pubkey_path is None


def test_verify_parse_args_with_pubkey():
    parsed = parse_verify_args(["audit.jsonl", "--pubkey", "pub.pem"])
    assert parsed is not None
    assert parsed.pubkey_path == "pub.pem"


def test_verify_parse_args_help():
    parsed = parse_verify_args(["--help"])
    assert parsed is not None and parsed.path is None


def test_verify_parse_args_unknown_flag_returns_none():
    assert parse_verify_args(["--bogus"]) is None


def test_verify_parse_args_pubkey_without_value_returns_none():
    assert parse_verify_args(["audit.jsonl", "--pubkey"]) is None


def test_verify_run_no_path_returns_2():
    result = run_verify(VerifyArgs(path=None, pubkey_path=None))
    assert result.exit_code == 2


def test_verify_run_valid_chain_returns_0(tmp_path: Path):
    log, pub_pem = _emit_session(tmp_path)
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(pub_pem)
    result = run_verify(VerifyArgs(path=str(log), pubkey_path=str(pub_path)))
    assert result.exit_code == 0
    assert "chain ok" in result.message
    assert "signatures ok" in result.message


def test_verify_run_detects_tampering(tmp_path: Path):
    log, _ = _emit_session(tmp_path)
    contents = log.read_bytes()
    tampered = bytearray(contents)
    # Flip a letter byte
    idx = next(i for i, b in enumerate(tampered) if chr(b).isalpha())
    tampered[idx] = ord("Z") if tampered[idx] != ord("Z") else ord("Y")
    log.write_bytes(bytes(tampered))
    result = run_verify(VerifyArgs(path=str(log), pubkey_path=None))
    assert result.exit_code == 1


# =====================================================================
# guardian-baseline
# =====================================================================


def test_baseline_parse_args_basic():
    parsed = parse_baseline_args(["log.jsonl"])
    assert parsed is not None
    assert parsed.path == "log.jsonl"
    assert parsed.check is False
    assert parsed.sigma == 3.0


def test_baseline_parse_args_check_with_custom_sigma():
    parsed = parse_baseline_args(["log.jsonl", "--check", "--sigma", "2.5"])
    assert parsed is not None
    assert parsed.check is True
    assert parsed.sigma == 2.5


def test_baseline_parse_args_rejects_zero_sigma():
    assert parse_baseline_args(["log.jsonl", "--sigma", "0"]) is None


def test_baseline_parse_args_missing_path_returns_none():
    assert parse_baseline_args([]) is None


def test_baseline_run_writes_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log, _ = _emit_session(tmp_path)
    out_dir = tmp_path / "baselines"
    monkeypatch.setenv("FLOWDOT_BASELINES_DIR", str(out_dir))
    result = run_baseline(BaselineArgs(path=str(log), agent=None, out=None, check=False, sigma=3.0))
    assert result.exit_code == 0
    assert len(result.profiles_written) == 1
    written = Path(result.profiles_written[0])
    assert written.exists()
    profile = json.loads(written.read_text(encoding="utf-8"))
    assert profile["agent_id"] == "agent-cli"
    assert profile["total_records"] > 0


def test_baseline_run_check_no_deviation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log, _ = _emit_session(tmp_path)
    monkeypatch.setenv("FLOWDOT_BASELINES_DIR", str(tmp_path / "baselines"))
    # First write a baseline
    run_baseline(BaselineArgs(path=str(log), agent=None, out=None, check=False, sigma=3.0))
    # Now check the same file against itself → no deviations
    result = run_baseline(BaselineArgs(path=str(log), agent=None, out=None, check=True, sigma=3.0))
    assert result.exit_code == 0
    assert "no deviations" in result.message


def test_baseline_run_check_missing_baseline_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log, _ = _emit_session(tmp_path)
    monkeypatch.setenv("FLOWDOT_BASELINES_DIR", str(tmp_path / "absent"))
    result = run_baseline(BaselineArgs(path=str(log), agent=None, out=None, check=True, sigma=3.0))
    assert result.exit_code == 1
    assert "no baseline" in result.message


def test_baseline_missing_file_returns_1():
    result = run_baseline(BaselineArgs(path="/no/such/file.jsonl", agent=None, out=None,
                                       check=False, sigma=3.0))
    assert result.exit_code == 1


def test_baseline_out_with_multiple_agents_returns_2(tmp_path: Path):
    log_a, _ = _emit_session(tmp_path, agent="agent-a")
    log_b, _ = _emit_session(tmp_path, agent="agent-b")
    # Combine into one file
    combined = tmp_path / "combined.jsonl"
    # Just use one file; emit_session writes one agent per file
    # Build a combined file manually
    combined.write_text(
        log_a.read_text(encoding="utf-8") + log_b.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    result = run_baseline(BaselineArgs(path=str(combined), agent=None,
                                       out=str(tmp_path / "out.json"),
                                       check=False, sigma=3.0))
    assert result.exit_code == 2


# =====================================================================
# guardian-correlator
# =====================================================================


def test_correlator_parse_args_requires_two_sources():
    assert parse_correlator_args(["only.jsonl:cli"]) is None


def test_correlator_parse_args_basic():
    parsed = parse_correlator_args(["a.jsonl:cli", "b.jsonl:mcp", "--out", "x.jsonl"])
    assert parsed is not None
    assert parsed.sources == [("a.jsonl", "cli"), ("b.jsonl", "mcp")]
    assert parsed.out == "x.jsonl"


def test_correlator_parse_args_threshold_in_range():
    assert parse_correlator_args(["a:1", "b:2", "--threshold", "1.5"]) is None
    parsed = parse_correlator_args(["a:1", "b:2", "--threshold", "0.5"])
    assert parsed is not None and parsed.threshold == 0.5


def test_correlator_parse_args_rejects_malformed_path_surface():
    # Missing surface part (trailing colon at end)
    assert parse_correlator_args(["a:", "b:mcp"]) is None
    # Missing colon entirely
    assert parse_correlator_args(["a", "b:mcp"]) is None


def test_correlator_parse_args_supports_windows_drive_path():
    """The path:surface split must split on the LAST colon so C:\\... works."""
    parsed = parse_correlator_args(["C:/path/to/a.jsonl:cli", "D:/b.jsonl:mcp"])
    assert parsed is not None
    assert parsed.sources[0] == ("C:/path/to/a.jsonl", "cli")
    assert parsed.sources[1] == ("D:/b.jsonl", "mcp")


def test_correlator_run_writes_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Two surfaces with overlapping sessions for the same agent_id → at least one match."""
    log_a, _ = _emit_session(tmp_path, agent="shared")
    # Make a second source with the SAME agent_id but a different session_id and
    # an overlapping timestamp window — overlapping sessions matcher should fire.
    log_b = tmp_path / "shared-mcp.jsonl"
    priv_pem, _ = generate_ed25519_keypair()
    priv = load_private_key(priv_pem)
    w = AuditLogWriter(AuditLogWriterOptions(
        path=str(log_b), agent_id="shared", session_id="sess-mcp", sign_with=priv,
    ))
    w.append({"kind": "session_open", "status": "approved", "initiator": "system"})
    # Use identical args to a call from log_a so args_hash_collision matcher fires
    w.append({"kind": "tool_call", "status": "pending", "initiator": "agent",
              "tool": {"name": "list_accounts", "args": {"i": 0}}})
    w.append({"kind": "session_close", "status": "approved", "initiator": "system"})
    w.close()

    out_path = tmp_path / "correlations.jsonl"
    args = CorrelatorArgs(
        sources=[(str(log_a), "cli"), (str(log_b), "mcp")],
        out=str(out_path),
    )
    result = run_correlator(args)
    assert result.exit_code == 0
    # Both writes happened in the same minute → expect an overlap match
    assert out_path.exists()
    lines = [l for l in out_path.read_text(encoding="utf-8").splitlines() if l]
    parsed = [json.loads(l) for l in lines]
    assert any(p["kind"] == "x_cross_surface_match" for p in parsed)


def test_correlator_missing_file_returns_1(tmp_path: Path):
    args = CorrelatorArgs(sources=[("/no/such/a.jsonl", "cli"), ("/no/such/b.jsonl", "mcp")])
    result = run_correlator(args)
    assert result.exit_code == 1


def test_correlator_run_too_few_sources_returns_2():
    args = CorrelatorArgs(sources=[("a.jsonl", "cli")])
    result = run_correlator(args)
    assert result.exit_code == 2
