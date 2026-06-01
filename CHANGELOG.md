# Changelog

All notable changes to this Python implementation of `guardian-agent` are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/). Versions follow [semver](https://semver.org/) — see `Docs/DevGuides/PUBLISHING_GUIDE.md` "Version Management" for the cross-language coupling rules with `@flowdot.ai/guardian-agent` on npm.

## [0.2.0] - 2026-05-21

First public PyPI release. Brings the Python reference implementation to **SPEC v0.5 parity** with the TypeScript implementation, including the full v0.8 runtime-safety layer and offline analysis CLIs.

### Added — Audit log

- ed25519 record signing on `AuditLogWriter` (matches TS PKCS#8 + SPKI PEM format; same wire shape — `signature: "ed25519:<base64url>"`).
- `AuditLogReader.verify_signatures(public_key)` for chain-plus-signature verification.
- External chain attestation: `Attestor` protocol, `http_attestor`, `null_attestor`, writer integration with `attest_every` + `attest_on_close` + recursion guard; emits `x_chain_attested` / `x_chain_attestation_failed` rows.
- `x_*` extension audit kinds support per SPEC §10 (`x_chain_attested`, `x_capability_yellow`, `x_honeytoken_triggered`, `x_heartbeat_warning`, `x_rate_limit_breached`, `x_cross_surface_match`, `x_session_recovered`, `x_panic_clear_warning`).
- `pending_operator` status (SPEC §4.5 / v0.4+).
- `tool.capabilities` field on audit records (SPEC §13.1).
- `surface` + `aggregator` attribution segments on `ModelAttribution`.
- Behavioral baselines (`AgentProfile`, σ-deviation reports) — backs the `guardian-baseline` CLI.
- Cross-surface correlation (`AuditSource`, `correlate`, overlap / args-hash / cosine similarity matchers) — backs the `guardian-correlator` CLI.

### Added — Gate subsystem

- HITL approval gate: `cli_approval_gate` (stdin), `async_callback_gate` (HTTP POST), `programmatic_gate` (callback), `data_channel_gate` (LiveKit-style frame encode/decode).
- Two-key operator authorization: `OperatorConfirmationGate` protocol, `callback_operator_gate`, `deny_all_operator_gate`, `await_with_timeout`.
- Gate option sets: `FLOWDOT_FIVE`, `CLASSIC_FOUR`, `define_gate_option_set`.

### Added — Runtime safety primitives

- `MultiRateLimiter` with `DEFAULT_BUCKETS` (`credential=2/s`, `delete=1/s`, `network-egress=5/s`, `read=50/s`, etc.).
- `CapabilityWindow` + `CapabilityRule` for sliding-window combination detection. Ships Yellow-only — Red-line auto-stop pending Yellow telemetry calibration.
- `HoneytokenSet` with value + phantom-tool detection. Zero false positives by construction.
- `GuardianRuntime.tool()` wires honeytoken → estop → two-key → tool_call → capability window → policy gate → execute → tool_result.

### Added — EStop hub coordination

- `HeartbeatMonitor` (dead-man's heartbeat — opt-in; default off).
- `EStopHub` with cached `is_pressed`, `InMemoryEStopStateStore`, WSGI 423 middleware, `EStopPoller`.

### Added — Policy

- `policy.attribution` flat-glob matching against 4-segment `surface/aggregator/provider/id` paths.
- `policy_store_gate` adapter wrapping `PolicyStore` as a `PolicyGate`.
- `PolicyWhen.attribution_path` for model-aware rule matching.

### Added — Notify adapters

- `console_notifier`, `multi_notifier`, `webhook_notifier` (urllib-based, no httpx dependency in the library).

### Added — CLIs

- `guardian-verify` — audit-log integrity verification (chain + signatures). Wired through `[project.scripts]`.
- `guardian-baseline` — per-`agent_id` σ-deviation reporting.
- `guardian-correlator` — cross-surface match detection.

### Added — Tests

- 329 tests passing on Windows + Linux.
- Negative-corpus harness (`tests/safety/test_no_false_trip.py`) replaying real audit logs from three surfaces (`cli`, `mcp`, `mcp-py`) through every v0.8 detector at default thresholds — zero false positives.
- Bidirectional cross-language conformance proved against the TypeScript implementation: TS-written logs validate under Python `guardian-verify`; Python-written logs validate under TS `guardian-verify`. See `flowdot-mcp-py/tests/test_cross_language.py` + `test_bidirectional_conformance.py`.

### Changed

- `cryptography>=42.0` is now a required dependency (was an optional `[signatures]` extra). Signing is no longer optional.
- `[project.urls]` fixed to point at `github.com/flowdot-llc/guardian-agent` (was incorrect `github.com/flowdot/guardian-agent`).

### Cross-language coupling

This release ships in lockstep with `@flowdot.ai/guardian-agent@0.2.0` on npm. Both implementations conform to SPEC v0.5; either's `guardian-verify` validates either's audit logs.

## [0.1.0] - 2026-05-14

Initial Python skeleton: trust foundation primitives (audit chain without signing, estop, policy, runtime). Unsigned wire format. Not published to PyPI.
