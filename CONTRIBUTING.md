# Contributing to `guardian-agent` (Python)

Thanks for looking. This is a pre-alpha reference implementation of the [guardian-agent SPEC](./SPEC.md). The TypeScript sister implementation lives at [`flowdot-llc/guardian-agent-ts`](https://github.com/flowdot-llc/guardian-agent-ts); both must conform to the same SPEC.

## Ground rules

### 1. The SPEC is the contract — both implementations must move together

`guardian-agent` (this repo, Python) and `@flowdot.ai/guardian-agent` (the npm package, TypeScript) implement the same language-neutral [SPEC.md](./SPEC.md). The bidirectional conformance bar is the gate:

> An audit log written + signed by either implementation MUST validate cleanly under the OTHER implementation's `guardian-verify` CLI.

If you touch the wire format (canonical-JSON serialization, hash chain, ed25519 signature shape, audit-record field semantics, policy file format, gate protocol), you **must**:

1. Update both implementations in lockstep.
2. Run both test suites green.
3. Run the bidirectional conformance tests in [`flowdot-mcp-py/tests/test_cross_language.py`](../flowdot-mcp-py/tests/test_cross_language.py) and `test_bidirectional_conformance.py` green.
4. Bump SPEC.md version + both package versions in the same release window.

PRs that change wire format without the TypeScript counterpart will be returned for revision.

### 2. No false E-stops, ever

Any mechanism that can trigger an emergency-stop (capability rules, honeytokens, heartbeat, rate-limiter denials) must ship Yellow-only (audit-row, no behavior change) until the negative-corpus harness in `tests/safety/test_no_false_trip.py` proves zero false positives against real production audit logs at the proposed thresholds.

> A mechanism that can't be calibrated to zero false positives on real data does not ship as an E-stop trigger.

Promotion criteria from Yellow → Red are in SPEC §13.3. The negative-corpus replay tests are the load-bearing gate.

### 3. No comments that re-state the code, no "// TODO" stubs

The repo follows the rule from `CLAUDE.md`: comments only for non-obvious WHY (hidden constraints, subtle invariants, workarounds for specific bugs, behavior that would surprise a reader). Identifier names carry the WHAT.

No `# TODO`, no `pass  # stub`, no half-finished implementations. Either land the change or don't open the PR. See `feedback_true_solution_only` in the maintainer's notes.

## Dev setup

Requires Python 3.10+ on Windows / Linux / macOS.

```bash
git clone https://github.com/flowdot-llc/guardian-agent.git
cd guardian-agent
py -3.11 -m pip install -e .[dev] --no-build-isolation
```

If `pip install -e` errors with a hatchling editable-install issue, try `pip install --upgrade hatchling editables` first.

## Running tests

```bash
py -3.11 -m pytest                  # full suite (~329 tests, ~1 second)
py -3.11 -m pytest tests/safety/    # negative-corpus harness only
py -3.11 -m pytest -k attestor      # match by test name
```

The bidirectional cross-language tests require Node.js on PATH and the TypeScript implementation built at `E:/FlowdotPlatform/guardian-agent-ts/dist/`. They live in `../flowdot-mcp-py/tests/` and are skipped when Node is unavailable. To run them:

```bash
cd ../flowdot-mcp-py
py -3.11 -m pytest tests/test_cross_language.py tests/test_bidirectional_conformance.py -v
```

## Linting and type-checking

```bash
py -3.11 -m ruff check src/         # zero errors required to merge
py -3.11 -m ruff format --check src/
py -3.11 -m mypy src/               # strict mode
```

## Project layout

```
src/guardian_agent/
  runtime/      GuardianRuntime, ToolOptions, capability, honeytokens, multi_rate_limiter
  audit/        AuditLogWriter, AuditLogReader, signature (ed25519), chain, attestor, stats, correlation
  estop/        EStopLocal, heartbeat, hub, middleware (WSGI), poller
  policy/       PolicyStore, PolicyEvaluator, integrity (HMAC), site_key, attribution, gate_adapter
  gate/         cli, async_callback, programmatic, data_channel, two_key
  notify/       Notifier protocol + console / multi / webhook reference adapters
  cli/          guardian_verify, guardian_baseline, guardian_correlator
tests/
  safety/       Negative-corpus harness (no false E-stops, ever)
  fixtures/     Real audit-log snapshots from production surfaces (cli / mcp / mcp-py)
```

Layout mirrors the TypeScript implementation 1:1. When you add or rename a module, mirror the change on the TS side.

## Pull request expectations

- Branch from `main`. One PR = one logical change.
- Tests required for every behavior change. The negative-corpus harness MUST stay at zero false positives — re-run it locally before opening the PR.
- Reference the SPEC section your change implements (e.g., "SPEC §13.1: capability tags on audit records").
- If the change crosses to TypeScript, link the companion PR in `guardian-agent-ts`.
- CI (`.github/workflows/ci.yml`) must be green. There is no fast-merge path past a red CI.

## Releasing

Maintainers only — see [`Docs/DevGuides/PUBLISHING_GUIDE.md`](https://github.com/flowdot-llc/FlowdotPlatform/blob/main/Docs/DevGuides/PUBLISHING_GUIDE.md) for the full PyPI release workflow. Short version:

1. Bump version in `pyproject.toml`.
2. Update `CHANGELOG.md`.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. CI's `publish.yml` runs the full gate + uploads to PyPI via OIDC Trusted Publishing. No long-lived tokens.

## License

AGPL-3.0-or-later. By contributing you agree your contribution is licensed under the same terms. FlowDot LLC, as sole copyright holder, dual-licenses for proprietary internal use inside `@flowdot.ai/*` packages — this is the standard open-core arrangement and does not affect your AGPL-3.0 rights as a downstream consumer.

## Security

If you find a security vulnerability — especially anything that breaks the audit-log integrity guarantees, signature verification, hash-chain semantics, or the negative-corpus "no false positives" bar — please email `security@flowdot.ai` rather than opening a public issue.
