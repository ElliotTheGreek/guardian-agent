# guardian-agent roadmap

**Last updated**: 2026-05-13

Versioned plan for the next ~12 months. Dates are targets, not commitments; the order is firmer than the dates.

## v0.1.0 — Spec and audit log (now)

- [x] Public spec ([SPEC.md](./SPEC.md)) covering audit log record format, policy YAML, gate protocol, E-stop semantics, threat model, conformance.
- [x] Repository structure and license.
- [ ] Minimal Python reference implementation of `GuardianRuntime`.
- [ ] JSONL audit log writer with hash chain.
- [ ] `@runtime.tool` decorator that records `tool_call` + `tool_result` events.
- [ ] Quickstart example that runs end-to-end without any approval gate or policy enforcement (audit-only mode).
- [ ] `pytest` suite exercising every record kind in §2.4 of the spec.

**Exit criteria**: `pip install -e .` works; `python examples/quickstart.py` produces a valid `audit.jsonl`; `guardian-verify` (stub) recomputes the hash chain.

## v0.2.0 — Tool-permission scoping

- [ ] YAML policy loader matching §3 of the spec.
- [ ] Wildcard tool-name matching with specificity rules.
- [ ] `policy_check` event emission with `status: denied` or `status: approved`.
- [ ] Tests: every example in §3 of the spec, plus pathological cases (no defaults, conflicting wildcards, reserved prefixes).
- [ ] CLI tool: `guardian-policy validate <file.yaml>`.

## v0.3.0 — HITL approval gate

- [ ] `cli_approval_gate` — synchronous stdin prompt with full request context displayed.
- [ ] `async_callback_gate(url)` — POSTs `GateRequest`, awaits JSON response.
- [ ] `programmatic_gate(handler)` — Python callable handler.
- [ ] `allow_session` and `always_allow` semantics, including policy file persistence for `always_allow`.
- [ ] Tests: each gate adapter against each decision type.

## v0.4.0 — Emergency-stop + guardian-eval companion

- [ ] `runtime.estop()` API.
- [ ] `SIGUSR1` signal handler in the reference impl.
- [ ] `estop_event` for cross-thread halt.
- [ ] `GuardianHalted` exception; audit log flush on halt.
- [ ] **`guardian-eval` companion package**: `pip install guardian-eval`.
  - Battery of red-team tests: gate-bypass attempts, permission-escalation attempts, audit-log tampering attempts, blast-radius measurement on tool misuse.
  - Outputs a structured report (JSON) and a human-readable summary (Markdown).
  - Wraps any `GuardianRuntime` instance and runs the harness against it.
- [ ] Public test corpus: three frontier-model agents (Claude, GPT, Ollama) wrapped and scored against the eval. Results published as a write-up.

**This is the milestone that unlocks the "shared eval substrate" claim.**

## v0.5.0 — Signed audit logs

- [ ] ed25519 signature support per §2.6 of the spec.
- [ ] `guardian-verify --signatures` flag verifies signatures end-to-end.
- [ ] Key generation utility: `guardian-keygen`.
- [ ] Documentation on key distribution patterns (in-band, out-of-band, manifest-based).
- [ ] Test corpus: tampered logs (modified record, deleted record, reordered records); verification must detect each.

## v0.6.0–v0.9.0 — Hardening

Roughly grouped, ordered by expected pull:

- Pluggable audit log storage: SQLite, S3-compatible blob, OpenSearch sink.
- Argument redaction with schema-driven `*_hash` placeholders.
- Multi-instance hash-chain coordinator (distributed audit).
- Policy composition rules (merge multiple files with precedence).
- Tool-namespace conventions document (best practices for naming tools to interact well with the policy file).
- MCP integration adapter: wrap an MCP client/server transparently.

## TypeScript reference companion (parallel track)

A second reference implementation in TypeScript is being developed in [`flowdot-llc/guardian-agent-ts`](https://github.com/flowdot-llc/guardian-agent-ts). It follows the same versioned spec and the same release cadence; v0.1.0 in TypeScript lands when v0.1.0 in Python lands, and so on. The Python implementation in this repository remains the reference for the spec; the TypeScript implementation is "the same spec, second language" for Node-shaped production runtimes (Electron, server-side Node, TypeScript MCP clients). Both feed `guardian-eval` via the shared audit-log format and gate protocol.

FlowDot's commercial platform runs an independent TypeScript runtime that also conforms to the spec; it predates `guardian-agent-ts` and is a separate codebase. The shared artifact is the spec, not the source code.

## v1.0.0 — Stable

- [ ] No breaking spec changes for 90 days.
- [ ] Conformance test suite published; third-party implementations can certify against it.
- [ ] At least one production deployment outside FlowDot itself (a regulated-industry adopter, an eval lab, or an open-source agent project).
- [ ] First public red-team study published: gate-bypass and audit-log evasion results across N agent frameworks, written up for a venue (workshop paper or technical report).

---

## Non-goals through v1.0

These are intentionally out of scope. If they belong in `guardian-agent` we'll learn that and re-scope; the default is "no":

- **A web UI** — the runtime is a library. Render the audit log however you want; the JSONL is the API.
- **Multi-tenant operation** — one runtime, one logical agent set. Multi-tenant deployment is the host platform's job.
- **Authentication and authorization of operators** — `operator_id` is opaque to the runtime. Auth is the gate adapter's responsibility.
- **Cost tracking, billing, quota enforcement** — the audit log carries token counts when known, but `guardian-agent` does not enforce limits.
- **Becoming an agent framework** — there are several good ones. We compose with them.

## How to influence the roadmap

Open an issue. Describe the use case, not just the feature. The roadmap above reflects priorities derived from concrete adopter requests; anything that helps a regulated-industry deployer, an evaluation team, or an open-source agent project ship a real system gets priority over generality.

## Funding-aware sequencing

This roadmap assumes a 6-month focused-work window. If that window does not materialize via grant support, the pace slows but the order does not change — v0.1 → v0.2 → v0.3 → v0.4 (with eval companion) is the load-bearing sequence regardless.

The v0.4 milestone (eval companion + public red-team write-up) is the load-bearing deliverable for the AI safety funding pathway. Everything before it is necessary; everything after it is durability.
