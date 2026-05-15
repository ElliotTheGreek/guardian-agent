# guardian-agent specification

**Version**: 0.5.0
**Status**: draft · interface stabilizing
**Last updated**: 2026-05-14

This document specifies the wire formats, file formats, and runtime semantics of the `guardian-agent` primitives. It is implementation-language-neutral. A "conforming implementation" produces audit-log records readable by any other conforming implementation, accepts policy files in the format below, exposes the gate protocol described, and implements emergency-stop semantics with identical observable behavior.

The spec is extracted from FlowDot LLC's production supervisor system (CLI, Native Electron, Mobile React Native, Hub Laravel backend, MCP server, VR Unity). The reference implementations are Python (`flowdot-llc/guardian-agent`) and TypeScript (`flowdot-llc/guardian-agent-ts`).

---

## 1. Scope

This spec is **language-neutral**. Implementations in any language are welcome.

What "two implementations conform to the same spec" means in practice:
- An audit-log file produced by one MUST be readable and hash-chain-verifiable by another.
- A `permissions.yaml` written for one MUST be honored identically by another.
- A gate callback URL hosted by one MUST be invocable by another.
- An `estop` triggered in one MUST produce an audit event identical in structure to one triggered in another.
- HMAC-signed policy files written by one MUST verify under another (see §3.5 site-key contract).

This spec defines:
- §2 — Audit log record format
- §3 — Tool-permission policy: file format, scopes, resolution order, HMAC integrity, site key
- §4 — HITL approval gate protocol
- §5 — Emergency-stop primitive semantics (in-process and hub-coordinated patterns)
- §6 — Notification fan-out
- §7 — Operator-initiated vs. agent-initiated actions
- §8 — Threat model
- §9 — Versioning and compatibility
- §10 — Conformance checklist

This spec does NOT define:
- How agents call tools (use any framework: LangChain, AutoGen, MCP, native)
- How models are routed or selected
- How to render the audit log (any JSONL reader works)
- How to operate the supervisor in production (deployment, multi-tenancy, billing)
- Which programming language an implementation uses

---

## 2. Audit log records

### 2.1 Storage

Default storage is **JSON Lines** (JSONL): one JSON object per line, UTF-8 encoded, LF-terminated. Append-only. Records are written in event-occurrence order.

### 2.2 Record schema

```json
{
  "v": "0.2.0",
  "event_id": "evt_01HXYZ7T9P6M3Q5R8KZNB2WVCM",
  "ts": "2026-05-13T23:45:12.345Z",
  "agent_id": "agent_abc123",
  "session_id": "sess_xyz789",
  "kind": "tool_call",
  "tool": {
    "name": "schwab_trading.list_accounts",
    "args": { "broker": "schwab" },
    "result": null,
    "duration_ms": null
  },
  "model": {
    "provider": "anthropic",
    "id": "claude-opus-4",
    "input_tokens": 1234,
    "output_tokens": 567
  },
  "status": "approved",
  "initiator": "operator",
  "prev_hash": "sha256:9f8c2a...",
  "signature": null
}
```

### 2.3 Field reference

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | string | yes | Spec version this record conforms to (semver). |
| `event_id` | string | yes | Globally unique identifier. ULID recommended. |
| `ts` | string | yes | ISO-8601 timestamp, millisecond precision, UTC, `Z`-suffixed. |
| `agent_id` | string | yes | Stable identifier for the agent instance. |
| `session_id` | string | yes | Identifier for the agent's current logical session. |
| `kind` | enum | yes | See §2.4. |
| `tool` | object | conditional | Required for tool/gate/policy events. |
| `tool.name` | string | conditional | `<namespace>.<function>` or bare `<function>`. |
| `tool.args` | object | conditional | Tool arguments. Object, never string. |
| `tool.result` | any | conditional | Populated on `tool_result`. May be `null`. |
| `tool.duration_ms` | number | conditional | Wall-clock duration on `tool_result`. |
| `model` | object | conditional | Identifies which model issued the call. Populated on `tool_call` when known. |
| `model.provider` | string | conditional | Lowercase: `anthropic`, `openai`, `ollama`, `local`. |
| `model.id` | string | conditional | Provider-specific model identifier. |
| `model.input_tokens` | number | optional | Input token count. |
| `model.output_tokens` | number | optional | Output token count. |
| `status` | enum | yes | `pending` \| `approved` \| `denied` \| `executed` \| `errored` \| `halted`. |
| `initiator` | enum | yes | `operator` \| `agent` \| `system`. See §7. |
| `prev_hash` | string | yes | `sha256:<hex>` over the previous record's full JSON bytes. `sha256:0` for first. |
| `signature` | string | optional | `ed25519:<base64url>` over the record bytes with `signature` cleared. v0.5+. |

### 2.4 Event kinds and sequences

`kind` values: `session_open` · `tool_call` · `gate_request` · `gate_response` · `policy_check` · `tool_result` · `estop_press` · `estop_clear` · `session_close`.

**Approved tool call** (4 events):
1. `tool_call` (status `pending`)
2. `gate_request` (status `pending`)
3. `gate_response` (status `approved`)
4. `tool_result` (status `executed`)

**Denied call via gate** (3 events):
1. `tool_call` (`pending`)
2. `gate_request` (`pending`)
3. `gate_response` (`denied`) — terminal

**Policy-blocked call** (2 events):
1. `tool_call` (`pending`)
2. `policy_check` (`denied`) — terminal, no gate

**Pre-approved call** (3 events, e.g. `forever-allow`):
1. `tool_call` (`pending`)
2. `policy_check` (`approved`)
3. `tool_result` (`executed`)

**Emergency-stop press**: a terminal `estop_press` (`halted`) event. Any in-flight `gate_request` resolves with `decision: deny`, `reason: "halt"`. Subsequent calls raise `GuardianHalted` until clear.

**Emergency-stop clear**: an `estop_clear` event. Session resumes only by constructing a new runtime (see §5.4).

### 2.5 Hash chain

`prev_hash` is computed over the previous record's complete JSON bytes (including its own `prev_hash` field, excluding trailing newline). First record uses `sha256:0`. A reader verifies log integrity by recomputing the chain. A break indicates tampering, truncation, or out-of-order writes.

### 2.6 Signatures (v0.5+)

When present, `signature` is an ed25519 signature over the record bytes with `signature: null`. Public keys are distributed out-of-band. Key rotation is out of scope for v0.x.

---

## 3. Tool-permission policy

### 3.1 File format

YAML. One policy file per agent or agent class. Two files together form the active state:

- `permissions.yaml` (or `.json`) — HMAC-signed; persisted `forever` and `banned` rules.
- `session.yaml` — unsigned; in-session `session` rules. Discarded between sessions.

```yaml
version: "0.2"
agent_id: "agent_demo"

defaults:
  scope: prompt        # prompt | once | session | forever | banned

rules:
  # Exact-match rules win over wildcards.
  - tool: "filesystem.read"
    scope: forever
    decision: allow

  - tool: "filesystem.write"
    scope: banned          # permanent deny

  - tool: "schwab_trading.*"
    scope: session
    decision: allow

  - tool: "network.http_post"
    scope: prompt          # always ask
```

### 3.2 Decisions and scopes (orthogonal axes)

Decisions: `allow` | `deny`.

Scopes (persistence): `once` | `session` | `forever` | `banned`.

- `once` — applies to this call only; not persisted.
- `session` — applies within the current `session_id`; lives in `session.yaml`.
- `forever` — applies across sessions; lives in `permissions.yaml`.
- `banned` — `(decision=deny, scope=forever)`. The shorthand exists because it's the most common deny pattern.

The synthetic scope `prompt` means "no rule matches; consult the configured gate."

### 3.3 Resolution order

For a given tool name in a given session, the evaluator returns the **first matching** decision in this order:

1. `banned` (forever-deny, exact match)
2. `banned` (forever-deny, wildcard match)
3. `forever` allow (exact match)
4. `forever` allow (wildcard match)
5. `session` allow (exact match)
6. `session` allow (wildcard match)
7. `defaults.scope` if not `prompt`
8. `prompt` (invoke gate)

**Banned beats allow at every layer.** A `banned` rule cannot be overridden by an allow rule, ever. This is the "kill switch for tools" semantic from FlowDot's existing permission service.

### 3.4 Matching rules

Tool names match using shell-style globs (`fnmatch`):
- `*` matches any sequence including the empty string
- `?` matches exactly one character
- `[seq]` matches one character from the set

Wildcard `*` alone matches every tool. Exact match always wins over any wildcard match. Among multiple wildcards of equal specificity, the first listed wins.

Reserved tool-name prefixes (MUST NOT appear in policy files): `guardian.`, `runtime.`, `internal.`.

### 3.5 HMAC integrity and the site key

`permissions.yaml` MUST be signed with HMAC-SHA256. On disk, the file is wrapped:

```yaml
version: 1
signed_at: "2026-05-13T23:45:12.345Z"
signature: "<base64-hmac-sha256>"
data: |
  version: "0.2"
  agent_id: "agent_demo"
  defaults:
    scope: prompt
  rules: ...
```

The HMAC is computed over the UTF-8 bytes of the canonical-form `data` payload, using the **site key** as the HMAC key.

**Site key**:
- Stored in `.flowdot/site.key` (or platform-appropriate equivalent).
- 32 random bytes, generated on first run if absent.
- File mode `0o600` (owner read/write only).
- Never transmitted; never logged.

Cross-language interop note: deriving the integrity key from OS identifiers (hostname, cpu model, homedir) breaks cross-language portability — Python and TypeScript see slightly different identifier strings. The `site.key` file is the canonical solution and replaces any prior implementation that derived from OS state.

On signature verification failure, the implementation MUST refuse to load the file and MUST treat the policy as empty (fail-closed). It MAY emit a security audit event.

`session.yaml` is unsigned. It is rewritten on every change and cleared on session end.

### 3.6 Cross-surface storage convention

Implementations writing to a shared directory (e.g., `.flowdot/`) for multi-process or multi-surface use:

- Directory mode: `0o700` (owner-only).
- File mode: `0o600` for sensitive files (`permissions.yaml`, `session.yaml`, `site.key`).
- Audit logs (`audit.jsonl`) MAY be mode `0o600` or `0o640` depending on read-only access requirements.
- Concurrent writers MUST use OS-level file locks (advisory `flock` on Unix; `LockFileEx` on Windows) when writing the policy files.
- Secure delete (3-pass overwrite) before `unlink` for `permissions.yaml` and `site.key` deletion.

### 3.7 Categories (optional)

Tools MAY belong to categories. The library ships a default category set (`command-execute`, `file-read`, `file-write`, `file-create`, `network-write`, `network-read`, `mcp-tool`, `toolkit-tool`, `flowdot-tool`) but consumers MAY define their own.

Category-level rules use the prefix syntax `category:<name>`:

```yaml
rules:
  - tool: "category:file-write"
    scope: forever
    decision: allow
```

Category rules are evaluated **after** specific tool rules but **before** the wildcard fallback.

---

## 4. HITL approval gate

### 4.1 Interface

```python
@dataclass
class GateRequest:
    event_id: str          # event_id of the originating tool_call
    tool_name: str
    tool_args: dict
    agent_id: str
    session_id: str
    model: Optional[ModelAttribution]
    context: Optional[str]  # natural-language summary the agent provides
    granularity: Literal["tool", "toolkit", "category"]  # see §4.3
    timeout_ms: Optional[int]  # gate-side timeout hint

@dataclass
class GateResponse:
    decision: Literal["allow", "allow_session", "allow_forever", "deny", "ban_forever"]
    reason: Optional[str]
    operator_id: Optional[str]
    granularity: Literal["tool", "toolkit", "category"]
```

A gate is any callable matching:

```python
def approval_gate(request: GateRequest) -> GateResponse: ...
```

### 4.2 Decision semantics

- `allow` — this call proceeds. Re-prompts on the next call to the same identifier.
- `allow_session` — upgrades the in-memory policy: identifier becomes `(allow, session)`. Persisted to `session.yaml`.
- `allow_forever` — upgrades the persistent policy: identifier becomes `(allow, forever)`. Persisted to `permissions.yaml`.
- `deny` — this call does not proceed; no policy change.
- `ban_forever` — `(deny, forever)`: identifier is banned. Persisted to `permissions.yaml`. Equivalent to setting the rule's `scope: banned`.

### 4.3 Granularity

`granularity` determines what identifier the decision applies to:

- `tool` — applies only to this specific tool name (e.g., `schwab_trading.list_accounts`).
- `toolkit` — applies to all tools under the same toolkit/namespace prefix (e.g., `schwab_trading.*`).
- `category` — applies to all tools sharing the same category (e.g., `category:file-write`).

The gate request includes the runtime's suggested granularity; the gate response confirms or downgrades it. A response MUST NOT escalate granularity (e.g., responding `toolkit` to a `tool`-level request) — that requires a separate gate invocation.

### 4.4 Reference gate implementations

| Adapter | Transport | Use case |
|---|---|---|
| `cli_approval_gate` | Blocking stdin prompt | Local development, single-process CLI |
| `async_callback_gate(url)` | POST `GateRequest`, await JSON response | Web/native UI with separate operator app |
| `programmatic_gate(handler)` | Direct callable | Host has its own UI (Electron renderer, mobile RN, etc.) |
| `data_channel_gate` | LiveKit data-channel frames | Voice/live-agent surfaces |

Conforming implementations SHOULD provide at least `cli` and `programmatic`.

### 4.5 Operator identification

`operator_id` is opaque to the runtime. Recorded in audit for attribution. The runtime does not authenticate operators — that is the gate adapter's responsibility.

### 4.6 Gate timeout and halt behavior

If the gate does not respond within `timeout_ms` (default 600,000 ms = 10 min), the runtime treats it as `deny` with `reason: "gate_timeout"` and emits a `gate_response` event accordingly.

If `estop` fires while a gate request is in flight, the gate is auto-resolved with `decision: deny`, `reason: "halt"`.

---

## 5. Emergency-stop

The supervisor primitive comes in two deployment shapes. Both share the audit-log shape and observable behavior.

### 5.1 Triggers (both shapes)

1. **In-process call**: `runtime.estop(reason, operator_id?)`.
2. **POSIX signal**: SIGUSR1 reserved. (Note: Node uses SIGUSR1 for inspector; TS impl uses SIGUSR2.)
3. **Cross-process broadcast**: see §5.3 / §5.4 per shape.

### 5.2 Common semantics on press

1. Set internal halt flag.
2. Any tool currently executing is allowed to complete (no forced interruption).
3. Any pending `gate_request` auto-resolves as `deny / halt`.
4. The next attempt to wrap or call a tool raises `GuardianHalted`.
5. An `estop_press` event is written with `status: halted` and `initiator: operator`.
6. Audit log is flushed.
7. Notifier fan-out fires (see §6).

The runtime does NOT call `sys.exit` / `process.exit`. Halt is scoped to the runtime; the host decides how to react.

### 5.3 In-process pattern (single-process deployment)

For researcher / eval / standalone-agent use cases:

- Halt flag is a process-local `AbortController` / `threading.Event`.
- No HTTP, no middleware, no DB.
- Clear: construct a new `GuardianRuntime` instance. The flag and the audit-log session ID are immutable; halts are session-terminal.

This is the default mode for `GuardianRuntime` constructed without an explicit `EStopHub` adapter.

### 5.4 Hub-coordinated pattern (FlowDot's production deployment)

For multi-surface platforms (web hub + native + mobile + CLI + MCP):

- **State table**: server-side row per user (or per agent), `pressed_at` / `cleared_at` columns. Append-only `estop_events` audit table.
- **Hot-path cache**: server caches the `isPressed(userId)` query with a 1-second TTL. Cache invalidated on every press and clear.
- **Press fan-out**: a single endpoint (`POST /api/.../estop`) sets the sticky flag, forwards to in-flight runtimes (Node servers, daemons), broadcasts via a poll-channel for offline daemons, writes audit, fires notifier.
- **Middleware gate**: side-effectful HTTP routes opt into an `EnsureNotPressed` middleware that returns **HTTP 423 Locked** with structured JSON while a press is active. Default ungated; opt-in per route.
- **Clear**: separate endpoint protected by recent-auth (e.g., password.confirm). Always reachable while pressed.
- **Pull-based safety net**: daemons that may miss push broadcasts poll the status endpoint every 5s.
- **Per-user scoping**: every press, clear, and check is bound to a single user identity. Admin-style cross-user actions MUST NOT exist.

The 423 status was chosen over 403 because RFC 4918 423 carries the specific semantic of "the resource is currently locked" — a temporary, owner-clearable condition.

### 5.5 Two-tap arming (UI convention)

Press controls SHOULD use two-tap arming with a 3-second window:
1. First tap arms the control (color tint, label change).
2. Second tap within 3 s fires the press.
3. Timer expires silently if no second tap.

This is a UX convention, not a wire requirement. A conforming implementation MAY use a different confirm pattern.

### 5.6 Local instant feedback

Press handlers SHOULD perform local instant feedback (cancel local runtime, collapse UI) **before** the network call, so the user sees motion immediately. The network call is fire-and-forget at the UI layer; failures only log.

---

## 6. Notifications

### 6.1 Interface

A notifier is any callable matching:

```python
def notifier(event: NotificationEvent) -> None: ...

@dataclass
class NotificationEvent:
    kind: Literal["estop_press", "estop_clear", "policy_breach", "gate_denied"]
    user_id: Optional[str]
    agent_id: str
    ts: str
    source: str               # "cli" | "native" | "mobile" | ...
    summary: dict             # e.g. { stopped_executions: 2, ip: "1.2.3.4" }
    canonical_clear_url: Optional[str]
```

### 6.2 Mandatory fan-out events

A conforming implementation MUST fire notifications on:

- `estop_press` — every press, every time.
- `estop_clear` — every clear, every time.

A conforming implementation MAY fire notifications on `policy_breach` (a `banned` tool was attempted) and `gate_denied` (an operator denied a gate prompt).

### 6.3 Reference notifier adapters

| Adapter | Transport | Use case |
|---|---|---|
| `console_notifier` | stderr write | Development |
| `webhook_notifier(url)` | POST JSON | Production HTTP integrations |
| `email_notifier(config)` | SMTP send | Operator paging |
| `multi_notifier([n1, n2, ...])` | Fan-out to several | Production |

### 6.4 Signed URLs

When the notification includes a `canonical_clear_url`, the URL SHOULD be cryptographically signed (e.g., HMAC token in query string) so it cannot be forged. This is a recommendation, not a requirement.

---

## 7. Operator-initiated vs. agent-initiated actions

Every audit record carries an `initiator` field:

- `operator` — direct human action (UI tap, API call carrying the appropriate header).
- `agent` — autonomous tool-using agent action.
- `system` — runtime-internal (timeouts, signal handlers).

Implementations MUST reject `estop_clear` requests with `initiator: agent`. Adversarial prompt injection that convinces an agent to clear its own kill switch is the most dangerous failure mode; this check is the load-bearing defense.

Implementations MAY reject `estop_press` requests with `initiator: agent` if the deployment configuration sets `allow_agent_initiated_press: false` (default: `true`, since agents *should* be able to halt themselves on detected anomaly).

The `initiator` is determined by an HTTP header on hub-coordinated deployments (e.g., `x-guardian-initiator: operator | agent | system`) and by an explicit argument on in-process calls.

---

## 8. Threat model

### 8.1 Defends against

- **Unintended tool invocation by the agent** — policy + gate intercept.
- **Tool-call drift** — sequence of approved calls leading to unwanted outcome (mitigated, not solved).
- **Post-incident reconstruction** — hash-chained audit log records what happened.
- **Silent denial of service** — every press AND clear notifies the operator; silent DoS becomes noisy.
- **Cross-user attack** — per-user scoping at every level; no admin override.
- **Audit-log tampering** — hash chain detects modification; optional signatures prove authorship.
- **Adversarial prompt injection clearing E-stop** — `initiator: agent` requests for clear are rejected (§7).
- **Policy-file tampering** — HMAC integrity; fail-closed on verification failure (§3.5).
- **Post-compromise log rewriting** — external chain attestation (§11) detects tamper of the local log after the fact.
- **Credential probing** — honeytokens (§12) detect tools accessing decoy values with zero false positives.
- **Exfiltration bursts** — per-capability rate buckets (§14) bite credential + network-egress patterns long before the global rate.
- **Operator-bypass on sensitive actions** — two-key gate (§15) suspends dispatch pending fresh operator confirmation.
- **Runaway loops** — dead-man's heartbeat (§16) auto-halts sessions that stop signaling liveness.
- **Cross-surface compromise** — offline correlator (§18) detects parallel sessions of the same agent_id across surfaces.

### 8.2 Does NOT defend against

- **Compromised runtime process** — if the process is fully compromised, the supervisor is too.
- **Compromised model** — supervisor catches malicious tool calls at the gate (if configured) but cannot detect malicious content in outputs alone.
- **Prompt injection of agent input** — handled at a lower layer (e.g., Tripwire).
- **Side-channel data exfiltration** — out of scope.
- **Compromised storage** — if attacker can write `permissions.yaml` AND has the site key, supervisor is bypassed.

### 8.3 Assumptions

- The host process and runtime are trusted.
- The audit log destination is append-only and access-controlled by the host system.
- The site key is protected by filesystem permissions appropriate to the host environment.

---

## 9. Versioning and compatibility

Semantic versioning. MAJOR bumps on incompatible wire-format changes; MINOR on additive fields; PATCH on clarifications.

Readers MUST accept records with patch/minor differences from their own. Readers SHOULD reject records with a higher MAJOR version.

The `v` field in every record is the spec version the writer claims to conform to.

---

## 10. Conformance checklist

A conforming implementation MUST:

- [ ] Emit JSONL records matching §2.2 with all required fields present.
- [ ] Maintain the hash chain per §2.5.
- [ ] Honor the four scopes per §3.2 and the resolution order per §3.3.
- [ ] HMAC-sign the persistent policy file using the site key (§3.5); fail-closed on verification failure.
- [ ] Implement the gate protocol per §4.1 with all five decision values per §4.2.
- [ ] Provide an emergency-stop primitive per §5 that produces the documented event sequence.
- [ ] Fire notifications on every `estop_press` and `estop_clear` per §6.2.
- [ ] Reject `estop_clear` requests with `initiator: agent` per §7.
- [ ] Per-user scope every operation; reject cross-user state references.

A conforming implementation MAY:

- Add additional event `kind` values, prefixed with `x_` to indicate extension.
- Support pluggable audit-log storage backends beyond JSONL.
- Add additional gate or notifier adapters.
- Sign audit records with ed25519 (v0.5+).
- Provide a hub-coordinated deployment shape (§5.4) in addition to in-process.
- Publish chain heads to an external attestor (§11).
- Scan tool-call args against a consumer-supplied honeytoken set (§12).
- Tag tools with capability classes and evaluate sliding-window combination rules (§13).
- Apply per-capability rate limits (§14).
- Suspend dispatch pending operator confirmation via a two-key gate (§15).
- Run a dead-man's heartbeat monitor that presses the EStop on hard miss (§16).
- Produce offline baselines (§17) and cross-surface correlation reports (§18).

A conforming implementation MUST when shipping the optional layers above:

- Recursion-safe attestation: an `x_chain_attested` row MUST NOT re-trigger attestation.
- Zero-default-tokens for §12: the library MUST NOT ship plausible-looking default honeytokens; consumers register their own.
- Yellow-before-Red for §13: a Red rule MUST NOT be promoted from Yellow without demonstrated zero organic fires.
- Opt-in heartbeat: §16 monitor MUST be OFF by default at the runtime level.

---

## 11. External chain attestation (v0.3.0+)

The hash chain plus optional ed25519 signatures from §2.5 / §2.6 prove that the log was *consistent at write time*, but the writer's key lives on the same host as the writer. A fully-compromised runtime can sign a fabricated chain just as easily as the legitimate writer (see §8.2). External attestation closes this gap by periodically publishing the chain head to an external append-only store the local process cannot rewrite.

### 11.1 Trigger

An attestation event fires:

- After every N appended records (configurable; default 100).
- On `session_close` (configurable; default true).
- On explicit caller request (`writer.runAttestation()`).

### 11.2 Payload

The attestation payload (v=1) is a JSON object with these fields, in any order:

| Field | Type | Description |
|---|---|---|
| `v` | `'1'` | Payload schema version. |
| `agentId` | string | Mirrors `agent_id` on the head record. |
| `sessionId` | string | Mirrors `session_id` on the head record. |
| `head` | string | `sha256:<hex>` of the canonical-JSON of the head record. |
| `signature` | string \| null | Head record's `ed25519:<base64url>` signature, or `null` when signing is disabled. |
| `recordCount` | integer | Total records appended in this session through the head. |
| `ts` | string | ISO-8601 timestamp of the attestation event. |

### 11.3 Receipt

The attestor MAY return a receipt:

| Field | Type | Description |
|---|---|---|
| `receiptId` | string | Attestor-assigned identifier (URL fragment, Rekor log index, S3 version id, etc.). |
| `url` | string (optional) | Inspectable URL for the receipt. |

### 11.4 Audit events

On successful attestation, the writer MUST append `x_chain_attested`:

```jsonl
{"kind":"x_chain_attested","status":"approved","initiator":"system","detail":{"chain_head":"sha256:...","records_in_session":100,"receipt_id":"...","receipt_url":"..."}}
```

On attestor failure, the writer MUST append `x_chain_attestation_failed` and continue. Attestation failure is NEVER fatal:

```jsonl
{"kind":"x_chain_attestation_failed","status":"errored","initiator":"system","detail":{"chain_head":"sha256:...","records_in_session":100,"error":"..."}}
```

Implementations MUST guarantee that an attestation row's own write does not recursively trigger another attestation.

### 11.5 Verifier behavior

A conforming verifier with attestation support MAY:

- Fetch external receipts from the configured endpoint.
- Cross-check each `x_chain_attested` row's `chain_head` against the receipt's hash for the same `receiptId`.
- Report any divergence as a tamper indicator with the same exit-code semantics as a broken hash chain (exit 1).

---

## 12. Honeytokens (v0.3.0+)

Deterministic decoys that no legitimate tool call should ever touch. When a honeytoken appears in a tool call's args (or as a phantom tool name), the runtime fires immediately. Zero false positives by construction: a hit means an agent has been probing.

### 12.1 Honeytoken types

- **Value tokens** — fixed strings or regex patterns. Matched against the canonical-JSON of `tool.args` recursively (any depth, any key).
- **Phantom tools** — tool names that are never advertised. Any dispatch to that name fires immediately, regardless of args.

### 12.2 Honeytoken set shape

A consumer-supplied object:

```ts
{
  id: string,                          // stable identifier for the set
  description?: string,
  tokens: Array<{
    id: string,                        // recorded in audit
    description?: string,
    value?: string,                    // mutually exclusive with pattern
    pattern?: RegExp                   // mutually exclusive with value
  }>,
  phantomTools?: string[]
}
```

The library SHIPS NO DEFAULT TOKENS. A library shipping plausible-looking fake credentials gets picked up by secret scanners and creates support load. Consumers register their own.

### 12.3 Hit behavior

On any hit, the runtime MUST:

1. Append `x_honeytoken_triggered` with status `halted` and detail describing the hit kind + token id (or tool name for phantom-tool hits):

```jsonl
{"kind":"x_honeytoken_triggered","status":"halted","initiator":"system","tool":{"name":"...","args":{...}},"detail":{"set_id":"...","hit_kind":"value_in_args|phantom_tool","token_id":"...","tool_name":"..."}}
```

2. Press the EStopLocal (if configured) with `reason: 'honeytoken:<token_id>'` or `'honeytoken:phantom_tool:<tool_name>'`.

3. Throw a halt error to the caller. The dispatched function MUST NOT run.

Phantom-tool match wins over value-in-args match when both would fire.

---

## 13. Capability tagging + tripwires (v0.3.0+)

Every tool is tagged with one or more capability classes. The runtime maintains a per-session sliding window of recent tool calls + their capability sets. Rule sets describe suspicious combinations; when a combination is observed within `window_ms`, the rule fires.

### 13.1 Canonical capability classes

The canonical set, extensible by consumers:

| Class | Meaning |
|---|---|
| `read` | Pure read of agent-accessible data. |
| `write` | Local write of agent-accessible data. |
| `delete` | Destruction of agent-accessible data. |
| `execute` | Run a subprocess or arbitrary code. |
| `network-egress` | Outbound network call. |
| `network-ingress` | Accept inbound network call. |
| `credential` | Read or write credentials. |
| `system-path` | Touch OS-level paths (`/etc`, `~/.ssh`, etc.). |
| `bulk` | Operation over many items. |
| `unknown` | Fallback for untagged tools. Excluded from rule combinations unless a rule explicitly names `'unknown'`. |

Consumers MAY register additional class strings.

### 13.2 Rule shape

```json
{
  "id": "exfil",
  "description": "credential + outbound + write within 1 min",
  "combination": ["credential", "network-egress", "write"],
  "window_ms": 60000,
  "level": "yellow"
}
```

A rule matches when every class in `combination` has been observed within the last `window_ms`. A single tool tagged with multiple classes may satisfy several required slots at once.

### 13.3 Yellow vs Red

- `level: 'yellow'` (v0.3.0+) — append `x_capability_yellow`. **No dispatch behavior change.** Yellow exists to collect telemetry.
- `level: 'red'` (v0.5.0+) — append `x_capability_redline` AND press the EStop. Red rules MUST NOT be deployed until corresponding Yellow telemetry has produced zero organic fires over a sustained window.

### 13.4 Wire shape

```jsonl
{"kind":"x_capability_yellow","status":"approved","initiator":"system","tool":{"name":"...","args":{...}},"detail":{"rule_id":"...","combination":[...],"window_ms":N,"contributing_event_ids":[...],"tool_capabilities":[...]}}
{"kind":"x_capability_redline","status":"approved","initiator":"system","tool":{"name":"...","args":{...}},"detail":{"rule_id":"...","combination":[...],"window_ms":N,"contributing_event_ids":[...],"tool_capabilities":[...]}}
```

### 13.5 Window semantics

The window slides forward at every event. Events older than the longest rule's `window_ms` are dropped. An implementation MUST cap the window's memory footprint (default: 10000 events per session) to defend against runaway agents.

Contributing event ids for a fire are returned in chronological order, deduped (a multi-class event that satisfies multiple slots appears once).

---

## 14. Per-capability rate limits (v0.3.0+)

Token-bucket rate limiting keyed by capability class. A normal-workload session sees zero impact; exfil-shaped bursts hit the narrow buckets long before they hit the global rate.

### 14.1 Default buckets

| Class | Calls per second (default) |
|---|---|
| `read` | 50 |
| `write` | 10 |
| `delete` | 1 |
| `execute` | 5 |
| `network-egress` | 5 |
| `network-ingress` | 50 |
| `credential` | 2 |
| `system-path` | 1 |
| `bulk` | 2 |

Implementations MUST allow per-class overrides. Untagged tools (`unknown`) fall through to a configurable default bucket (typical: the previous-implementation global rate; default 50/s).

### 14.2 Multi-class dispatch

A tool tagged with multiple classes consumes one token from EVERY relevant bucket. First denial wins; earlier-class tokens already consumed in the same call are NOT refunded (errs on the side of slowing the caller).

### 14.3 Breach audit

On a breach, the runtime MUST append `x_rate_limit_breached` once per burst (suppress duplicate breach rows until a subsequent call succeeds):

```jsonl
{"kind":"x_rate_limit_breached","status":"denied","initiator":"system","detail":{"tool":"...","class":"credential","retry_after_ms":N}}
```

---

## 15. Two-key operator authorization (v0.4.0+)

For tool dispatches that require fresh operator confirmation before proceeding (analogous to `sudo` for AI agents, or the Hub `password.confirm` gate for `panic_clear`), the runtime suspends the call, writes a `policy_check { status: pending_operator }` audit row with a unique `gate_id`, and calls the configured operator gate. Approved → proceed; denied → throw. Timeout is treated as denied (fail-closed).

### 15.1 Audit record status `pending_operator`

§2.2 is extended with a new `status` value: `pending_operator`. Implementations MUST accept this status when reading; writers SHOULD only emit it on `policy_check` records issued by the two-key flow.

### 15.2 Request payload

The runtime calls the gate with:

```ts
{
  gate_id: string,                     // "gt_<ulid>"
  tool_name: string,
  tool_args: Record<string, unknown>,  // CALLER REDACTED, matches audit
  reason: string,                      // free-text (rule_id, capability name, etc.)
  timeout_ms: number,
  agent_id: string,
  session_id: string
}
```

### 15.3 Response

```ts
{
  decision: 'approved' | 'denied',
  operator_id?: string,                // recorded in audit
  reason?: string                      // recorded in audit; 'timeout' on synthesized timeout response
}
```

### 15.4 Wire shape

```jsonl
{"kind":"policy_check","status":"pending_operator","initiator":"system","tool":{"name":"...","args":{...}},"detail":{"gate_id":"gt_...","timeout_ms":N,"reason":"..."}}
{"kind":"policy_check","status":"approved","initiator":"operator","tool":{"name":"...","args":{...}},"detail":{"gate_id":"gt_...","operator_id":"...","reason":"..."}}
{"kind":"policy_check","status":"denied","initiator":"operator","tool":{"name":"...","args":{...}},"detail":{"gate_id":"gt_...","reason":"timeout|operator_denied|..."}}
```

The pending row and the resolution row MUST share the same `gate_id`.

### 15.5 Timeout

Library-defined default: 5 minutes. Implementations MUST allow per-call and runtime-level overrides. On timeout, the library synthesizes a `{ decision: 'denied', reason: 'timeout' }` response and writes the denied audit row.

### 15.6 Transport

The library defines the suspend/resume contract. Consumers wire the actual transport — HTTP webhook, IPC frame to a UI process, LiveKit data channel, Hub-side `password.confirm` endpoint. Library-shipped reference adapters:

- `callbackOperatorGate(fn)` — wraps a plain async callback.
- `denyAllOperatorGate(reason)` — defensive fallback for CI / no-operator environments.

---

## 16. Dead-man's heartbeat (v0.4.0+)

For long-running surfaces, the consumer (or its harness) must call `heartbeat()` every N seconds. Missed heartbeats trigger graduated responses.

### 16.1 Configuration

```ts
{
  softMs: number,                      // soft window
  hardMs: number,                      // hard window (> softMs)
  checkIntervalMs?: number             // default = clamp(softMs/4, 50, 5000)
}
```

Implementations MUST reject `softMs <= 0` and `hardMs <= softMs` at construction.

### 16.2 State machine

`idle → softMissed → hardMissed`. Heartbeat resets to `idle` from `softMissed`. `hardMissed` is terminal — `heartbeat()` does NOT recover. Recovery requires constructing a new monitor (new session).

### 16.3 Behavior on miss

**Soft miss:** append `x_heartbeat_warning` with `status: approved` and `detail.level: 'soft'`. No EStop press. Dispatch continues.

**Hard miss:** append `x_heartbeat_warning` with `status: halted` and `detail.level: 'hard'`, then press the EStop with `reason: 'heartbeat_missed'`. Stop monitoring (session is halted).

### 16.4 Opt-in requirement

Heartbeat MUST be OFF by default at the runtime level. A surface that does not wire `heartbeat()` into its main loop MUST NOT enable it — that's a guaranteed day-1 false E-stop.

---

## 17. Behavioral baselines (offline, v0.5.0+)

Descriptive statistics on audit-record streams, produced and consumed by the offline `guardian-baseline` CLI. **The supervisor MUST NOT consult baselines in the hot path.** Baselines are reports for operator review, not runtime tripwires.

### 17.1 Profile shape

Per `agent_id`, version `v=1`:

```ts
{
  agent_id: string,
  v: '1',
  session_count: number,
  total_records: number,
  tool_call_count: number,
  avg_session_length_events: number,
  stddev_session_length_events: number,
  avg_session_duration_ms: number,
  stddev_session_duration_ms: number,
  tool_frequency: Record<string, number>,
  hour_of_day: number[24],             // counts per UTC hour
  kind_frequency: Record<string, number>,
  status_frequency: Record<string, number>,
  first_ts: string | null,
  last_ts: string | null,
  generated_at: string
}
```

### 17.2 Storage

`~/.flowdot/audit/baselines/<agent_id>.json` (configurable via `FLOWDOT_BASELINES_DIR`). Mode `0o600`. Filename derived from `agent_id` with shell-unsafe characters replaced by `_`.

### 17.3 Deviation reporting

`compareToBaseline(candidate, baseline, { sigmaThreshold, minBaselineSessions })` returns a list of metrics that deviated above `sigmaThreshold` σ (default 3). When the baseline σ is 0 (degenerate), any non-equal observation is reported with `sigma: null`. Tools present in candidate but absent in baseline are flagged.

The deviation report is descriptive output. **No audit row is written.** The operator decides what to do.

---

## 18. Cross-surface correlation (offline, v0.5.0+)

The offline `guardian-correlator` CLI reads audit logs from multiple sources for the same `agent_id` and reports patterns that span surfaces:

### 18.1 Match types

| Match type | Predicate |
|---|---|
| `overlapping_sessions` | Two sessions, different surfaces, same agent_id, with intersecting time windows. |
| `args_hash_collision` | Identical canonical-JSON SHA256 of `tool.args` for the same `tool_name` on two different surfaces within `argsHashWindowMs` (default 60s). |
| `sequence_similarity` | Cosine similarity of per-session tool-frequency vectors ≥ threshold (default 0.9) AND start times within `similarityWindowMs` (default 10 min) AND each session has ≥ `similarityMinCalls` tool calls (default 5). |

### 18.2 Output

Findings are written as JSONL rows with `kind: 'x_cross_surface_match'` to a separate log (default `~/.flowdot/audit/correlations.jsonl`). The correlator MUST NOT mutate source audit files.

```jsonl
{"ts":"...","kind":"x_cross_surface_match","agent_id":"...","match_type":"overlapping_sessions|args_hash_collision|sequence_similarity","surfaces":["cli","mcp"],"session_ids":["...","..."],"detail":{...}}
```

### 18.3 Operator workflow

Correlation reports are read by hand or piped into the operator's review tooling. The matcher does not signal back into runtimes; if a correlation justifies a halt, the operator presses PANIC.

---

## Open questions (rolling)

1. **Distributed audit logs** — how do multiple runtime instances coordinate a single hash chain? Likely answer: per-instance chains plus a coordinator that joins them.
2. **Argument redaction** — schema-driven `*_hash` placeholders for PII fields (currently pattern-based per surface).
3. **Red-line auto-stop calibration** — formal criteria for promoting a Yellow rule to Red. Current rule of thumb: zero organic fires in negative corpus + ≥ one surface release with zero Yellow fires for that combination.

**Resolved in v0.3+:**
- ~~Replay verification CLI~~ → `guardian-verify` shipped.
- ~~Model-aware policy rules~~ → `PolicyWhen.attribution_path` + glob matcher shipped (v0.7).

---

*Specification © 2026 FlowDot LLC. AGPL-3.0-or-later. Spec text additionally licensed CC BY-SA 4.0.*
