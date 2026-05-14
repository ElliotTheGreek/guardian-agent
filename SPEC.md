# guardian-agent specification

**Version**: 0.1.0
**Status**: draft · interface unstable
**Last updated**: 2026-05-13

This document specifies the wire formats, file formats, and runtime semantics of the four `guardian-agent` primitives. It is implementation-language-neutral; the reference implementation is Python, but conforming implementations in other languages are welcome.

A "conforming implementation" is one that produces audit-log records readable by the reference implementation, accepts policy files in the format below, and exposes the four primitives with the semantics described.

---

## 1. Scope

This spec is **language-neutral**. The reference implementation in the [`flowdot-llc/guardian-agent`](https://github.com/flowdot-llc/guardian-agent) repository is written in Python; a TypeScript reference companion is being developed in [`flowdot-llc/guardian-agent-ts`](https://github.com/flowdot-llc/guardian-agent-ts). FlowDot's commercial platform runs an independent TypeScript implementation that also conforms to this spec. Implementations in additional languages are welcome.

What two implementations conform to the same spec means in practice: an audit-log file produced by one can be read and verified by another; a `permissions.yaml` written for one is honored by another; a gate callback URL hosted by one can be invoked by another; an `estop` triggered in one produces an audit event identical in structure to one triggered in another.

This spec defines:
- §2 — Audit log record format (JSONL on disk; JSON over the wire)
- §3 — Tool-permission policy file format (YAML)
- §4 — HITL approval gate protocol
- §5 — Emergency-stop primitive semantics
- §6 — Versioning and compatibility rules

It does NOT define:
- How agents call tools (use any framework: LangChain, AutoGen, MCP, native)
- How models are routed or selected
- How to render the audit log (any JSONL reader works)
- How to operate the supervisor in production (deployment, multi-tenancy, billing — those are platform concerns)
- Which programming language an implementation uses

---

## 2. Audit log records

### 2.1 Storage

The default storage is **JSON Lines** (JSONL): one JSON object per line, UTF-8 encoded, LF-terminated. Append-only. Records are written in event-occurrence order; readers MUST NOT assume strict chronological order across distributed writers (use the `ts` field plus `event_id` for ordering).

### 2.2 Record schema

Every record is a JSON object with the following structure:

```json
{
  "v": "0.1.0",
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
  "prev_hash": "sha256:9f8c2a...",
  "signature": null
}
```

### 2.3 Field reference

| Field | Type | Required | Description |
|---|---|---|---|
| `v` | string | yes | Spec version this record conforms to (semver). |
| `event_id` | string | yes | Globally unique identifier. ULID recommended (sortable, fixed-width). |
| `ts` | string | yes | ISO-8601 timestamp with millisecond precision, UTC, `Z`-suffixed. |
| `agent_id` | string | yes | Stable identifier for the agent instance. |
| `session_id` | string | yes | Identifier for the agent's current logical session. |
| `kind` | enum | yes | One of: `tool_call`, `tool_result`, `gate_request`, `gate_response`, `policy_check`, `estop`, `session_open`, `session_close`. |
| `tool` | object | conditional | Required when `kind` is `tool_call`, `tool_result`, `gate_request`, `gate_response`, or `policy_check`. |
| `tool.name` | string | conditional | Fully-qualified tool name. Format: `<namespace>.<function>` or bare `<function>`. |
| `tool.args` | object | conditional | Arguments passed to the tool. Object, never string. |
| `tool.result` | any | conditional | Populated only on `tool_result` events. May be `null` for void tools. |
| `tool.duration_ms` | number | conditional | Wall-clock duration of the tool execution, populated on `tool_result`. |
| `model` | object | conditional | Populated for `tool_call` if known. Identifies which model issued the call. |
| `model.provider` | string | conditional | Lowercase provider name. Examples: `anthropic`, `openai`, `ollama`, `local`. |
| `model.id` | string | conditional | Provider-specific model identifier. |
| `model.input_tokens` | number | optional | Token count for the model's input that produced this call. |
| `model.output_tokens` | number | optional | Token count for the model's output that issued this call. |
| `status` | enum | yes | One of: `pending`, `approved`, `denied`, `executed`, `errored`, `halted`. |
| `prev_hash` | string | yes | `sha256:<hex>` over the previous record's full JSON bytes; `sha256:0` for the first record. Hash chain. |
| `signature` | string | optional | ed25519 signature over the record bytes with `signature` field cleared. Format: `ed25519:<base64url>`. v0.5+. |

### 2.4 Event sequence

For a typical approved tool call, the sequence is four events:

1. `tool_call` (`status: pending`) — agent issued the call
2. `gate_request` (`status: pending`) — gate asked the operator
3. `gate_response` (`status: approved`) — operator allowed
4. `tool_result` (`status: executed`) — tool ran, result captured

For a denied call, the sequence is three events:

1. `tool_call` (`status: pending`)
2. `gate_request` (`status: pending`)
3. `gate_response` (`status: denied`) — no execution event follows

For a policy-blocked call (no gate involved):

1. `tool_call` (`status: pending`)
2. `policy_check` (`status: denied`) — terminal

For an emergency-stop:

1. ... (any in-flight events)
2. `estop` (`status: halted`) — terminal for the session

### 2.5 Hash chain

`prev_hash` is computed over the previous record's complete JSON bytes (including its `prev_hash` field, excluding its trailing newline). The first record in a log file has `"prev_hash": "sha256:0"`.

A reader can verify log integrity by recomputing the chain. A break in the chain indicates tampering, truncation, or out-of-order writes.

### 2.6 Signatures (v0.5+)

Optional. When present, `signature` is an ed25519 signature over the record bytes with the `signature` field set to `null`. Public keys are distributed out-of-band; key rotation and revocation are out of scope for v0.x.

---

## 3. Tool-permission policy

### 3.1 File format

YAML. One policy file per agent or per agent class. Loaded at runtime startup; reloadable on SIGHUP in the reference implementation.

```yaml
version: "0.1"
agent_id: "agent_demo"

defaults:
  mode: gate           # gate | allow | deny
  scope: session       # session | permanent

permissions:
  - tool: "schwab_trading.*"
    mode: gate
    scope: session
  - tool: "filesystem.read"
    mode: allow
    scope: permanent
  - tool: "filesystem.write"
    mode: deny
  - tool: "network.http_post"
    mode: gate
    scope: permanent
    notes: "External writes require explicit approval each session."
```

### 3.2 Modes

- `allow` — tool call proceeds without consulting the gate.
- `deny` — tool call is rejected; a `policy_check` event with `status: denied` is logged; no `tool_result` is generated.
- `gate` — tool call is suspended; a `gate_request` event is emitted; the configured approval gate is invoked; the gate's response determines whether the call proceeds.

### 3.3 Scopes

- `session` — applies only within the current session (defined by `session_id` in the audit log).
- `permanent` — applies across sessions. Persisted between runtime restarts via the policy file.

### 3.4 Matching rules

Tool names are matched using shell-style wildcards (`fnmatch`). Specificity wins: an exact match overrides a wildcard match. If multiple wildcard patterns match, the first listed in the file wins.

The `defaults` block applies to any tool not matched by a rule in `permissions`.

### 3.5 Reserved tool names

The following tool-name prefixes are reserved for runtime use and MUST NOT appear in policy files: `guardian.`, `runtime.`, `internal.`.

---

## 4. HITL approval gate

### 4.1 Interface

An approval gate is any callable conforming to the following signature:

```python
def approval_gate(request: GateRequest) -> GateResponse: ...
```

Where:

```python
@dataclass
class GateRequest:
    event_id: str          # event_id of the originating tool_call
    tool_name: str
    tool_args: dict
    agent_id: str
    session_id: str
    model: Optional[ModelAttribution]
    context: Optional[str] # natural-language summary the agent provides

@dataclass
class GateResponse:
    decision: Literal["allow", "allow_session", "always_allow", "deny"]
    reason: Optional[str]
    operator_id: Optional[str]
```

### 4.2 Decision semantics

- `allow` — this specific call proceeds. The next call to the same tool re-prompts.
- `allow_session` — this and all subsequent calls to the same tool within the current session proceed without prompting. Equivalent to upgrading the in-memory policy to `mode: allow, scope: session`.
- `always_allow` — this and all subsequent calls to the same tool, across sessions, proceed without prompting. The policy file is updated; the change is persisted.
- `deny` — this call does not proceed; no policy change.

### 4.3 Reference gate implementations

The reference implementation ships three approval-gate adapters:

- `cli_approval_gate` — synchronous, blocking stdin prompt. Suitable for local development.
- `async_callback_gate(url)` — POSTs the `GateRequest` to a callback URL, awaits a JSON response. Suitable for production deployments where a separate UI handles operator approval.
- `programmatic_gate(handler)` — calls a Python handler. Suitable when the host application has its own UI.

### 4.4 Operator identification

`operator_id` is opaque to the runtime. It is recorded in the audit log for attribution. The runtime does not authenticate operators; that is the responsibility of the gate implementation.

---

## 5. Emergency-stop

### 5.1 Triggers

The emergency-stop primitive can be triggered by:

1. **In-process call**: `runtime.estop(reason: str, operator_id: Optional[str] = None)`.
2. **POSIX signal**: `SIGUSR1` is reserved for emergency-stop in the reference implementation. Custom signal handlers may be installed.
3. **Programmatic from another thread**: the runtime exposes an `estop_event` (`threading.Event`) that any thread may set.

### 5.2 Semantics

When triggered:

1. The runtime sets an internal halt flag.
2. Any tool call currently being executed is allowed to complete (no forced thread termination — the runtime does not interrupt user code mid-syscall).
3. Any pending `gate_request` is auto-resolved with `decision: deny`, `reason: "halt"`.
4. The next attempt to wrap or call a tool raises `GuardianHalted` from the runtime.
5. An `estop` event is written to the audit log with `status: halted`.
6. The audit log is flushed.

The runtime does not call `sys.exit`. Halt semantics are scoped to the runtime; the host process decides how to react.

### 5.3 Recovery

A halted runtime is terminal. To resume operation, a new `GuardianRuntime` instance must be constructed (which begins a new session).

---

## 6. Versioning and compatibility

This spec follows semantic versioning:

- **MAJOR** version bumps when the wire format changes incompatibly.
- **MINOR** version bumps when fields are added in a backward-compatible way.
- **PATCH** version bumps for spec clarifications that do not change behavior.

The reference implementation pins to a major spec version. Readers MUST accept records with patch/minor version differences from their own; readers SHOULD reject records with a higher major version.

The `v` field in every audit record is the spec version that the writer claims to conform to.

---

## 7. Threat model

`guardian-agent` defends against:

- **Unintended tool invocation by the agent** — the agent calls a tool the operator did not authorize.
- **Tool call drift** — a sequence of approved calls leading to an outcome the operator would not have approved holistically (mitigated, not solved — see roadmap).
- **Post-incident reconstruction** — what did the agent do? When? With what arguments? Against which model? The hash-chained audit log answers these.

It does NOT defend against:

- **A compromised runtime** — if the runtime process is fully compromised, the supervisor is too. Defense-in-depth assumes the runtime is trusted.
- **A compromised model** — if the model issues malicious tool calls, the supervisor catches them at the gate (if configured) but cannot detect malice from output content alone.
- **Prompt injection of the agent** — handled by composition with prompt-injection defenses (e.g., Tripwire) at a lower layer.
- **Side-channel data exfiltration** — out of scope.

The threat model assumes:

- The host process and the runtime are trusted.
- The audit log destination is append-only and access-controlled by the host system.
- The policy file is integrity-protected by the host system (e.g., readonly mount, signed deploy).

---

## 8. Conformance checklist

A conforming implementation MUST:

- Emit JSONL records matching §2.2 with all required fields present.
- Maintain the hash chain per §2.5.
- Honor the four `mode` values per §3.2.
- Implement the gate protocol per §4.1 with the four decision semantics per §4.2.
- Provide an emergency-stop primitive per §5 that produces the documented event sequence.

A conforming implementation MAY:

- Add additional event `kind` values, prefixed with `x_` to indicate extension.
- Support pluggable storage backends beyond JSONL.
- Add additional gate implementations.
- Sign audit records (v0.5+).

---

## Open questions for v0.2+

These are intentionally unspecified in v0.1.0 and will be settled as the implementation matures:

1. **Distributed audit logs** — how do multiple runtime instances coordinate a single hash chain? Likely answer: per-instance chains plus a coordinator that joins them.
2. **Argument redaction** — how should sensitive arguments (PII, credentials) be redacted in audit records while preserving auditability? Likely answer: schema-driven redaction with a `*_hash` placeholder.
3. **Replay verification CLI** — what's the canonical tool for verifying a log file's integrity? Likely answer: `guardian-verify <file.jsonl>`.
4. **Policy composition** — can multiple policy files be merged? With what precedence rules?

Comments and issues welcome.

---

*This specification is © 2026 FlowDot LLC, released under AGPL-3.0-or-later. The spec text itself is also released under CC BY-SA 4.0 to encourage citation and adaptation in research and policy work.*
