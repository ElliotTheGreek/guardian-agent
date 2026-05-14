# guardian-agent

> A runtime supervisor for tool-using LLM agents. Audit log, tool-permission scoping, human-in-the-loop approval gates, and an emergency-stop primitive — as a small, dependency-light Python library that wraps any agent's tool-call loop.

**Status**: pre-alpha · spec v0.1.0 · interface unstable · not yet on PyPI

---

## The problem

Production LLM agents call tools. The tools touch real systems — brokerage accounts, EHR records, defense data pipelines, payment APIs. As agents move from chat assistants into healthcare, finance, and defense pilots, the layer that supervises those tool calls — *what's allowed, what's logged, what can be stopped mid-execution* — remains ad-hoc, closed-source, and unverified.

There is no public reference implementation a regulated-industry deployer or evaluator can pick up. Each team builds the same four primitives from scratch, badly. Each evaluator has to read source code to know whether the supervisor is real or theater.

`guardian-agent` is the missing reference implementation: four primitives, one small library, one public spec.

## The four primitives

1. **Audit log** — every tool call gets a structured, append-only record. Hash-chained for tamper evidence; optionally signed with ed25519. Persistable to JSONL today, pluggable backends in v0.2+.
2. **Tool-permission scoping** — a YAML policy declares which tools are allowed, denied, session-only, or always-allow. Wildcards and groups supported. Enforced at every call site.
3. **HITL approval gate** — a configurable hook pauses the agent before a tool fires and surfaces an approval prompt to a human operator. Synchronous (CLI blocking prompt), async (callback URL), or programmatic (your UI handles it).
4. **Emergency-stop** — a process-wide kill switch. Triggered by signal, API call, or external callback. Halts the agent mid-loop, flushes the audit log, raises `GuardianHalted`.

Nothing else.

## Quickstart

```python
from guardian_agent import GuardianRuntime, Policy, cli_approval_gate

runtime = GuardianRuntime(
    audit_log="./audit.jsonl",
    policy=Policy.from_yaml("./permissions.yaml"),
    approval_gate=cli_approval_gate,   # or: async callback, or your UI handler
)

# Wrap any tool function — LangChain, MCP, AutoGen, native Python:
@runtime.tool
def list_brokerage_accounts(broker: str):
    ...

@runtime.tool
def get_positions(account_id: str):
    ...

# Your agent code calls these as normal. The runtime intercepts every call,
# checks the policy, optionally requests approval, runs the tool, writes the
# audit event. From inside the agent loop, nothing changes.

# Hit the kill switch from anywhere — another thread, a signal, an HTTP endpoint:
runtime.estop(reason="operator manual halt", operator_id="elliot@flowdot.ai")
```

A minimal `permissions.yaml`:

```yaml
version: "0.1"
agent_id: "agent_demo"
defaults:
  mode: gate           # gate | allow | deny
  scope: session       # session | permanent

permissions:
  - tool: "list_brokerage_accounts"
    mode: gate
  - tool: "get_positions"
    mode: gate
  - tool: "filesystem.read"
    mode: allow
    scope: permanent
  - tool: "filesystem.write"
    mode: deny
```

See [`examples/quickstart.py`](./examples/quickstart.py) for a runnable version.

## What guardian-agent is NOT

It is deliberately small. To stay useful, it does not become any of:

- **An agent harness** — no chat surface, no model routing, no toolkit ecosystem. Bring your own agent (Claude, GPT, Ollama, LangChain, AutoGen, MCP client, whatever).
- **A platform** — no hub, no accounts, no multi-tenancy, no billing, no managed deployment.
- **A workflow builder** — no node graph, no recipes, no connections.
- **An observability dashboard** — no web UI. The audit log is structured JSONL; render it however you want.
- **A model evaluation suite** — the companion [`guardian-eval`](./docs/eval-companion.md) package (coming v0.4) will measure gate-bypass surface and audit-log completeness. `guardian-agent` itself only enforces.

If you want any of the above, the upstream project — [FlowDot](https://flowdot.ai) — provides them. `guardian-agent` is the supervisor primitive that FlowDot is built on top of; FlowDot is the operated, hosted, multi-surface platform that depends on these primitives. Either can be used without the other.

## How users adopt it

- **Lab / research team running an eval** — wrap your model's tool functions with `@runtime.tool`, point at a permission policy that denies everything, run the agent against your prompts, read the audit log to see what it tried to call. Use the structured log as evidence in a paper or red-team report.
- **Open-source agent project** — drop the runtime into your existing tool-call loop to give downstream users an off-the-shelf audit log and approval gate. Adds a few lines of glue; no architectural change.
- **Regulated-industry deployer** — adopt the audit-log format and HITL gate semantics as part of your internal compliance evidence. Pair with your SIEM or audit system on the backend.
- **Standards/policy work** — cite the [SPEC](./SPEC.md) when proposing what a runtime supervisor should do. The spec is intentionally implementation-light and venue-neutral.

## How it contributes

`guardian-agent` exists to make three things possible that are currently impossible without rebuilding from scratch:

1. **A shared spec for what "supervisor layer" means.** Right now every closed product claims it has one. There's no way to compare them, no way to evaluate them, no way for a regulator to point at "the standard."
2. **A reference implementation that a third party can adopt without depending on a private vendor.** Trust infrastructure that ships only inside a proprietary platform is not trust infrastructure; it's vendor lock-in.
3. **An eval substrate** — the companion eval harness (coming v0.4) measures gate-bypass surface, audit-log completeness, blast radius on tool misuse. Any agent wrapped with this runtime can be measured against any other.

## Why open source — and why AGPL

The primitives are most useful when they can be audited, adopted, and composed by anyone. AGPL-3.0 keeps them open while preventing a closed-source provider from quietly re-hosting the supervisor without contributing changes back.

For organizations that need a non-copyleft license for internal use, **commercial licensing is available** — contact `licensing@flowdot.ai`. The MongoDB / Sentry / Sourcegraph dual-license pattern.

## Project status & roadmap

This repo is currently a spec-first stub. The order of work:

- **v0.1.0** *(now)* — SPEC + audit-log record format + minimal Python reference impl of audit log only. No signatures yet.
- **v0.2.0** — Tool-permission scoping (policy YAML, wildcard matching, enforcement).
- **v0.3.0** — HITL approval gate (sync CLI, async callback, programmatic).
- **v0.4.0** — Emergency-stop primitive (signal handlers, API, halt semantics). `guardian-eval` companion package.
- **v0.5.0** — Hash-chained + ed25519-signed audit logs. Replay verification CLI.
- **v1.0.0** — Stable API; pluggable storage backends; first public red-team study published.

Full plan: [ROADMAP.md](./ROADMAP.md).

## Funding & affiliation

`guardian-agent` is funded as a public-goods deliverable. FlowDot LLC (NY, founded 2025) is the upstream maintainer of the codebase and operates the commercial FlowDot platform that depends on these primitives. The spec, reference implementation, and eval harness are released open-source independently of the FlowDot product.

Grant support is being sought from:
- [Foresight Institute AI for Science & Safety Nodes](https://foresight.org/grants/grants-ai-for-science-safety/)
- [Manifund AI Safety Regranting](https://manifund.org/about/regranting)
- NSF SBIR Phase I (AI7 Trustworthy AI track)

If you're a regrantor or program officer evaluating fit, the [SPEC](./SPEC.md) and [ROADMAP](./ROADMAP.md) are the load-bearing documents.

## Contributing

Pre-alpha. Open an issue before sending a PR larger than a typo fix; the API surface is still moving. CONTRIBUTING.md will land with v0.2.0.

## License

AGPL-3.0-or-later. See [LICENSE](./LICENSE).

Commercial license: `licensing@flowdot.ai`.

## Citation

If you use `guardian-agent` in research, please cite:

```
Mousseau, E. (2026). guardian-agent: A runtime supervisor for tool-using LLM
agents. v0.1.0. https://github.com/flowdot/guardian-agent
```

---

*Lineage note: the primitives draw directly on Mark S. Miller's object-capability security work (KeyKOS, the E language, agoric computing). guardian-agent extends capability-style runtime controls from OS process boundaries to LLM tool-call boundaries.*
