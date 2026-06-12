# tollbooth Gateway — Design Rationale

Date: 2026-06-11. Output of the initial brainstorm (input: `agent-gateway-handoff.md`). SPEC.md holds the requirements; this doc records the WHY behind the decisions and the alternatives rejected.

## Prior Art Survey

Studied before designing, per the handoff ("differentiate, don't duplicate"):

| Project | Approach | Why tollbooth is different |
|---|---|---|
| [Lasso mcp-gateway](https://github.com/lasso-security/mcp-gateway) (Python) | Plugin guardrails: secret masking, Presidio PII, SQLite tracing; reads existing `mcp.json` | Masking-focused; custom policy + injection detection paywalled behind Lasso's API. No declarative allow/deny/approval engine, no fail-closed posture |
| [Invariant mcp-scan](https://invariantlabs.ai/blog/introducing-mcp-scan) (now Snyk) | Static scanner + proxy mode with YAML guardrails (PII/secrets/tool restrictions) | Closest overlap. Proxy is *temporarily injected* (rewrites client config, restores on exit); research lineage is injection/tool-poisoning; now a corporate asset. Audit is logging, not compliance-mapped |
| [eqtylab mcp-guardian](https://github.com/eqtylab/mcp-guardian) (Rust) | GUI for real-time human approval of tool calls | Human-in-the-loop GUI, not a declarative policy/DLP engine |

**Defensible lane:** practitioner-grade egress DLP (PAN/Luhn, real secret patterns), compliance-mapped audit (SOC 2), fail-closed by default, and a *permanent declared gateway* — one config file that IS the security boundary, not an injected wrapper.

UX borrowed from Lasso: bootstrap `tollbooth.yaml` by importing an existing client `mcp.json` (S2).

## Decisions and Rejected Alternatives

The full decision log lives in SPEC.md → Key Decisions. Summary of the brainstorm-resolved items (the handoff's ⚠️ marks):

1. **v1 scope = M1 + M2** (proxy+policy, then DLP), built as two sequential milestones, released together. A policy-only proxy is undifferentiated; DLP is the differentiator; but DLP can't be built before traffic flows.
2. **Topology: one aggregating gateway**, tools always namespaced `{server}_{tool}`. Rejected per-server wrappers (process/config sprawl) and collision-only prefixing (adding an upstream can silently rename tools and re-aim policy rules — predictability beats transparency here). Routing uses a namespaced-name → (server, tool) mapping table because server names may themselves contain underscores; string-splitting is a correctness bug waiting to happen.
3. **Policy argument matching: structured field matchers** (`where:` with `equals`/`regex`/`prefix`/`not_prefix`). Rejected a CEL-style expression language for v1 (interpreter dependency; configs become code; can be added later as one more operator) and regex-over-serialized-args (serialization-order brittleness; cannot express path containment).
4. **DLP defaults are direction-aware**: requests block (egress is the true exfil path; redacting args silently corrupts calls), results redact (`[REDACTED:{pattern-id}]` keeps agents usable on real codebases — a control that forces users to disable it protects nothing). Per-pattern overrides.
5. **Approval = deny-with-approvable-message.** Client-agnostic, zero protocol dependency, fail-closed-aligned. MCP elicitation rejected for v1 (uneven client support must not gate core safety); approval TUI deferred. `Decision` is an extensible enum so these slot in later.
6. **stdio-only upstream transport** behind an `UpstreamTransport` interface; streamable HTTP (N1) drops in later without touching the proxy/policy core.
7. **Official `mcp` SDK over fastmcp's `as_proxy`**: the interception points are the product; owning the message pump keeps control of them. Python over TypeScript for stack fit (maintainer's DLP/security tooling is Python).
8. **Fail-closed everywhere**, including "a result that can't be redacted is blocked." Fail-open is explicit opt-in only.

## Pipeline as the Extensibility Seam

Policy and DLP are both implemented as interceptors on an ordered chain (request path and result path). This is deliberate: M4's "pluggable detector interface" is not new architecture — it's formalizing the interface the first two interceptors already use. Prompt-injection detectors, rate limiters, and the Claude Code adapter all attach at the same seam.

## Lessons Applied (from `~/.claude/lessons/cross-cutting.md`)

- **Pattern 1 (overlap specificity):** DLP must suppress generic matches inside regions claimed by specific patterns — spec'd as an R6 scenario.
- **Pattern 2 (false positives):** Luhn validation on PAN; test corpus of Luhn-invalid numbers, UUIDs-that-look-like-keys, benign paths matching deny patterns.
- **Pattern 6 (fail-fast):** config validation at startup; crashing interceptor ⇒ deny; no silent pass-through anywhere.
- **Pattern 8 (concurrency):** concurrent tool calls through one gateway tested for cross-call state corruption.
- **Pattern 9 (source vs installed):** `pythonpath = ["."]` in pyproject from day one; reinstall before CLI smoke tests.
