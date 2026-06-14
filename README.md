<p align="center">
  <img src="https://raw.githubusercontent.com/Realgagenichols/tollbooth/main/assets/header.svg" alt="tollbooth — a firewall + DLP + audit layer for AI agent tool traffic" width="860">
</p>

<p align="center">
  <a href="#"><img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white"></a>
  <a href="#"><img alt="Built on MCP" src="https://img.shields.io/badge/built%20on-MCP-58A6FF"></a>
  <a href="#development"><img alt="319 tests" src="https://img.shields.io/badge/tests-319%20passing-3FB950"></a>
  <a href="#design-decisions-that-matter"><img alt="Fail-closed by default" src="https://img.shields.io/badge/default-fail--closed-F85149"></a>
  <a href="https://github.com/Realgagenichols/tollbooth/blob/main/LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-8957E5"></a>
</p>

<p align="center">
  <b>tollbooth</b> sits between any MCP client and the servers it talks to, and enforces
  security policy, data-loss prevention, and a tamper-evident audit trail on
  <i>every</i> tool call and result that crosses the boundary.
</p>

---

Your AI agent's tool traffic — filesystem writes, shell exec, web fetches, API calls — flows **unmediated** today. There is no control point to deny a dangerous call, stop a secret from leaking out through a tool argument, redact a credential before it lands in the model's context, or produce a compliance-grade record of what the agent actually did.

tollbooth is that control point. It's a transparent [MCP](https://modelcontextprotocol.io) proxy: your client points at one server (tollbooth), tollbooth wraps the real upstream servers, and the gateway config file *is* the security boundary.

## Caught in the act

A single config turns an unmediated agent into a governed one. The recording below is **real `tollbooth` output** — every frame is the live policy + DLP engine answering actual Claude Code hook events (reproduce it yourself with `vhs demo/demo.tape`):

<p align="center">
  <img src="https://raw.githubusercontent.com/Realgagenichols/tollbooth/main/assets/demo.gif" alt="tollbooth denying a curl-pipe-sh shell call, blocking an AWS key from leaving in a GitHub issue, redacting credentials out of a tool result, then verifying the tamper-evident audit chain" width="860">
</p>

Requests carrying secrets are **blocked** (egress is the exfil path). Secrets in results are **redacted in place** so the agent keeps working on real codebases instead of you disabling the control. Safe calls pass straight through, untouched. Every decision is hash-chained into a log you can prove wasn't edited — and the raw secret value appears in none of it.

<details>
<summary>Prefer text? The same run, line by line.</summary>

```console
$ tollbooth hook pre  < curl-pipe-sh.json        # agent pipes a remote script to a shell
  ⛔ deny — "tollbooth: claude/Bash denied by policy rule 'no-curl-pipe-sh'."

$ tollbooth hook pre  < aws-key-to-github.json   # agent leaks an AWS key into a GitHub issue
  ⛔ deny — "github/create_issue blocked — sensitive data detected in arguments
            (aws-access-key). The flagged values were not forwarded upstream."

$ tollbooth hook post < result-with-creds.json   # a tool result comes back carrying creds
  ✏️  updatedToolOutput:
        aws_access_key_id = [REDACTED:aws-access-key]
        [REDACTED:aws-secret-key]

$ tollbooth hook pre  < safe-ls.json             # a safe call — no output, defers to Claude
  (silence)

$ grep -c AKIAIOSFODNN7EXAMPLE demo/demo-audit.jsonl
  0                                              # the raw key is nowhere in the log

$ tollbooth audit verify --log demo/demo-audit.jsonl
  ✅ OK: 4 event(s), head seq=3 hash=8d540adb…, mode=sha256 (unkeyed)
```
</details>

## What it stops

| Threat | tollbooth control |
|---|---|
| Agent coerced into `curl … \| sh`, `rm -rf`, etc. | **Policy engine** — regex/field rules deny the call before it reaches the upstream |
| Path traversal / writes escaping the project (`/etc/passwd`) | **`not_prefix` / `prefix` matchers** on argument fields |
| Secret or PAN in a tool **argument** leaving for an upstream | **DLP egress block** — the call is stopped, pattern id logged, value never |
| Credential in a tool **result** entering model context | **DLP redaction** — `[REDACTED:pattern-id]` in place, rest intact |
| Prompt injection in returned tool output | **Reference detector plugin** — `block` or `annotate` (see [limitations](#limitations)) |
| Audit log edited, truncated, or reordered to hide activity | **Hash-chained JSONL** (HMAC-keyed) — `audit verify` names the break |
| "Just turn the control off so the agent works" pressure | **Direction-aware defaults** keep agents usable; **fail-closed** on any internal error |

## How it works

```
client ──tool call──▶ tollbooth ──▶ [ policy → DLP-request → plugins ] ──▶ upstream
client ◀──result──── tollbooth ◀── [ DLP-result → plugins ] ◀──────────── upstream
                          │
                          └──▶ tamper-evident audit log (one event per decision)
```

One aggregating gateway process is an MCP **server** to your client and an MCP **client** to N upstream servers. It exposes the union of upstream tools, namespaced `{server}_{tool}`, routed through a mapping table (never string-splitting — server names can contain underscores). Absent any policy, behavior is identical to a direct connection.

## Install

```bash
pip install mcp-tollbooth        # or:  uv add mcp-tollbooth
```

Or run it without installing anything:

```bash
uvx --from mcp-tollbooth tollbooth --help
```

> The distribution is **`mcp-tollbooth`** (the name `tollbooth` was taken on PyPI); the command and the import package are both **`tollbooth`**.

## Quickstart

```bash
git clone https://github.com/Realgagenichols/tollbooth.git
cd tollbooth
uv sync

# 1. Write a gateway config (see examples/tollbooth.yaml) — or bootstrap one
#    from your existing client config:
uv run tollbooth import ~/.claude/claude_desktop_config.json   # or .mcp.json
cp examples/tollbooth.yaml tollbooth.yaml                      # ...or by hand

# 2. Check it
uv run tollbooth validate -c tollbooth.yaml

# 3. Emit the client config block and paste it into your client's MCP config
#    (.mcp.json, claude_desktop_config.json, ...)
uv run tollbooth emit-config -c tollbooth.yaml
```

Your client then talks to `tollbooth run -c tollbooth.yaml`, which proxies everything through the pipeline.

## Upstream servers

Each entry under `servers:` is classified by which field it declares — `command` for a local stdio server (a subprocess) or `url` for a remote streamable-HTTP server. An entry with neither, or both, is a config error.

```yaml
servers:
  fs:                                    # stdio: tollbooth launches the subprocess
    command: my-fs-server
    args: [--root, /data]
    env:
      LOG_LEVEL: info
  remote:                                # http: tollbooth connects to the URL
    url: https://api.example.com/mcp
    headers:
      Authorization: Bearer ${REMOTE_TOKEN}
```

HTTP header values may reference environment variables as `${VAR}`, resolved at startup — so tokens live in the environment, never in `tollbooth.yaml`. A referenced variable that is unset fails closed at startup, naming the variable (never its value). Errors about an HTTP upstream echo only the URL **origin** (`scheme://host[:port]`) — never userinfo, path, query, or header content. A dead HTTP upstream returns a clean error for *its* calls without taking the gateway down. `tollbooth import` brings both `command` and `url` entries in from an existing client config.

### OAuth for HTTP upstreams

For servers that require an interactive OAuth grant (rather than a long-lived `${VAR}` bearer token), declare an `auth` block:

```yaml
servers:
  remote:
    url: https://mcp.example.com/mcp
    auth:
      type: oauth
      scopes: [mcp:read, mcp:write]   # optional
      callback_port: 8765             # optional loopback redirect port (default 8765)
```

Authenticate once, interactively:

```bash
tollbooth auth login remote -c tollbooth.yaml   # opens a browser; stores the token
tollbooth auth status       -c tollbooth.yaml   # shows token presence/expiry (never values)
tollbooth auth logout remote                    # deletes the stored token
```

Tokens are stored under `$XDG_DATA_HOME/tollbooth/oauth/<server>.json` (default `~/.local/share/...`), file mode `0600` in a `0700` directory. When the gateway runs, a valid token is used as-is and an expired one is **refreshed silently** — no browser. If no usable token remains (and refresh fails), that upstream **fails closed** with a clear message to re-run `tollbooth auth login`; the gateway and other upstreams keep working. Access/refresh tokens are never written to logs, errors, or the audit log.

## Policy rules

```yaml
policy:
  default: deny          # decision when no rule matches (allowlist posture)
  failure_mode: closed   # internal error => block (set `open` to log-and-continue)
  rules:
    - name: block-writes-outside-project
      action: deny       # allow | deny | require-approval
      server: fs         # exact server name or "*"
      tool: write_file   # exact tool name or "*"
      where:             # ALL fields must match; matchers: equals, regex,
        path:            #   prefix, not_prefix (exactly one per field)
          not_prefix: /Users/me/project
```

Rules are evaluated top-down; the first match decides. `require-approval` blocks the call with a message naming the rule and how to permit it — distinct from a hard deny, and an extensible enum so a future approval TUI / MCP elicitation slots in without reworking the model.

> **Gotcha:** a rule with a `where:` block can only fire when that argument is present in the call. Negative matchers + `default: allow` can be bypassed by argument omission — prefer `default: deny` for guard configs.

## DLP

Enabled by default (`dlp.enabled: true`). Direction-aware: a detection in a tool call's **arguments blocks the call** (egress is the exfil path); a detection in a **result is redacted** in place as `[REDACTED:{pattern-id}]` so the agent keeps working. Overlapping detections resolve to the most specific match. Dict keys and numeric values that would need redaction withhold the whole result instead — nothing sensitive passes because it arrived in an awkward shape.

| Pattern id | Detects |
|---|---|
| `aws-access-key` | AWS access key IDs (`AKIA...`) |
| `aws-secret-key` | AWS secret key assignments |
| `github-token` | GitHub tokens (`ghp_`, `gho_`, ..., `github_pat_`) |
| `private-key-pem` | PEM private keys (full block redacted, incl. `ENCRYPTED`) |
| `connection-string` | DB URLs with credentials (`postgres://user:pass@...`) |
| `api-key-assignment` | Generic `api_key=...` assignments |
| `password-assignment` | `password:`/`passwd:`/`pwd=` assignments |
| `pan` | Payment cards (Visa/MC incl. 2-series/Amex/Discover), Luhn-validated |
| `ssn` | US Social Security Numbers |
| `us-phone` | US phone numbers (separators required) |

Override per pattern and direction:

```yaml
dlp:
  enabled: true
  overrides:
    private-key-pem:
      results: block       # withhold the whole result instead of redacting
    us-phone:
      requests: allow      # this CRM legitimately sends phone numbers
      results: allow
```

Request actions: `block` (default) | `allow`. Result actions: `redact` (default) | `block` | `allow`. Unknown pattern ids or actions fail validation at startup.

## Audit log

Point the trail at a file for one JSON event per decision:

```yaml
audit:
  log: ./tollbooth-audit.jsonl
  record: metadata        # or "full" — see below
```

```json
{"event": "decision", "call_id": "2a2b0cca…", "path": "request", "server": "fs", "tool": "write_file", "decision": "deny", "reason_id": "block-writes-outside-project", "v": 2, "ts": "2026-06-12T10:00:00+00:00", "seq": 5, "prev": "df412ac5…", "session": "f32a7ae3…"}
```

DLP decisions are audited by pattern id, never value: a blocked request logs `"reason_id": "dlp:pan"`, a redacted result logs `"reason_id": "redacted:aws-access-key"`. Decisions made because a security check was skipped (fail-open) are tagged `fail-open:<stage>` — the trail never hides a degraded state. (`audit_log: <path>` is the pre-M3 spelling and still works.)

### Tamper evidence

Every event carries a monotonic `seq` and `prev` — the SHA-256 of the previous log line — so edits, deletions, and reordering break the chain, which also spans gateway restarts:

```bash
tollbooth audit verify --log tollbooth-audit.jsonl
# OK: 10 event(s), head seq=9 hash=0a8e09b2…, mode=sha256 (unkeyed)
```

Record the reported head externally: a log truncated back to an earlier event still verifies on its own, but won't match your recorded head. Set `TOLLBOOTH_AUDIT_KEY` (environment variable, never a flag) to upgrade the chain to HMAC-SHA-256 — then an attacker who can rewrite the whole file still can't forge a valid chain without the key. Verification exit codes: `0` clean, `1` tamper/unreadable finding, `2` usage error.

### Payload recording & session replay

By default (`record: metadata`) no argument or result values are ever written. `record: full` additionally records **post-enforcement** payloads only: arguments of allowed requests and result content *after* redaction — exactly what crossed the boundary. Denied or blocked traffic never has payloads recorded, enforced inside the logger itself.

Each gateway run is a session (with a session-start event carrying the gateway version and a config *digest*, never config contents). Query and replay the trail:

```bash
# Filtered events as JSONL — by server, tool, decision, session, time window
tollbooth audit query --log audit.jsonl --decision deny --since 2026-06-12T00:00:00

# Chronological timeline of one session; renders payloads when recorded,
# degrades to a decision timeline on metadata-only logs
tollbooth audit replay <session-id> --log audit.jsonl
```

## Plugins

Beyond the built-in policy and DLP stages you can load your own interceptors, declared in config as `module:factory` import specs. Plugins run **after** the built-ins, in declared order — they can tighten a verdict but never loosen one (the first non-`allow` decision short-circuits), under the same fail-closed semantics: a plugin that raises at runtime denies the call (or withholds the result).

```yaml
plugins:
  - plugin: examples.plugins.prompt_injection:create   # importable module:factory
    settings:
      action: annotate    # plugin-specific settings dict, passed to the factory
```

Loading is fail-fast: an import error, a factory that raises, a name collision with a built-in, or an interceptor implementing neither hook aborts startup naming the plugin (reporting the exception **type** only — settings values are never echoed). Auto-discovery is deliberately *not* supported: the config file is the security boundary, so installing a package must never silently insert an interceptor.

Write one against the public API (`from tollbooth import ...`):

```python
from tollbooth import ToolCall, PolicyResult, Decision, ResultEdit, BlockResult

class TagInternalHosts:
    name = "tag-internal-hosts"          # unique; used in audit reason_ids

    def check_request(self, call: ToolCall) -> PolicyResult:
        # Return DENY/REQUIRE_APPROVAL to short-circuit, or ALLOW to pass.
        if "10.0." in str(call.args.get("url", "")):
            return PolicyResult(decision=Decision.DENY, rule_name=self.name,
                                message="internal host blocked")
        return PolicyResult(decision=Decision.ALLOW, rule_name=None, message="ok")

    def check_result(self, call: ToolCall, content: str) -> ResultEdit:
        # Transform content, or `raise BlockResult(reason_id)` to withhold it.
        return ResultEdit(content=content)

def create(settings: dict) -> "TagInternalHosts":
    return TagInternalHosts()
```

An interceptor may implement `check_request`, `check_result`, or both. Exported types: `ToolCall`, `PolicyResult`, `ResultEdit`, `BlockResult`, `Decision`, `RequestInterceptor`, `ResultInterceptor`. The shipped `examples/plugins/prompt_injection.py` is a reference result-path detector — see [limitations](#limitations).

## Claude Code hooks

The same policy + DLP engine runs as Claude Code [PreToolUse/PostToolUse hooks](https://docs.claude.com/en/docs/claude-code/hooks), governing the client's *own* tools (Bash, Edit, ...) — not just proxied MCP servers. `tollbooth hook pre|post` reads the hook event JSON on stdin and answers on stdout:

- **pre** — `deny` → `permissionDecision: "deny"` naming the rule; `require-approval` → `"ask"` with the approvable message; `allow` → **no output**, deferring to Claude Code's own permission prompt (tollbooth never auto-approves).
- **post** — DLP redactions come back via `updatedToolOutput`; a per-pattern `block` override replaces the output with a withholding message.

Native tools route as server `claude` (e.g. a rule for server `claude`, tool `Bash`); MCP tools arrive as `mcp__{server}__{tool}` and route as `(server, tool)`. Any internal error — malformed stdin, broken config, a pipeline crash — fails closed and never echoes input values. Audit events append under Claude's `session_id`, with cross-process locking so concurrent hook invocations keep the hash chain intact.

```bash
tollbooth emit-config --claude-hooks -c tollbooth.yaml   # merge into .claude/settings.json
```

## Design decisions that matter

The point of tollbooth isn't that it proxies MCP — it's the judgment calls a security control has to get right:

- **Fail-closed by default.** Any error in policy, DLP, or redaction *denies* the call; a result that can't be redacted is withheld. A control that fails open is not a control. Fail-open is an explicit, audited opt-in.
- **Detected values never appear in logs or errors.** Audit records pattern/rule **ids**, not matches. Payload recording is opt-in *and* post-enforcement only — the log holds what crossed the boundary, never blocked secrets.
- **Direction-aware DLP** — requests **block**, results **redact**. Redacting outbound arguments would silently corrupt calls; blocking every result would make agents unusable and get the control disabled. Egress is the true exfil path, so that's where the hard stop lives.
- **Tamper evidence is keyed.** The hash chain detects edits, deletions, and reordering; with `TOLLBOOTH_AUDIT_KEY` set, an attacker who rewrites the whole file still can't forge a valid chain.
- **The config file is the security boundary.** Plugins are explicitly declared `module:factory` specs with fail-fast loading — never entry-point auto-discovery, so installing a package can't silently insert an interceptor.
- **Plugins run after built-ins and only tighten.** A plugin can never pre-empt a built-in deny; the hook adapter's `allow` defers to the client's own prompt rather than auto-approving.

> A deeper writeup — full threat model, rejected alternatives, and the reasoning behind each call — is in [**Designing a security gateway for AI agents**](https://github.com/Realgagenichols/tollbooth/blob/main/docs/security-design.md).

## Limitations

Stated plainly, because a security tool that overclaims is worse than one that doesn't:

- **Prompt-injection detection is a reference, not production-grade.** The shipped detector proves the plugin interface; it matches a small set of instruction-override heuristics and *will* miss real attacks. Treat it as an integration example.
- **tollbooth governs tool traffic, not the LLM API itself.** It does not see or modify model completions.
- **Non-tool MCP traffic** (resources, prompts) is proxied transparently but **not yet scanned** — a later milestone.
- **Local, single-process.** No graphical UI and no hosted/multi-tenant deployment; tollbooth runs alongside the client.

## Architecture

| Module | Responsibility |
|--------|---------------|
| `main` | CLI: `run`, `emit-config`, `validate`, `import`, `audit verify\|query\|replay`, `hook pre\|post` |
| `config` | Load + pydantic-validate `tollbooth.yaml`; emit/import client config |
| `proxy` | Client-facing MCP server; tool aggregation + namespacing; routes through the pipeline |
| `upstream` | `UpstreamTransport` interface + `StdioUpstream` / `HttpUpstream` (supervised); `build_upstream` factory |
| `policy` | YAML rules, field matchers, first-match-wins, extensible `Decision` enum |
| `pipeline` | Ordered interceptor chain (request + result paths); policy and DLP are interceptors |
| `dlp` | Secrets / PAN (Luhn) / PII patterns; overlap suppression; direction-aware actions |
| `audit` | Hash-chained JSONL log; opt-in HMAC + payload recording; query/replay |
| `plugins` | Config-declared interceptor loading + fail-fast validation; documented public API |
| `hook` | Claude Code hook adapter: stdin event → pipeline → hook decision JSON |

Stack: the official `mcp` Python SDK, `pydantic`, and `pyyaml` — no other runtime dependencies. The project is built spec-first: every feature traces to an RFC 2119 requirement with Given/When/Then scenarios that map directly to tests.

## Development

```bash
uv run pytest          # 319 tests, incl. a real-subprocess gateway E2E
uv run ruff check .    # lint
```

## License

[MIT](https://github.com/Realgagenichols/tollbooth/blob/main/LICENSE) © Gage Nichols
