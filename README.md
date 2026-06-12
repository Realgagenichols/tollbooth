# tollbooth

A security gateway for AI agents: a transparent MCP proxy that enforces policy on every tool call and result passing between your MCP client (Claude Code, Claude Desktop, Cursor, custom agents) and its MCP servers.

**A firewall + DLP + audit layer for agentic AI tool traffic.**

- **Policy engine** — declarative YAML rules over tool calls: `allow` / `deny` / `require-approval` by server, tool, and argument patterns (first match wins)
- **DLP on agent traffic** — secrets, payment cards (Luhn-validated), and PII detected in both directions: requests carrying sensitive data are **blocked**, results are **redacted** in place
- **Fail-closed** — an internal error blocks the call; a result that can't be redacted is withheld; fail-open is explicit opt-in
- **Audit** — one structured JSONL event per decision; detected values never logged

## How it works

```
MCP client ──▶ tollbooth (policy ▸ DLP ▸ audit) ──▶ your real MCP servers
```

Your client config points at one server: tollbooth. Tollbooth launches the real upstream servers, exposes their tools namespaced as `{server}_{tool}`, and enforces policy on every call.

## Quickstart

```bash
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

The client then talks to `tollbooth run -c tollbooth.yaml`, which proxies everything through the policy pipeline.

## Policy rules

```yaml
policy:
  default: deny          # decision when no rule matches
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

Rules are evaluated top-down; the first match decides. `require-approval` blocks the call with a message naming the rule and how to permit it — distinct from a hard deny.

> **Gotcha:** a rule with a `where:` block can only fire when that argument is present in the call. Negative matchers + `default: allow` can be bypassed by argument omission — prefer `default: deny` for guard configs.

## DLP

Enabled by default (`dlp.enabled: true`). Direction-aware: a detection in a tool call's **arguments blocks the call** (egress is the exfil path); a detection in a **result is redacted** in place as `[REDACTED:{pattern-id}]` so the agent keeps working. Dict keys and numeric values that would need redaction withhold the whole result instead — nothing sensitive passes because it arrived in an awkward shape.

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

Set `audit_log: ./tollbooth-audit.jsonl` for one JSON event per decision:

```json
{"ts": "2026-06-12T10:00:00+00:00", "path": "request", "server": "fs", "tool": "write_file", "decision": "deny", "reason_id": "block-writes-outside-project"}
```

DLP decisions are audited by pattern id, never value: a blocked request logs `"reason_id": "dlp:pan"`, a redacted result logs `"reason_id": "redacted:aws-access-key"`. Decisions made because a security check was skipped (fail-open) are tagged `fail-open:<stage>` — the audit trail never hides a degraded state.

## Development

```bash
uv run pytest          # full suite, incl. a real-subprocess gateway E2E
uv run ruff check .    # lint
```
