# tollbooth

A security gateway for AI agents: a transparent MCP proxy that enforces policy on every tool call and result passing between your MCP client (Claude Code, Claude Desktop, Cursor, custom agents) and its MCP servers.

**A firewall + DLP + audit layer for agentic AI tool traffic.**

- **Policy engine** — declarative YAML rules over tool calls: `allow` / `deny` / `require-approval` by server, tool, and argument patterns (first match wins)
- **Fail-closed** — an internal error blocks the call; fail-open is explicit opt-in
- **Audit** — one structured JSONL event per decision; argument values never logged
- **Coming (M2)** — DLP on agent traffic: block secrets/PAN/PII in requests, redact them in results

## How it works

```
MCP client ──▶ tollbooth (policy ▸ audit) ──▶ your real MCP servers
```

Your client config points at one server: tollbooth. Tollbooth launches the real upstream servers, exposes their tools namespaced as `{server}_{tool}`, and enforces policy on every call.

## Quickstart

```bash
uv sync

# 1. Write a gateway config (see examples/tollbooth.yaml)
cp examples/tollbooth.yaml tollbooth.yaml

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

## Audit log

Set `audit_log: ./tollbooth-audit.jsonl` for one JSON event per decision:

```json
{"ts": "2026-06-12T10:00:00+00:00", "path": "request", "server": "fs", "tool": "write_file", "decision": "deny", "reason_id": "block-writes-outside-project"}
```

Decisions made because a security check was skipped (fail-open) are tagged `fail-open:<stage>` — the audit trail never hides a degraded state.

## Development

```bash
uv run pytest          # full suite, incl. a real-subprocess gateway E2E
uv run ruff check .    # lint
```

Requirements and design live in `SPEC.md` (RFC 2119 + Given/When/Then scenarios); design rationale in `docs/design/gateway-design.md`.
