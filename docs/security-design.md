# Designing a security gateway for AI agents

*The decisions behind [tollbooth](https://github.com/Realgagenichols/tollbooth) — a firewall + DLP + audit layer for agentic AI tool traffic.*

AI agents now write files, run shell commands, hit APIs, and fetch URLs on your behalf. That traffic flows **unmediated**: there is no control point between the model deciding to call `shell.exec("curl … | sh")` and the call actually running. No way to deny a dangerous call, stop a secret from leaking out through a tool argument, redact a credential before it lands back in the model's context, or produce a record of what the agent actually did.

tollbooth is that control point — a transparent [MCP](https://modelcontextprotocol.io) proxy that sits between any MCP client and the servers it talks to. The interesting part isn't that it proxies MCP; it's the handful of decisions a security control has to get *right*. This is a tour of those decisions, the alternatives I rejected, and why.

## The threat model first

A control is only as good as the threats it's honest about. tollbooth defends against:

- **Dangerous actions** the agent is coerced or confused into taking — destructive shell commands, writes outside a project, fetch-and-execute.
- **Egress of secrets** — an agent putting an API key, password, or PAN into a tool *argument* that leaves for an upstream (the exfiltration path).
- **Ingress of secrets into context** — a tool *result* carrying credentials that would otherwise be pasted straight into the model's window (and from there, anywhere the model sends text).
- **Repudiation** — "what did the agent do?" needs an answer you can *trust*, including after a host compromise.

And it explicitly does **not** claim to solve:

- **Prompt-injection detection quality.** v1 ships a *reference* detector to prove the plugin interface; it matches a few instruction-override heuristics and will miss real attacks. Overclaiming here would be the worst thing a security tool could do.
- **The model API itself.** tollbooth governs tool traffic, not completions.
- **Non-tool MCP traffic** (resources, prompts) — proxied transparently in v1, scanned later.

Naming what you *don't* cover is part of the design, not an afterthought.

## Decision 1 — Fail closed, including "a result that can't be redacted is blocked"

Any error in policy evaluation, DLP scanning, or redaction **denies the call** (or withholds the result). Fail-open is available, but only as an explicit, audited opt-in.

The corollary is the one people skip: if DLP *detects* a secret in a result but can't cleanly redact it — say it appears as a dict **key**, or as a numeric leaf where rewriting the value would corrupt the response shape — the entire result is withheld, not passed through. Renaming a key or rewriting a number to scrub it would silently corrupt the data the model receives; passing it through unredacted would leak. So it's refused.

> A security control that fails open is not a security control. It's a logging statement with extra steps.

*Rejected:* fail-open by default ("don't break the agent"). That optimizes for the wrong failure. The whole point is that the dangerous path is the one you stop when you're unsure.

## Decision 2 — Direction-aware DLP: requests **block**, results **redact**

The naive designs both fail:

- **Block everything** (deny any call or result touching a secret) makes the agent unusable on a real codebase — which leads users to disable the control entirely. A control that gets turned off protects nothing.
- **Redact everything**, including outbound arguments, silently corrupts the calls the agent is trying to make, and — worse — *hides the exfiltration attempt* instead of stopping it.

So tollbooth is direction-aware. A secret in a **request argument** is the exfil path: the call is **blocked** outright (the flagged value is never forwarded, and never echoed in the error). A secret in a **result** is **redacted in place** as `[REDACTED:{pattern-id}]`, so the agent keeps working — it just never sees the raw credential.

This keeps the control *on* because it keeps the agent *useful*, which is the only way a control survives contact with daily work.

## Decision 3 — Detected values never touch the logs; payloads are opt-in and post-enforcement only

The audit log records **what** fired — server, tool, rule id, pattern id, decision — never the matched value. A blocked PAN logs `dlp:pan`, not the number.

Payload recording (arguments, results) is **off by default**. When you turn it on (`record: full`), the logger records only **post-enforcement** content: the arguments of *allowed* requests and result content *after* redaction — exactly what crossed the boundary. Denied or blocked traffic never has payloads recorded, and that's enforced inside the logger itself, not left to the caller to remember.

The result: "secrets never appear in logs" is true by construction in the default mode, and even in full mode the log holds only what actually flowed — never a secret DLP blocked, never a value DLP scrubbed.

*Rejected:* always-on full recording (it captures exactly the sensitive data your patterns missed) and metadata-only-forever (no forensic replay). Opt-in, post-enforcement recording is the seam between those.

## Decision 4 — Tamper evidence via a keyed hash chain

Every audit event carries a monotonic sequence number and `prev`: the SHA-256 of the previous log line. Edits, deletions, and reordering all break the chain, and the chain is seeded from the file's last line on startup so it spans restarts — and concurrent writers (a live gateway plus Claude Code hook processes) serialize with cross-process locking so the chain stays intact.

The threat that hashes alone *don't* stop: an attacker who can rewrite the whole file can recompute every hash. So when `TOLLBOOTH_AUDIT_KEY` is set, the chain upgrades to **HMAC-SHA-256** — now a valid chain can't be forged without the key, even by someone who owns the file.

One honest limitation, surfaced rather than hidden: **end-truncation** (lopping off the most recent events) produces a log that still verifies *on its own*. The only defense is comparing against a head you recorded externally — so `verify` prints the head (seq + hash) on success, precisely so you can record it somewhere the attacker can't reach.

*Rejected:* external signing / transparency-log anchoring (real infrastructure, deferred) and plain-hash-only (kept as the no-key default, but it can't survive a whole-file rewrite).

## Decision 5 — The config file *is* the security boundary

Plugins (custom interceptors) are declared in config as explicit `module:factory` import specs and loaded fail-fast: a bad import, a factory that raises, a name collision with a built-in, or a non-conforming object **aborts startup**, naming the plugin (and reporting the exception *type* only — never interpolated config or values).

What I deliberately did **not** build: setuptools entry-point auto-discovery. If plugins loaded themselves by being installed, then `pip install some-package` could silently insert an interceptor into your security pipeline. The config file has to be the one place that decides what runs. Plugins also run *after* the built-in policy and DLP stages and can only *tighten* a verdict — the first non-allow short-circuits — so a plugin can never quietly demote a built-in deny.

## Decision 6 — `require-approval` without depending on a client UI

"Ask a human" is a great decision type and a deployment headache: MCP elicitation support is uneven across clients, and a side-channel approval UI is a real build. So in v1, `require-approval` is implemented as **deny-with-an-approvable-message**: the call is blocked, but with a response distinct from a hard deny that names the rule and explains how to permit it. The `Decision` enum stays extensible, so an approval TUI or MCP elicitation slots in later without reworking the policy model.

It's the fail-closed-aligned, zero-dependency version of human-in-the-loop: when in doubt, stop — and tell the human exactly what to do about it.

---

## The throughline

Every one of these is the same instinct applied to a different surface: **when the system is unsure, it should stop, and it should be honest about what it can't do.** Fail closed. Don't log the secret. Block egress, don't corrupt it. Make tampering detectable, and admit which tampering it can't catch. Make the config the boundary. That instinct — more than any particular pattern or parser — is what separates a security control from a feature that happens to sit in the data path.

If you want to see it run, the [README](https://github.com/Realgagenichols/tollbooth#readme) has a 40-second recording of the gateway denying a `curl | sh`, blocking an AWS key from leaving in a GitHub issue, redacting credentials out of a tool result, and verifying the tamper-evident chain — all real output. Install it with `pip install mcp-tollbooth`.
