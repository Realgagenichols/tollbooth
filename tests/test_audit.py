"""Tests for S1 (structured, redacting audit logging) and the M3 audit trail:
R8 tamper-evident chain, R9 session/call correlation."""

import hashlib
import io
import json

import pytest

from tollbooth.audit import GENESIS, AuditLogger
from tollbooth.pipeline import Pipeline, PolicyInterceptor, ToolCall
from tollbooth.policy import Decision, Matcher, Rule


def make_pipeline(stream, rules=None, default=Decision.ALLOW, **kwargs):
    return Pipeline(
        request_interceptors=[PolicyInterceptor(rules=rules or [], default=default)],
        audit=AuditLogger(stream),
        **kwargs,
    )


def events(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()]


class TestAuditEvents:
    # S1 scenario: decision logged without sensitive values
    def test_denied_call_logged_without_secret_value(self):
        stream = io.StringIO()
        rules = [
            Rule(
                name="no-token-push",
                action=Decision.DENY,
                server="web",
                tool="post",
                where={"body": Matcher(regex="ghp_")},
            )
        ]
        pipeline = make_pipeline(stream, rules=rules)
        pipeline.evaluate_request(
            ToolCall(server="web", tool="post", args={"body": "token=ghp_auditsecret99"})
        )
        [event] = events(stream)
        assert event["decision"] == "deny"
        assert event["server"] == "web"
        assert event["tool"] == "post"
        assert event["reason_id"] == "no-token-push"
        assert "ghp_auditsecret99" not in stream.getvalue()

    def test_every_decision_kind_emits_one_event(self):
        stream = io.StringIO()
        rules = [
            Rule(name="ok", action=Decision.ALLOW, server="s", tool="allowed"),
            Rule(name="ask", action=Decision.REQUIRE_APPROVAL, server="s", tool="ask"),
        ]
        pipeline = make_pipeline(stream, rules=rules, default=Decision.DENY)
        pipeline.evaluate_request(ToolCall(server="s", tool="allowed", args={}))
        pipeline.evaluate_request(ToolCall(server="s", tool="ask", args={}))
        pipeline.evaluate_request(ToolCall(server="s", tool="other", args={}))
        decisions = [e["decision"] for e in events(stream)]
        assert decisions == ["allow", "require-approval", "deny"]
        assert events(stream)[0]["reason_id"] == "ok"  # allow carries its rule
        # default decision has no rule
        assert events(stream)[2]["reason_id"] is None

    @pytest.mark.regression
    def test_fail_open_skip_is_visible_in_audit_trail(self):
        """An auditor must see that a security check was skipped, not a clean allow."""

        class Boom:
            name = "boom"

            def check_request(self, call):
                raise RuntimeError("kaput")

        stream = io.StringIO()
        pipeline = Pipeline(
            request_interceptors=[Boom()], audit=AuditLogger(stream), fail_open=True
        )
        pipeline.evaluate_request(ToolCall(server="s", tool="t", args={}))
        [event] = events(stream)
        assert event["decision"] == "allow"
        assert event["reason_id"] == "fail-open:boom"

    @pytest.mark.regression
    def test_fail_open_result_skip_is_audited(self):
        class Boom:
            name = "boom"

            def check_result(self, call, content):
                raise RuntimeError("kaput")

        stream = io.StringIO()
        pipeline = Pipeline(
            result_interceptors=[Boom()], audit=AuditLogger(stream), fail_open=True
        )
        verdict = pipeline.process_result(ToolCall(server="s", tool="t", args={}), "c")
        assert verdict.content == "c"
        [event] = events(stream)
        assert event["path"] == "result"
        assert event["reason_id"] == "fail-open:boom"

    def test_events_carry_timestamp_and_path(self):
        stream = io.StringIO()
        pipeline = make_pipeline(stream)
        pipeline.evaluate_request(ToolCall(server="s", tool="t", args={}))
        [event] = events(stream)
        assert event["path"] == "request"
        assert "ts" in event  # ISO-8601 UTC
        assert event["ts"].endswith("+00:00")

    def test_fail_closed_denial_is_audited(self):
        class Boom:
            name = "boom"

            def check_request(self, call):
                raise RuntimeError("kaput")

        stream = io.StringIO()
        pipeline = Pipeline(request_interceptors=[Boom()], audit=AuditLogger(stream))
        pipeline.evaluate_request(ToolCall(server="s", tool="t", args={}))
        [event] = events(stream)
        assert event["decision"] == "deny"
        assert event["reason_id"] == "interceptor-failure:boom"

    # S1/R7: one combined event per transformed result, none for clean passes.
    def test_redaction_emits_exactly_one_event(self):
        from tollbooth.dlp import DlpResultInterceptor

        stream = io.StringIO()
        pipeline = Pipeline(
            result_interceptors=[DlpResultInterceptor()], audit=AuditLogger(stream)
        )
        call = ToolCall(server="fs", tool="read_file", args={})

        pipeline.process_result(call, "nothing sensitive")
        assert events(stream) == []  # clean pass-through: no event

        pipeline.process_result(call, "key AKIAIOSFODNN7EXAMPLE ssn 123-45-6789")
        [event] = events(stream)
        assert event["path"] == "result"
        assert event["decision"] == "allow"
        assert event["reason_id"] == "redacted:aws-access-key,ssn"
        assert "AKIAIOSFODNN7EXAMPLE" not in stream.getvalue()

    def test_result_block_is_audited(self):
        from tollbooth.pipeline import BlockResult

        class Blocker:
            name = "dlp"

            def check_result(self, call, content):
                raise BlockResult("private-key-pem")

        stream = io.StringIO()
        pipeline = Pipeline(result_interceptors=[Blocker()], audit=AuditLogger(stream))
        pipeline.process_result(ToolCall(server="s", tool="t", args={}), "secret stuff")
        [event] = events(stream)
        assert event["path"] == "result"
        assert event["decision"] == "deny"
        assert event["reason_id"] == "private-key-pem"
        assert "secret stuff" not in stream.getvalue()

    def test_pipeline_without_audit_logger_still_works(self):
        pipeline = Pipeline()
        result = pipeline.evaluate_request(ToolCall(server="s", tool="t", args={}))
        assert result.decision is Decision.ALLOW


def emit_decisions(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.decision(
            path="request", server="s", tool=f"t{i}", decision="allow", reason_id=None
        )


class TestChain:
    """R8 writer side: every event extends a hash chain."""

    def test_seq_is_monotonic_from_zero(self):
        stream = io.StringIO()
        emit_decisions(AuditLogger(stream), 3)
        assert [e["seq"] for e in events(stream)] == [0, 1, 2]

    def test_first_event_links_to_genesis(self):
        stream = io.StringIO()
        emit_decisions(AuditLogger(stream), 1)
        [event] = events(stream)
        assert event["prev"] == GENESIS
        assert event["v"] == 2

    def test_each_event_carries_hash_of_previous_line(self):
        stream = io.StringIO()
        emit_decisions(AuditLogger(stream), 3)
        lines = stream.getvalue().splitlines()
        for prev_line, line in zip(lines, lines[1:], strict=False):
            expected = hashlib.sha256(prev_line.encode("utf-8")).hexdigest()
            assert json.loads(line)["prev"] == expected

    # R8: TOLLBOOTH_AUDIT_KEY upgrades the chain to HMAC-SHA-256.
    def test_keyed_chain_uses_hmac_not_plain_hash(self):
        import hmac as hmac_mod

        stream = io.StringIO()
        emit_decisions(AuditLogger(stream, key=b"k3y"), 2)
        first, second = stream.getvalue().splitlines()
        keyed = hmac_mod.new(b"k3y", first.encode("utf-8"), hashlib.sha256).hexdigest()
        plain = hashlib.sha256(first.encode("utf-8")).hexdigest()
        assert json.loads(second)["prev"] == keyed
        assert json.loads(second)["prev"] != plain

    def test_key_value_never_appears_in_log(self):
        stream = io.StringIO()
        emit_decisions(AuditLogger(stream, key=b"sentinel-audit-key"), 2)
        assert "sentinel-audit-key" not in stream.getvalue()

    def test_audit_key_from_env(self, monkeypatch):
        from tollbooth.audit import audit_key_from_env

        monkeypatch.delenv("TOLLBOOTH_AUDIT_KEY", raising=False)
        assert audit_key_from_env() is None
        monkeypatch.setenv("TOLLBOOTH_AUDIT_KEY", "hunter2")
        assert audit_key_from_env() == b"hunter2"


class TestCorrelation:
    """R9: session and call ids correlate events."""

    # R9 scenario: request/result correlation (same call id on both paths)
    def test_request_and_result_events_share_call_id(self):
        from tollbooth.dlp import DlpResultInterceptor

        stream = io.StringIO()
        pipeline = Pipeline(
            request_interceptors=[PolicyInterceptor(rules=[], default=Decision.ALLOW)],
            result_interceptors=[DlpResultInterceptor()],
            audit=AuditLogger(stream),
        )
        call = ToolCall(server="fs", tool="read", args={}, call_id="call-abc")
        pipeline.evaluate_request(call)
        pipeline.process_result(call, "key AKIAIOSFODNN7EXAMPLE")
        request_event, result_event = events(stream)
        assert request_event["path"] == "request"
        assert result_event["path"] == "result"
        assert request_event["call_id"] == result_event["call_id"] == "call-abc"

    # R9 scenario: distinct sessions — two runs carry distinct session ids
    def test_two_loggers_have_distinct_session_ids(self):
        first, second = io.StringIO(), io.StringIO()
        emit_decisions(AuditLogger(first), 1)
        emit_decisions(AuditLogger(second), 1)
        [a] = events(first)
        [b] = events(second)
        assert a["session"] and b["session"]
        assert a["session"] != b["session"]

    def test_all_events_in_one_run_share_session_id(self):
        stream = io.StringIO()
        emit_decisions(AuditLogger(stream), 3)
        assert len({e["session"] for e in events(stream)}) == 1


class TestSessionStart:
    """R9: gateway startup emits a session-start event — digest, never contents."""

    def test_session_start_event_chains_and_carries_fields(self):
        stream = io.StringIO()
        logger = AuditLogger(stream)
        logger.session_start(gateway_version="0.1.0", config_digest="ab" * 32)
        emit_decisions(logger, 1)
        start, decision = events(stream)
        assert start["event"] == "session-start"
        assert start["seq"] == 0
        assert start["prev"] == GENESIS
        assert start["gateway_version"] == "0.1.0"
        assert start["config_digest"] == "ab" * 32
        assert decision["seq"] == 1  # decisions chain off the start event

    # R9 scenario: session start without secrets
    def test_config_digest_not_config_contents(self, tmp_path):
        from tollbooth.config import load_config
        from tollbooth.main import _config_digest

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(
            "servers:\n"
            "  fs:\n"
            "    command: /bin/echo\n"
            "    env:\n"
            "      API_TOKEN: sentinel-env-secret-77\n",
            encoding="utf-8",
        )
        config = load_config(config_path)
        digest = _config_digest(config)
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
        assert _config_digest(config) == digest  # deterministic

        stream = io.StringIO()
        logger = AuditLogger(stream)
        logger.session_start(gateway_version="0.1.0", config_digest=digest)
        assert "sentinel-env-secret-77" not in stream.getvalue()


class TestChainResume:
    """R8: appending to an existing log seeds the chain from its last line."""

    def test_chain_resumes_across_reopen(self, tmp_path):
        from tollbooth.audit import tail_state

        log_path = tmp_path / "audit.jsonl"
        with open(log_path, "w", encoding="utf-8") as handle:
            emit_decisions(AuditLogger(handle), 2)
        with open(log_path, "a", encoding="utf-8") as handle:
            emit_decisions(AuditLogger(handle, resume=tail_state(log_path)), 1)

        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert [json.loads(ln)["seq"] for ln in lines] == [0, 1, 2]
        third = json.loads(lines[2])
        assert third["prev"] == hashlib.sha256(lines[1].encode("utf-8")).hexdigest()

    def test_tail_state_missing_or_empty_file(self, tmp_path):
        from tollbooth.audit import tail_state

        assert tail_state(tmp_path / "absent.jsonl") is None
        empty = tmp_path / "empty.jsonl"
        empty.touch()
        assert tail_state(empty) is None

    def test_malformed_last_line_raises_without_echoing_content(self, tmp_path):
        from tollbooth.audit import AuditError, tail_state

        log_path = tmp_path / "audit.jsonl"
        log_path.write_text('{"not-an-event": "sentinel-payload-xyz"\n', encoding="utf-8")
        with pytest.raises(AuditError) as excinfo:
            tail_state(log_path)
        assert "sentinel-payload-xyz" not in str(excinfo.value)
        assert "audit.jsonl" in str(excinfo.value)


def write_log(path, n, key=None):
    """A fresh chained log with n decision events; returns the lines."""
    with open(path, "w", encoding="utf-8") as handle:
        emit_decisions(AuditLogger(handle, key=key), n)
    return path.read_text(encoding="utf-8").splitlines()


class TestVerifyChain:
    """R8: `verify_chain` detects modification, deletion, and reordering."""

    # R8 scenario: intact log verifies
    def test_intact_log_verifies_with_head(self, tmp_path):
        from tollbooth.audit import verify_chain

        log_path = tmp_path / "audit.jsonl"
        lines = write_log(log_path, 3)
        head = verify_chain(log_path)
        assert head.events == 3
        assert head.seq == 2
        assert head.digest == hashlib.sha256(lines[-1].encode("utf-8")).hexdigest()

    # R8 scenario: modified event detected (and content never echoed)
    def test_modified_line_detected_without_echo(self, tmp_path):
        from tollbooth.audit import AuditError, verify_chain

        log_path = tmp_path / "audit.jsonl"
        lines = write_log(log_path, 3)
        lines[1] = lines[1].replace('"t1"', '"tampered-sentinel-tool"')
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditError) as excinfo:
            verify_chain(log_path)
        message = str(excinfo.value)
        assert "line 3" in message  # break detected where prev no longer matches
        assert "tampered-sentinel-tool" not in message

    # R8 scenario: deleted event detected
    def test_deleted_interior_line_detected(self, tmp_path):
        from tollbooth.audit import AuditError, verify_chain

        log_path = tmp_path / "audit.jsonl"
        lines = write_log(log_path, 3)
        del lines[1]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditError, match="line 2"):
            verify_chain(log_path)

    def test_reordered_lines_detected(self, tmp_path):
        from tollbooth.audit import AuditError, verify_chain

        log_path = tmp_path / "audit.jsonl"
        lines = write_log(log_path, 3)
        lines[1], lines[2] = lines[2], lines[1]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditError):
            verify_chain(log_path)

    # R8 scenario: chain spans restarts
    def test_restart_appended_log_verifies(self, tmp_path):
        from tollbooth.audit import tail_state, verify_chain

        log_path = tmp_path / "audit.jsonl"
        write_log(log_path, 2)
        with open(log_path, "a", encoding="utf-8") as handle:
            emit_decisions(AuditLogger(handle, resume=tail_state(log_path)), 2)
        head = verify_chain(log_path)
        assert head.events == 4
        assert head.seq == 3

    # R8 scenario: forged chain without the key
    def test_unkeyed_reforge_of_keyed_log_fails_under_key(self, tmp_path):
        from tollbooth.audit import AuditError, verify_chain

        log_path = tmp_path / "audit.jsonl"
        write_log(log_path, 3, key=b"k3y")
        assert verify_chain(log_path, key=b"k3y").events == 3

        # Attacker rewrites the file, recomputing plain SHA-256 links.
        events_list = [json.loads(ln) for ln in log_path.read_text().splitlines()]
        events_list[1]["tool"] = "forged"
        forged_lines = []
        prev = "genesis"
        for event in events_list:
            event["prev"] = prev
            line = json.dumps(event, ensure_ascii=False)
            forged_lines.append(line)
            prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
        log_path.write_text("\n".join(forged_lines) + "\n", encoding="utf-8")
        with pytest.raises(AuditError):
            verify_chain(log_path, key=b"k3y")

    def test_malformed_line_fails_loudly_without_echo(self, tmp_path):
        from tollbooth.audit import AuditError, verify_chain

        log_path = tmp_path / "audit.jsonl"
        write_log(log_path, 2)
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write("garbage sentinel-not-json {{{\n")
        with pytest.raises(AuditError) as excinfo:
            verify_chain(log_path)
        assert "line 3" in str(excinfo.value)
        assert "sentinel-not-json" not in str(excinfo.value)

    @pytest.mark.regression
    def test_unicode_line_separators_in_values_do_not_break_framing(self, tmp_path):
        """U+2028/U+2029/U+0085 pass through json.dumps(ensure_ascii=False)
        raw; framing must be '\\n'-only or a self-written log fails verify."""
        from tollbooth.audit import tail_state, verify_chain

        log_path = tmp_path / "audit.jsonl"
        with open(log_path, "w", encoding="utf-8") as handle:
            logger = AuditLogger(handle)
            logger.decision(
                path="request",
                server="s",
                tool="evil\u2028tool\u2029name\u0085x",
                decision="deny",
                reason_id=None,
            )
            logger.decision(
                path="request", server="s", tool="ok", decision="allow", reason_id=None
            )
        head = verify_chain(log_path)
        assert head.events == 2
        seq, _last = tail_state(log_path)
        assert seq == 1

    def test_empty_log_verifies_as_zero_events(self, tmp_path):
        from tollbooth.audit import verify_chain

        log_path = tmp_path / "audit.jsonl"
        log_path.touch()
        head = verify_chain(log_path)
        assert head.events == 0
        assert head.seq is None
