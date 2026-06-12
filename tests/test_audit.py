"""Tests for S1: structured, redacting audit logging."""

import io
import json

import pytest

from tollbooth.audit import AuditLogger
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
