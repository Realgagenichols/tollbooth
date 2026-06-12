"""Tests for R4 scenarios: fail-closed pipeline behavior."""

import logging

import pytest

from tollbooth.pipeline import Pipeline, ToolCall
from tollbooth.policy import Decision, PolicyResult


class StubInterceptor:
    """Request interceptor with a scripted verdict, recording invocations."""

    def __init__(self, name, decision=Decision.ALLOW, error=None):
        self.name = name
        self.decision = decision
        self.error = error
        self.calls = []

    def check_request(self, call):
        self.calls.append(call)
        if self.error is not None:
            raise self.error
        return PolicyResult(decision=self.decision, rule_name=self.name, message=self.name)


class StubResultInterceptor:
    def __init__(self, name, transform=None, error=None):
        self.name = name
        self.transform = transform
        self.error = error

    def check_result(self, call, content):
        if self.error is not None:
            raise self.error
        if self.transform is not None:
            return self.transform(content)
        return content


CALL = ToolCall(server="fs", tool="read_file", args={"path": "/tmp/x"})


class TestRequestPath:
    def test_all_allow_passes(self):
        pipeline = Pipeline(request_interceptors=[StubInterceptor("a"), StubInterceptor("b")])
        result = pipeline.evaluate_request(CALL)
        assert result.decision is Decision.ALLOW

    def test_deny_short_circuits_later_interceptors(self):
        deny = StubInterceptor("deny-er", decision=Decision.DENY)
        after = StubInterceptor("after")
        pipeline = Pipeline(request_interceptors=[deny, after])
        result = pipeline.evaluate_request(CALL)
        assert result.decision is Decision.DENY
        assert after.calls == []  # never reached

    def test_require_approval_short_circuits(self):
        approval = StubInterceptor("appr", decision=Decision.REQUIRE_APPROVAL)
        pipeline = Pipeline(request_interceptors=[approval])
        assert pipeline.evaluate_request(CALL).decision is Decision.REQUIRE_APPROVAL

    # R4 scenario: evaluation error blocks the call
    def test_crashing_interceptor_fails_closed(self, caplog):
        pipeline = Pipeline(
            request_interceptors=[StubInterceptor("boom", error=RuntimeError("kaput"))]
        )
        with caplog.at_level(logging.ERROR):
            result = pipeline.evaluate_request(CALL)
        assert result.decision is Decision.DENY
        assert "boom" in caplog.text  # failure logged with interceptor name
        assert "failed" in result.message.lower()

    # R4 scenario: configurable fail-open
    def test_crashing_interceptor_fails_open_when_configured(self, caplog):
        boom = StubInterceptor("boom", error=RuntimeError("kaput"))
        after = StubInterceptor("after")
        pipeline = Pipeline(request_interceptors=[boom, after], fail_open=True)
        with caplog.at_level(logging.ERROR):
            result = pipeline.evaluate_request(CALL)
        assert result.decision is Decision.ALLOW
        assert "failed open" in caplog.text.lower()
        assert after.calls  # fail-open skips the broken stage, later stages still run

    def test_crash_log_never_contains_argument_values(self, caplog):
        secret_call = ToolCall(server="s", tool="t", args={"token": "ghp_pipelinesecret"})
        pipeline = Pipeline(
            request_interceptors=[StubInterceptor("boom", error=RuntimeError("kaput"))]
        )
        with caplog.at_level(logging.ERROR):
            pipeline.evaluate_request(secret_call)
        assert "ghp_pipelinesecret" not in caplog.text


class TestResultPath:
    def test_no_interceptors_passes_content_unchanged(self):
        pipeline = Pipeline()
        verdict = pipeline.process_result(CALL, "hello")
        assert verdict.decision is Decision.ALLOW
        assert verdict.content == "hello"

    def test_transforms_chain_in_order(self):
        pipeline = Pipeline(
            result_interceptors=[
                StubResultInterceptor("upper", transform=str.upper),
                StubResultInterceptor("exclaim", transform=lambda c: c + "!"),
            ]
        )
        verdict = pipeline.process_result(CALL, "hello")
        assert verdict.content == "HELLO!"

    # R4: a result that can't be processed is blocked, not passed through
    def test_crashing_result_interceptor_fails_closed(self, caplog):
        pipeline = Pipeline(
            result_interceptors=[StubResultInterceptor("boom", error=RuntimeError("kaput"))]
        )
        with caplog.at_level(logging.ERROR):
            verdict = pipeline.process_result(CALL, "content")
        assert verdict.decision is Decision.DENY
        assert verdict.content is None  # original content withheld

    def test_crashing_result_interceptor_fails_open_when_configured(self):
        pipeline = Pipeline(
            result_interceptors=[StubResultInterceptor("boom", error=RuntimeError("kaput"))],
            fail_open=True,
        )
        verdict = pipeline.process_result(CALL, "content")
        assert verdict.decision is Decision.ALLOW
        assert verdict.content == "content"


@pytest.mark.regression
def test_policy_interceptor_integrates(tmp_path):
    """Policy engine plugs into the pipeline as the first request interceptor."""
    from tollbooth.pipeline import PolicyInterceptor
    from tollbooth.policy import Matcher, Rule

    rules = [
        Rule(
            name="no-etc",
            action=Decision.DENY,
            server="fs",
            tool="read_file",
            where={"path": Matcher(prefix="/etc/")},
        )
    ]
    pipeline = Pipeline(
        request_interceptors=[PolicyInterceptor(rules=rules, default=Decision.ALLOW)]
    )
    denied = pipeline.evaluate_request(
        ToolCall(server="fs", tool="read_file", args={"path": "/etc/passwd"})
    )
    assert denied.decision is Decision.DENY
    assert denied.rule_name == "no-etc"
    allowed = pipeline.evaluate_request(CALL)
    assert allowed.decision is Decision.ALLOW
