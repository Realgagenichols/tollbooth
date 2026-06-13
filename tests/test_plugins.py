"""Tests for R13 (plugin loading + pipeline behavior) and R14 (reference detector)."""

import pytest

from tests.plugin_samples import SENTINEL
from tollbooth.config import ConfigError, PluginConfig
from tollbooth.plugins import PluginSet, load_plugins


def spec(plugin: str, **settings) -> PluginConfig:
    return PluginConfig(plugin=plugin, settings=settings)


class TestLoadPlugins:
    def test_empty_specs_load_nothing(self):
        assert load_plugins([]) == PluginSet()

    def test_request_and_result_plugins_classified_by_protocol(self):
        loaded = load_plugins(
            [
                spec("tests.plugin_samples:deny_tool", tool="deploy"),
                spec("tests.plugin_samples:redact_word", word="x"),
            ]
        )
        assert [p.name for p in loaded.request] == ["deny-tool"]
        assert [p.name for p in loaded.result] == ["redact-word"]

    def test_declared_order_preserved(self):
        loaded = load_plugins(
            [
                spec("tests.plugin_samples:allow_all"),
                spec("tests.plugin_samples:deny_tool"),
            ]
        )
        assert [p.name for p in loaded.request] == ["allow-all", "deny-tool"]

    # R13 scenario: broken plugin aborts startup
    def test_import_failure_names_plugin(self):
        with pytest.raises(ConfigError, match="no_such_module:create.*import failed"):
            load_plugins([spec("no_such_module:create")])

    def test_missing_factory_rejected(self):
        with pytest.raises(ConfigError, match="not a callable factory"):
            load_plugins([spec("tests.plugin_samples:does_not_exist")])

    def test_non_callable_factory_rejected(self):
        with pytest.raises(ConfigError, match="not a callable factory"):
            load_plugins([spec("tests.plugin_samples:NOT_A_FACTORY")])

    # R13 scenario: broken plugin aborts startup — error carries the exception
    # TYPE, never interpolated exception text (Pattern 11)
    def test_factory_failure_reports_type_never_message(self):
        with pytest.raises(ConfigError) as excinfo:
            load_plugins([spec("tests.plugin_samples:boom")])
        assert "RuntimeError" in str(excinfo.value)
        assert SENTINEL not in str(excinfo.value)

    def test_settings_never_echoed_in_errors(self):
        with pytest.raises(ConfigError) as excinfo:
            load_plugins([spec("tests.plugin_samples:boom", token=SENTINEL)])
        assert SENTINEL not in str(excinfo.value)

    def test_nameless_interceptor_rejected(self):
        with pytest.raises(ConfigError, match="no usable 'name'"):
            load_plugins([spec("tests.plugin_samples:no_name")])

    def test_checkless_interceptor_rejected(self):
        with pytest.raises(ConfigError, match="neither check_request nor check_result"):
            load_plugins([spec("tests.plugin_samples:no_checks")])

    def test_builtin_name_shadowing_rejected(self):
        with pytest.raises(ConfigError, match="collides"):
            load_plugins([spec("tests.plugin_samples:reserved_name")])

    def test_duplicate_plugin_names_rejected(self):
        with pytest.raises(ConfigError, match="collides"):
            load_plugins(
                [
                    spec("tests.plugin_samples:deny_tool"),
                    spec("tests.plugin_samples:deny_tool"),
                ]
            )


WIRED_CONFIG = """
servers:
  fs:
    command: fake-fs-server
policy:
  default: allow
plugins:
  - plugin: tests.plugin_samples:deny_tool
    settings:
      tool: deploy
  - plugin: tests.plugin_samples:redact_word
    settings:
      word: hunter2
"""


class TestPluginWiring:
    """R13: plugins land on the pipeline after built-ins, in declared order."""

    def _gateway(self, tmp_path, text):
        import io

        from tollbooth.config import load_config
        from tollbooth.main import build_gateway

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(text, encoding="utf-8")
        return build_gateway(load_config(config_path), audit_stream=io.StringIO())

    def test_plugins_appended_after_builtins(self, tmp_path):
        gateway = self._gateway(tmp_path, WIRED_CONFIG)
        assert [i.name for i in gateway.pipeline.request_interceptors] == [
            "policy",
            "dlp-request",
            "deny-tool",
        ]
        assert [i.name for i in gateway.pipeline.result_interceptors] == [
            "dlp-result",
            "redact-word",
        ]

    # R13 scenario: broken plugin aborts startup (gateway never builds)
    def test_broken_plugin_aborts_before_proxying(self, tmp_path):
        bad = WIRED_CONFIG.replace("deny_tool", "boom")
        with pytest.raises(ConfigError, match="boom.*RuntimeError"):
            self._gateway(tmp_path, bad)

    def test_validate_loads_plugins_and_reports_count(self, tmp_path, capsys):
        from tollbooth.main import cmd_validate

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(WIRED_CONFIG, encoding="utf-8")
        assert cmd_validate(str(config_path)) == 0
        assert "plugins=2" in capsys.readouterr().out

    def test_validate_fails_on_broken_plugin(self, tmp_path):
        from tollbooth.main import cmd_validate

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(WIRED_CONFIG.replace("deny_tool", "boom"), encoding="utf-8")
        with pytest.raises(ConfigError):
            cmd_validate(str(config_path))


class TestPluginsInPipeline:
    """R13 scenarios driven through a real Pipeline with loaded plugins."""

    def _pipeline(self, plugin_specs, rules=None, default=None, stream=None):
        import io

        from tollbooth.audit import AuditLogger
        from tollbooth.pipeline import Pipeline, PolicyInterceptor
        from tollbooth.policy import Decision

        loaded = load_plugins(plugin_specs)
        stream = stream if stream is not None else io.StringIO()
        pipeline = Pipeline(
            request_interceptors=[
                PolicyInterceptor(rules=rules or [], default=default or Decision.ALLOW),
                *loaded.request,
            ],
            result_interceptors=list(loaded.result),
            audit=AuditLogger(stream),
        )
        return pipeline, stream

    @staticmethod
    def _events(stream):
        import json

        return [json.loads(line) for line in stream.getvalue().splitlines()]

    @staticmethod
    def _call(tool="deploy"):
        from tollbooth.pipeline import ToolCall

        return ToolCall(server="fs", tool=tool, args={}, call_id="c1")

    # R13 scenario: config-declared plugin blocks a call
    def test_plugin_deny_blocks_and_audits_reason(self):
        from tollbooth.policy import Decision

        pipeline, stream = self._pipeline([spec("tests.plugin_samples:deny_tool", tool="deploy")])
        result = pipeline.evaluate_request(self._call("deploy"))
        assert result.decision is Decision.DENY
        [event] = self._events(stream)
        assert event["decision"] == "deny"
        assert event["reason_id"] == "plugin:deny-tool"

    # R13 scenario: plugin cannot pre-empt a built-in decision
    def test_plugin_cannot_preempt_builtin_deny(self):
        from tollbooth.policy import Decision, Rule

        deny_rule = Rule(name="no-deploy", action="deny", server="fs", tool="deploy")
        pipeline, stream = self._pipeline(
            [spec("tests.plugin_samples:allow_all")], rules=[deny_rule]
        )
        result = pipeline.evaluate_request(self._call("deploy"))
        assert result.decision is Decision.DENY
        assert result.rule_name == "no-deploy"
        [event] = self._events(stream)
        assert event["reason_id"] == "no-deploy"

    # R13 scenario: result plugin edits flow through with audit
    def test_result_plugin_edit_reaches_client_and_audit(self):
        from tollbooth.policy import Decision

        pipeline, stream = self._pipeline(
            [spec("tests.plugin_samples:redact_word", word="hunter2")]
        )
        verdict = pipeline.process_result(self._call(), "pw is hunter2 ok")
        assert verdict.decision is Decision.ALLOW
        assert verdict.content == "pw is [PLUGIN] ok"
        [event] = self._events(stream)
        assert event["reason_id"] == "redacted:plugin:redact-word"

    def test_result_plugin_block_withholds(self):
        from tollbooth.policy import Decision

        pipeline, _ = self._pipeline(
            [spec("tests.plugin_samples:redact_word", word="hunter2", block=True)]
        )
        verdict = pipeline.process_result(self._call(), "pw is hunter2 ok")
        assert verdict.decision is Decision.DENY
        assert verdict.content is None
        assert "plugin:redact-word" in verdict.message

    # R13 scenario: runtime plugin failure is fail-closed; log carries the
    # plugin name and exception type only (Pattern 11)
    def test_runtime_plugin_failure_fails_closed(self, caplog):
        from tollbooth.policy import Decision

        pipeline, stream = self._pipeline([spec("tests.plugin_samples:crashy")])
        with caplog.at_level("ERROR"):
            result = pipeline.evaluate_request(self._call())
            verdict = pipeline.process_result(self._call(), "content")
        assert result.decision is Decision.DENY
        assert verdict.decision is Decision.DENY
        assert SENTINEL not in caplog.text
        assert SENTINEL not in stream.getvalue()
        assert "crashy" in caplog.text

    # pipeline.py reviewer note (M4): multiple naming allows aggregate in
    # chain order instead of last-writer-wins
    def test_allow_reasons_aggregate_in_chain_order(self):
        from tollbooth.policy import Decision, Rule

        allow_rule = Rule(name="allow-deploy", action="allow", server="fs", tool="deploy")
        pipeline, stream = self._pipeline(
            [spec("tests.plugin_samples:allow_all")], rules=[allow_rule]
        )
        result = pipeline.evaluate_request(self._call("deploy"))
        assert result.decision is Decision.ALLOW
        assert result.rule_name == "allow-deploy,plugin:allow-all"
        [event] = self._events(stream)
        assert event["reason_id"] == "allow-deploy,plugin:allow-all"
