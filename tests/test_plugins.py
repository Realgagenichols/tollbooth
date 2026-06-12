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
