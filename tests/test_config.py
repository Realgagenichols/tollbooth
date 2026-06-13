"""Tests for R3 scenarios: single-file gateway configuration."""

import pytest

from tollbooth.config import (
    ConfigError,
    HttpUpstreamConfig,
    StdioUpstreamConfig,
    emit_client_config,
    load_config,
)

VALID_CONFIG = """
servers:
  fs:
    command: fake-fs-server
    args: ["--root", "/tmp"]
    env:
      LOG_LEVEL: info
  github:
    command: fake-github-server
policy:
  default: deny
  failure_mode: closed
  rules:
    - name: allow-reads
      action: allow
      server: fs
      tool: read_file
    - name: block-writes-outside-project
      action: deny
      server: fs
      tool: write_file
      where:
        path:
          not_prefix: /tmp
"""


def write_config(tmp_path, text):
    path = tmp_path / "tollbooth.yaml"
    path.write_text(text, encoding="utf-8")
    return path


class TestLoadConfig:
    # R3 scenario: load config and launch upstreams (loading half; launch in proxy tests)
    def test_valid_config_loads_servers_and_rules(self, tmp_path):
        config = load_config(write_config(tmp_path, VALID_CONFIG))
        assert set(config.servers) == {"fs", "github"}
        assert config.servers["fs"].command == "fake-fs-server"
        assert config.servers["fs"].args == ["--root", "/tmp"]
        assert config.servers["fs"].env == {"LOG_LEVEL": "info"}
        assert config.servers["github"].args == []
        assert [r.name for r in config.policy.rules] == [
            "allow-reads",
            "block-writes-outside-project",
        ]
        assert config.policy.default == "deny"
        assert config.policy.failure_mode == "closed"

    def test_defaults_are_allow_and_fail_closed(self, tmp_path):
        config = load_config(write_config(tmp_path, "servers:\n  fs:\n    command: x\n"))
        assert config.policy.default == "allow"
        assert config.policy.failure_mode == "closed"
        assert config.policy.rules == []

    # R3 scenario: invalid config — undefined server referenced in a rule
    def test_rule_referencing_undefined_server_rejected(self, tmp_path):
        bad = VALID_CONFIG.replace("server: fs", "server: nope", 1)
        with pytest.raises(ConfigError, match="nope"):
            load_config(write_config(tmp_path, bad))

    # R3 scenario: invalid config — invalid regex (fail at load, not at match time)
    def test_invalid_regex_rejected(self, tmp_path):
        bad = VALID_CONFIG.replace("not_prefix: /tmp", 'regex: "[unclosed"')
        with pytest.raises(ConfigError, match="regex"):
            load_config(write_config(tmp_path, bad))

    # R3 scenario: invalid config — malformed YAML
    def test_malformed_yaml_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="YAML"):
            load_config(write_config(tmp_path, "servers: [unclosed"))

    def test_missing_file_rejected(self, tmp_path):
        with pytest.raises(ConfigError, match="No such"):
            load_config(tmp_path / "absent.yaml")

    def test_matcher_with_multiple_operators_rejected(self, tmp_path):
        bad = VALID_CONFIG.replace(
            "not_prefix: /tmp", 'not_prefix: /tmp\n          equals: "x"'
        )
        with pytest.raises(ConfigError, match="exactly one"):
            load_config(write_config(tmp_path, bad))

    def test_unknown_action_rejected(self, tmp_path):
        bad = VALID_CONFIG.replace("action: deny", "action: explode")
        with pytest.raises(ConfigError):
            load_config(write_config(tmp_path, bad))

    @pytest.mark.regression
    def test_validation_error_never_echoes_secret_values(self, tmp_path):
        """A typo'd key next to a secret must not leak the secret into the error."""
        bad = """
servers:
  gh:
    command: gh-server
    envv:
      GITHUB_TOKEN: ghp_supersecret123
"""
        with pytest.raises(ConfigError) as excinfo:
            load_config(write_config(tmp_path, bad))
        message = str(excinfo.value)
        assert "ghp_supersecret123" not in message
        # Location stays actionable: names the server and the offending field.
        assert "gh" in message and "envv" in message

    @pytest.mark.regression
    def test_yaml_error_never_echoes_source_snippet(self, tmp_path):
        """PyYAML marks embed the offending source line — secrets must not leak."""
        bad = "servers:\n  gh:\n    command: x\n    env: {GITHUB_TOKEN: ghp_yamlsecret456\n"
        with pytest.raises(ConfigError, match="YAML") as excinfo:
            load_config(write_config(tmp_path, bad))
        message = str(excinfo.value)
        assert "ghp_yamlsecret456" not in message
        assert "line " in message  # coordinates stay actionable


class TestEmitClientConfig:
    # R3 scenario: emit client config
    def test_emit_single_tollbooth_entry(self, tmp_path):
        path = write_config(tmp_path, VALID_CONFIG)
        client = emit_client_config(path)
        assert set(client["mcpServers"]) == {"tollbooth"}
        entry = client["mcpServers"]["tollbooth"]
        assert entry["command"].endswith("tollbooth")
        assert entry["args"] == ["run", "-c", str(path.resolve())]

    @pytest.mark.regression
    def test_emitted_command_is_absolute_when_running_from_venv(self, monkeypatch, tmp_path):
        """MCP clients have a minimal PATH: emit the real binary path, not a bare name."""
        fake_bin = tmp_path / "tollbooth"
        fake_bin.touch()
        monkeypatch.setattr("sys.argv", [str(fake_bin)])
        path = write_config(tmp_path, VALID_CONFIG)
        command = emit_client_config(path)["mcpServers"]["tollbooth"]["command"]
        assert command == str(fake_bin.resolve())


class TestDlpConfig:
    """R6/R7: the dlp: section — defaults, overrides, validation."""

    def test_dlp_defaults_when_section_absent(self, tmp_path):
        config = load_config(write_config(tmp_path, VALID_CONFIG))
        assert config.dlp.enabled is True
        assert config.dlp.overrides == {}
        assert config.dlp.request_overrides() == {}
        assert config.dlp.result_overrides() == {}

    def test_overrides_parsed_per_direction(self, tmp_path):
        text = VALID_CONFIG + (
            "dlp:\n"
            "  overrides:\n"
            "    private-key-pem:\n"
            "      results: block\n"
            "    us-phone:\n"
            "      requests: allow\n"
            "      results: allow\n"
        )
        config = load_config(write_config(tmp_path, text))
        assert config.dlp.request_overrides() == {"us-phone": "allow"}
        assert config.dlp.result_overrides() == {
            "private-key-pem": "block",
            "us-phone": "allow",
        }

    def test_dlp_can_be_disabled_explicitly(self, tmp_path):
        config = load_config(write_config(tmp_path, VALID_CONFIG + "dlp:\n  enabled: false\n"))
        assert config.dlp.enabled is False

    # R3 scenario (invalid config) applied to the dlp section
    def test_unknown_pattern_id_rejected_at_startup(self, tmp_path):
        text = VALID_CONFIG + "dlp:\n  overrides:\n    not-a-pattern:\n      results: block\n"
        with pytest.raises(ConfigError, match="unknown DLP pattern id"):
            load_config(write_config(tmp_path, text))

    def test_invalid_action_rejected_at_startup(self, tmp_path):
        text = VALID_CONFIG + "dlp:\n  overrides:\n    pan:\n      requests: redact\n"
        with pytest.raises(ConfigError, match="pan"):
            load_config(write_config(tmp_path, text))


class TestAuditConfig:
    """R10: the audit: block — log path, record mode, audit_log back-compat."""

    def test_defaults_metadata_and_no_log(self, tmp_path):
        config = load_config(write_config(tmp_path, VALID_CONFIG))
        assert config.audit.log is None
        assert config.audit.record == "metadata"

    def test_audit_block_parsed(self, tmp_path):
        text = VALID_CONFIG + "audit:\n  log: /tmp/audit.jsonl\n  record: full\n"
        config = load_config(write_config(tmp_path, text))
        assert config.audit.log == "/tmp/audit.jsonl"
        assert config.audit.record == "full"

    def test_legacy_audit_log_normalizes_into_audit_block(self, tmp_path):
        text = VALID_CONFIG + "audit_log: /tmp/audit.jsonl\n"
        config = load_config(write_config(tmp_path, text))
        assert config.audit.log == "/tmp/audit.jsonl"
        assert config.audit.record == "metadata"

    def test_both_audit_log_and_audit_block_rejected(self, tmp_path):
        text = VALID_CONFIG + (
            "audit_log: /tmp/a.jsonl\naudit:\n  log: /tmp/b.jsonl\n"
        )
        with pytest.raises(ConfigError, match="audit"):
            load_config(write_config(tmp_path, text))

    # lessons: enum-like string options raise on unknown values at load
    def test_typoed_record_mode_rejected_at_startup(self, tmp_path):
        text = VALID_CONFIG + "audit:\n  record: ful\n"
        with pytest.raises(ConfigError, match="record"):
            load_config(write_config(tmp_path, text))


class TestPluginsConfig:
    """R13: config-declared plugin import specs."""

    PLUGINS = VALID_CONFIG + (
        "plugins:\n"
        "  - plugin: tests.plugin_samples:deny_tool\n"
        "    settings:\n"
        "      tool: deploy\n"
    )

    def test_plugins_section_parses(self, tmp_path):
        config = load_config(write_config(tmp_path, self.PLUGINS))
        assert [p.plugin for p in config.plugins] == ["tests.plugin_samples:deny_tool"]
        assert config.plugins[0].settings == {"tool": "deploy"}

    def test_plugins_default_empty(self, tmp_path):
        config = load_config(write_config(tmp_path, VALID_CONFIG))
        assert config.plugins == []

    # R13 scenario: broken plugin aborts startup (spec-shape half: a plugin
    # entry that can't be an import spec fails at config validation)
    def test_bad_import_spec_rejected(self, tmp_path):
        bad = self.PLUGINS.replace("tests.plugin_samples:deny_tool", "no-colon-here")
        with pytest.raises(ConfigError, match="import spec"):
            load_config(write_config(tmp_path, bad))

    def test_unknown_plugin_keys_rejected(self, tmp_path):
        bad = self.PLUGINS.replace("settings:", "setings:")
        with pytest.raises(ConfigError, match="setings"):
            load_config(write_config(tmp_path, bad))


class TestServerClassification:
    """N1: presence-based stdio (`command`) vs http (`url`) classification."""

    def test_command_entry_is_stdio(self, tmp_path):
        cfg = "servers:\n  fs:\n    command: fake-fs-server\n"
        config = load_config(write_config(tmp_path, cfg))
        assert isinstance(config.servers["fs"], StdioUpstreamConfig)

    def test_url_entry_is_http(self, tmp_path):
        cfg = (
            "servers:\n  remote:\n"
            "    url: https://api.example.com/mcp\n"
            "    headers:\n      Authorization: Bearer ${REMOTE_TOKEN}\n"
        )
        config = load_config(write_config(tmp_path, cfg))
        remote = config.servers["remote"]
        assert isinstance(remote, HttpUpstreamConfig)
        assert remote.url == "https://api.example.com/mcp"
        assert remote.headers == {"Authorization": "Bearer ${REMOTE_TOKEN}"}

    def test_mixed_stdio_and_http(self, tmp_path):
        cfg = (
            "servers:\n"
            "  fs:\n    command: fake-fs-server\n"
            "  remote:\n    url: http://localhost:9000/mcp\n"
        )
        config = load_config(write_config(tmp_path, cfg))
        assert isinstance(config.servers["fs"], StdioUpstreamConfig)
        assert isinstance(config.servers["remote"], HttpUpstreamConfig)

    def test_entry_with_neither_rejected(self, tmp_path):
        cfg = "servers:\n  bad:\n    args: ['--x']\n"
        with pytest.raises(ConfigError, match="bad.*either 'command'.*or 'url'"):
            load_config(write_config(tmp_path, cfg))

    def test_entry_with_both_rejected(self, tmp_path):
        cfg = "servers:\n  bad:\n    command: x\n    url: http://localhost/mcp\n"
        with pytest.raises(ConfigError, match="bad.*both 'command'.*'url'"):
            load_config(write_config(tmp_path, cfg))

    def test_non_http_scheme_rejected(self, tmp_path):
        cfg = "servers:\n  bad:\n    url: ftp://example.com/mcp\n"
        with pytest.raises(ConfigError, match="scheme must be http"):
            load_config(write_config(tmp_path, cfg))

    def test_malformed_env_ref_in_header_rejected(self, tmp_path):
        cfg = (
            "servers:\n  remote:\n"
            "    url: https://api.example.com/mcp\n"
            "    headers:\n      Authorization: 'Bearer ${BROKEN'\n"
        )
        with pytest.raises(ConfigError, match="malformed"):
            load_config(write_config(tmp_path, cfg))

    def test_http_classification_error_never_echoes_header_secret(self, tmp_path):
        """A bad url next to a secret header must not leak the secret."""
        cfg = (
            "servers:\n  remote:\n"
            "    url: ftp://example.com/mcp\n"
            "    headers:\n      Authorization: Bearer ghp_httpsecret789\n"
        )
        with pytest.raises(ConfigError) as excinfo:
            load_config(write_config(tmp_path, cfg))
        assert "ghp_httpsecret789" not in str(excinfo.value)
