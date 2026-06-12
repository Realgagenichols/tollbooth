"""Tests for R3 scenarios: single-file gateway configuration."""

import pytest

from tollbooth.config import ConfigError, emit_client_config, load_config

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
        assert "servers.gh.envv" in message  # location stays actionable


class TestEmitClientConfig:
    # R3 scenario: emit client config
    def test_emit_single_tollbooth_entry(self, tmp_path):
        path = write_config(tmp_path, VALID_CONFIG)
        client = emit_client_config(path)
        assert set(client["mcpServers"]) == {"tollbooth"}
        entry = client["mcpServers"]["tollbooth"]
        assert entry["command"] == "tollbooth"
        assert entry["args"] == ["run", "-c", str(path.resolve())]
