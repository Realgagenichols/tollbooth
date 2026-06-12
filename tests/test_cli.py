"""Tests for R3 CLI scenarios: validate and emit-config."""

import json

import pytest

from tollbooth.main import main

GOOD_CONFIG = """
servers:
  fs:
    command: fake-fs-server
policy:
  default: deny
  rules:
    - name: allow-reads
      action: allow
      server: fs
      tool: read_file
"""


def run_cli(monkeypatch, *argv):
    monkeypatch.setattr("sys.argv", ["tollbooth", *argv])
    try:
        main()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


@pytest.fixture
def good_config(tmp_path):
    path = tmp_path / "tollbooth.yaml"
    path.write_text(GOOD_CONFIG, encoding="utf-8")
    return path


@pytest.fixture
def bad_config(tmp_path):
    path = tmp_path / "tollbooth.yaml"
    path.write_text("servers: [broken", encoding="utf-8")
    return path


class TestValidate:
    def test_good_config_exits_zero(self, monkeypatch, capsys, good_config):
        code = run_cli(monkeypatch, "validate", "-c", str(good_config))
        assert code == 0
        out = capsys.readouterr().out
        assert "OK" in out

    # R3 scenario: invalid config — clear error, nonzero exit
    def test_bad_config_exits_nonzero_with_clear_error(self, monkeypatch, capsys, bad_config):
        code = run_cli(monkeypatch, "validate", "-c", str(bad_config))
        assert code != 0
        err = capsys.readouterr().err
        assert "YAML" in err

    def test_missing_file_exits_nonzero(self, monkeypatch, capsys, tmp_path):
        code = run_cli(monkeypatch, "validate", "-c", str(tmp_path / "nope.yaml"))
        assert code != 0


class TestEmitConfig:
    # R3 scenario: emit client config
    def test_emits_single_tollbooth_entry_as_json(self, monkeypatch, capsys, good_config):
        code = run_cli(monkeypatch, "emit-config", "-c", str(good_config))
        assert code == 0
        emitted = json.loads(capsys.readouterr().out)
        assert set(emitted["mcpServers"]) == {"tollbooth"}
        assert emitted["mcpServers"]["tollbooth"]["args"] == [
            "run",
            "-c",
            str(good_config.resolve()),
        ]

    def test_invalid_config_not_emitted(self, monkeypatch, capsys, bad_config):
        code = run_cli(monkeypatch, "emit-config", "-c", str(bad_config))
        assert code != 0
        assert capsys.readouterr().out == ""  # nothing emitted on error


class TestRunWiring:
    def test_build_gateway_wires_config(self, tmp_path):
        """run's builder: rules, default, failure_mode, audit stream all wired."""
        import io

        from tollbooth.config import load_config
        from tollbooth.main import build_gateway
        from tollbooth.policy import Decision

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(
            GOOD_CONFIG.replace("default: deny", "default: deny\n  failure_mode: open"),
            encoding="utf-8",
        )
        config = load_config(config_path)
        gateway = build_gateway(config, audit_stream=io.StringIO())
        assert set(gateway.upstreams) == {"fs"}
        assert gateway.pipeline.fail_open is True
        [policy] = gateway.pipeline.request_interceptors
        assert policy.default is Decision.DENY
        assert [r.name for r in policy.rules] == ["allow-reads"]
        assert gateway.pipeline.audit is not None

    def test_audit_log_config_field_accepted(self, tmp_path):
        from tollbooth.config import load_config

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(
            GOOD_CONFIG + f"audit_log: {tmp_path / 'audit.jsonl'}\n", encoding="utf-8"
        )
        config = load_config(config_path)
        assert config.audit_log == str(tmp_path / "audit.jsonl")
