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
        assert "dlp=on" in out  # R6: DLP defaults to enabled

    def test_validate_reports_dlp_off(self, monkeypatch, capsys, tmp_path):
        path = tmp_path / "tollbooth.yaml"
        path.write_text(GOOD_CONFIG + "dlp:\n  enabled: false\n", encoding="utf-8")
        run_cli(monkeypatch, "validate", "-c", str(path))
        assert "dlp=off" in capsys.readouterr().out

    # R3 scenario: invalid config — clear error, exit 2 (config-error contract)
    def test_bad_config_exits_two_with_clear_error(self, monkeypatch, capsys, bad_config):
        code = run_cli(monkeypatch, "validate", "-c", str(bad_config))
        assert code == 2
        err = capsys.readouterr().err
        assert "YAML" in err

    def test_missing_file_exits_two(self, monkeypatch, capsys, tmp_path):
        code = run_cli(monkeypatch, "validate", "-c", str(tmp_path / "nope.yaml"))
        assert code == 2


class TestEmitConfig:
    # R3 scenario: emit client config
    def test_emits_single_tollbooth_entry_as_json(self, monkeypatch, capsys, good_config):
        code = run_cli(monkeypatch, "emit-config", "-c", str(good_config))
        assert code == 0
        emitted = json.loads(capsys.readouterr().out)
        assert set(emitted["mcpServers"]) == {"tollbooth"}
        assert emitted["mcpServers"]["tollbooth"]["command"].endswith("tollbooth")
        assert emitted["mcpServers"]["tollbooth"]["args"] == [
            "run",
            "-c",
            str(good_config.resolve()),
        ]

    def test_invalid_config_not_emitted(self, monkeypatch, capsys, bad_config):
        code = run_cli(monkeypatch, "emit-config", "-c", str(bad_config))
        assert code == 2
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
        # DLP is on by default: policy first, then the request scanner (R7).
        policy, dlp_request = gateway.pipeline.request_interceptors
        assert policy.default is Decision.DENY
        assert [r.name for r in policy.rules] == ["allow-reads"]
        assert dlp_request.name == "dlp-request"
        [dlp_result] = gateway.pipeline.result_interceptors
        assert dlp_result.name == "dlp-result"
        assert gateway.pipeline.audit is not None

    def test_build_gateway_without_dlp_when_disabled(self, tmp_path):
        import io

        from tollbooth.config import load_config
        from tollbooth.main import build_gateway

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(GOOD_CONFIG + "dlp:\n  enabled: false\n", encoding="utf-8")
        gateway = build_gateway(load_config(config_path), audit_stream=io.StringIO())
        [policy] = gateway.pipeline.request_interceptors
        assert policy.name == "policy"
        assert gateway.pipeline.result_interceptors == []

    def test_build_gateway_passes_dlp_overrides(self, tmp_path):
        import io

        from tollbooth.config import load_config
        from tollbooth.main import build_gateway

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(
            GOOD_CONFIG + "dlp:\n  overrides:\n    private-key-pem:\n      results: block\n",
            encoding="utf-8",
        )
        gateway = build_gateway(load_config(config_path), audit_stream=io.StringIO())
        [dlp_result] = gateway.pipeline.result_interceptors
        assert dlp_result.overrides == {"private-key-pem": "block"}

    def test_audit_log_config_field_accepted(self, tmp_path):
        from tollbooth.config import load_config

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(
            GOOD_CONFIG + f"audit_log: {tmp_path / 'audit.jsonl'}\n", encoding="utf-8"
        )
        config = load_config(config_path)
        assert config.audit_log == str(tmp_path / "audit.jsonl")

    def test_audit_stream_opens_file_append(self, tmp_path):
        from contextlib import ExitStack

        from tollbooth.config import GatewayConfig
        from tollbooth.main import _open_audit_stream

        path = tmp_path / "audit.jsonl"
        config = GatewayConfig.model_validate(
            {"servers": {"fs": {"command": "x"}}, "audit_log": str(path)}
        )
        with ExitStack() as stack:
            stream = _open_audit_stream(config, stack)
            assert stream.mode == "a"
        assert stream.closed  # ExitStack owns the handle

    def test_unwritable_audit_log_is_config_error(self, tmp_path):
        from contextlib import ExitStack

        from tollbooth.config import ConfigError, GatewayConfig
        from tollbooth.main import _open_audit_stream

        config = GatewayConfig.model_validate(
            {
                "servers": {"fs": {"command": "x"}},
                "audit_log": str(tmp_path / "no-such-dir" / "audit.jsonl"),
            }
        )
        with ExitStack() as stack, pytest.raises(ConfigError, match="audit log"):
            _open_audit_stream(config, stack)


class TestImport:
    """S2: bootstrap tollbooth.yaml from an existing MCP client config."""

    CLIENT_CONFIG = {
        "mcpServers": {
            "fs": {"command": "fs-server", "args": ["--root", "/tmp"]},
            "github": {"command": "gh-server", "env": {"GITHUB_TOKEN": "tok_import_test"}},
        }
    }

    def write_client_config(self, tmp_path, data=None):
        path = tmp_path / "claude_desktop_config.json"
        path.write_text(json.dumps(data or self.CLIENT_CONFIG), encoding="utf-8")
        return path

    # S2 scenario: import from mcp.json — both servers become upstreams,
    # permissive starter ruleset, and the file round-trips through validate
    def test_import_two_servers_round_trips(self, monkeypatch, capsys, tmp_path):
        from tollbooth.config import load_config
        from tollbooth.policy import Decision

        client = self.write_client_config(tmp_path)
        out = tmp_path / "tollbooth.yaml"
        code = run_cli(monkeypatch, "import", str(client), "-o", str(out))
        assert code == 0
        assert "2 upstream server(s)" in capsys.readouterr().out

        config = load_config(out)  # round-trip: generated file validates
        assert set(config.servers) == {"fs", "github"}
        assert config.servers["fs"].args == ["--root", "/tmp"]
        assert config.servers["github"].env == {"GITHUB_TOKEN": "tok_import_test"}
        assert config.policy.default is Decision.ALLOW
        assert config.policy.rules == []
        assert config.dlp.enabled is True

    def test_import_vscode_servers_key(self, monkeypatch, tmp_path):
        from tollbooth.config import load_config

        client = self.write_client_config(
            tmp_path, {"servers": {"fs": {"command": "fs-server"}}}
        )
        out = tmp_path / "out.yaml"
        assert run_cli(monkeypatch, "import", str(client), "-o", str(out)) == 0
        assert set(load_config(out).servers) == {"fs"}

    def test_non_stdio_entries_skipped_with_notice(self, monkeypatch, capsys, tmp_path):
        client = self.write_client_config(
            tmp_path,
            {
                "mcpServers": {
                    "fs": {"command": "fs-server"},
                    "remote": {"url": "https://example.com/mcp"},
                }
            },
        )
        out = tmp_path / "out.yaml"
        assert run_cli(monkeypatch, "import", str(client), "-o", str(out)) == 0
        captured = capsys.readouterr()
        assert "1 upstream server(s)" in captured.out
        assert "skipped 'remote'" in captured.err

    # S2/R3: malformed input — clear error, no raw exception interpolation
    def test_malformed_json_clear_error(self, monkeypatch, capsys, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text('{"mcpServers": {token_here', encoding="utf-8")
        out = tmp_path / "out.yaml"
        code = run_cli(monkeypatch, "import", str(path), "-o", str(out))
        assert code == 2
        err = capsys.readouterr().err
        assert "malformed JSON" in err
        assert "token_here" not in err  # coordinates only, never source content
        assert not out.exists()

    def test_empty_or_missing_servers_rejected(self, monkeypatch, capsys, tmp_path):
        client = self.write_client_config(tmp_path, {"mcpServers": {}})
        code = run_cli(monkeypatch, "import", str(client), "-o", str(tmp_path / "o.yaml"))
        assert code == 2
        assert "no MCP servers" in capsys.readouterr().err

    def test_refuses_to_overwrite_existing_output(self, monkeypatch, capsys, tmp_path):
        client = self.write_client_config(tmp_path)
        out = tmp_path / "tollbooth.yaml"
        out.write_text("# precious existing config\n", encoding="utf-8")
        code = run_cli(monkeypatch, "import", str(client), "-o", str(out))
        assert code == 2
        assert "refusing to overwrite" in capsys.readouterr().err
        assert out.read_text() == "# precious existing config\n"

    # Section-4 review C1: malformed SHAPE (valid JSON) must produce a clean
    # exit-2 error that never echoes input values (pydantic input_value leak).
    @pytest.mark.regression
    def test_malformed_shape_never_echoes_values(self, monkeypatch, capsys, tmp_path):
        client = self.write_client_config(
            tmp_path,
            {"mcpServers": {"fs": {"command": "fs-server", "args": "--token sk_live_LEAK"}}},
        )
        out = tmp_path / "out.yaml"
        code = run_cli(monkeypatch, "import", str(client), "-o", str(out))
        assert code == 2
        captured = capsys.readouterr()
        assert "sk_live_LEAK" not in captured.err + captured.out
        assert "args" in captured.err  # location stays actionable
        assert not out.exists()

    # Section-4 review W1: unwritable output is a clean config error, not a traceback
    @pytest.mark.regression
    def test_unwritable_output_clear_error(self, monkeypatch, capsys, tmp_path):
        client = self.write_client_config(tmp_path)
        out = tmp_path / "no-such-dir" / "out.yaml"
        code = run_cli(monkeypatch, "import", str(client), "-o", str(out))
        assert code == 2
        assert "cannot write" in capsys.readouterr().err

    def test_output_file_is_owner_only(self, monkeypatch, tmp_path):
        # The generated file may carry env-block secrets from the client config.
        client = self.write_client_config(tmp_path)
        out = tmp_path / "out.yaml"
        run_cli(monkeypatch, "import", str(client), "-o", str(out))
        assert (out.stat().st_mode & 0o777) == 0o600

    def test_empty_mcpservers_falls_back_to_servers_key(self, monkeypatch, tmp_path):
        from tollbooth.config import load_config

        client = self.write_client_config(
            tmp_path, {"mcpServers": {}, "servers": {"fs": {"command": "fs-server"}}}
        )
        out = tmp_path / "out.yaml"
        assert run_cli(monkeypatch, "import", str(client), "-o", str(out)) == 0
        assert set(load_config(out).servers) == {"fs"}
