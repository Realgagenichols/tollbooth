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


OAUTH_CONFIG = """
servers:
  remote:
    url: https://mcp.example.com/mcp
    auth:
      type: oauth
"""


@pytest.fixture
def oauth_config(tmp_path):
    path = tmp_path / "tollbooth.yaml"
    path.write_text(OAUTH_CONFIG, encoding="utf-8")
    return path


def _seed_token(name, access="SECRET-AT", refresh="SECRET-RT"):
    import anyio
    from mcp.shared.auth import OAuthToken

    from tollbooth.oauth import FileTokenStorage

    async def _seed():
        await FileTokenStorage(name).set_tokens(
            OAuthToken(
                access_token=access, token_type="Bearer", expires_in=3600,
                refresh_token=refresh,
            )
        )

    anyio.run(_seed)


class TestAuthCli:
    def test_status_reports_not_authenticated(self, monkeypatch, capsys, oauth_config, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        code = run_cli(monkeypatch, "auth", "status", "-c", str(oauth_config))
        assert code == 0
        assert "not authenticated" in capsys.readouterr().out

    def test_status_lists_stored_token_without_values(
        self, monkeypatch, capsys, oauth_config, tmp_path
    ):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _seed_token("remote")
        code = run_cli(monkeypatch, "auth", "status", "-c", str(oauth_config))
        out = capsys.readouterr().out
        assert code == 0
        assert "token stored" in out
        assert "SECRET-AT" not in out and "SECRET-RT" not in out

    def test_status_no_oauth_servers(self, monkeypatch, capsys, good_config, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        code = run_cli(monkeypatch, "auth", "status", "-c", str(good_config))
        assert code == 0
        assert "No OAuth-configured upstreams" in capsys.readouterr().out

    def test_logout_removes_then_reports_absent(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _seed_token("remote")
        code = run_cli(monkeypatch, "auth", "logout", "remote")
        assert code == 0
        assert "removed" in capsys.readouterr().out
        run_cli(monkeypatch, "auth", "logout", "remote")
        assert "no stored credentials" in capsys.readouterr().out

    def test_login_unknown_server_errors(self, monkeypatch, capsys, oauth_config):
        code = run_cli(monkeypatch, "auth", "login", "ghost", "-c", str(oauth_config))
        assert code == 2
        assert "no server named 'ghost'" in capsys.readouterr().err

    def test_login_non_oauth_server_errors(self, monkeypatch, capsys, good_config):
        code = run_cli(monkeypatch, "auth", "login", "fs", "-c", str(good_config))
        assert code == 2
        assert "not an OAuth HTTP upstream" in capsys.readouterr().err

    def test_validate_oauth_config_needs_no_token_or_network(
        self, monkeypatch, capsys, oauth_config, tmp_path
    ):
        """N2: validate stays disk/env-independent — no token on disk required."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "empty-xdg"))
        code = run_cli(monkeypatch, "validate", "-c", str(oauth_config))
        assert code == 0
        assert "OK" in capsys.readouterr().out

    def test_status_never_prints_token_values_sweep(
        self, monkeypatch, capsys, oauth_config, tmp_path
    ):
        """N2 secret hygiene: status output never contains token values."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
        _seed_token("remote", access="AT-SENTINEL-XYZ", refresh="RT-SENTINEL-XYZ")
        run_cli(monkeypatch, "auth", "status", "-c", str(oauth_config))
        run_cli(monkeypatch, "auth", "logout", "remote")
        combined = capsys.readouterr().out
        assert "AT-SENTINEL-XYZ" not in combined
        assert "RT-SENTINEL-XYZ" not in combined


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


class TestAuditWiring:
    def test_build_gateway_passes_record_mode(self, tmp_path):
        import io

        from tollbooth.config import load_config
        from tollbooth.main import build_gateway

        config_path = tmp_path / "tollbooth.yaml"
        config_path.write_text(
            "servers:\n  fs:\n    command: /bin/echo\naudit:\n  record: full\n",
            encoding="utf-8",
        )
        gateway = build_gateway(load_config(config_path), audit_stream=io.StringIO())
        assert gateway.pipeline.audit.records_content is True


class TestAuditVerify:
    """R8: `tollbooth audit verify` validates the chain from the CLI."""

    @staticmethod
    def _write_log(path, n=3, key=None):
        from tollbooth.audit import AuditLogger

        with open(path, "w", encoding="utf-8") as handle:
            logger = AuditLogger(handle, key=key)
            for i in range(n):
                logger.decision(
                    path="request",
                    server="s",
                    tool=f"t{i}",
                    decision="allow",
                    reason_id=None,
                )
        return path

    def test_intact_log_reports_ok_with_head(self, monkeypatch, capsys, tmp_path):
        log = self._write_log(tmp_path / "audit.jsonl")
        monkeypatch.delenv("TOLLBOOTH_AUDIT_KEY", raising=False)
        code = run_cli(monkeypatch, "audit", "verify", "--log", str(log))
        assert code == 0
        out = capsys.readouterr().out
        assert "OK: 3 event(s)" in out
        assert "seq=2" in out
        assert "mode=sha256" in out

    def test_tampered_log_exits_one_without_echo(self, monkeypatch, capsys, tmp_path):
        log = self._write_log(tmp_path / "audit.jsonl")
        lines = log.read_text(encoding="utf-8").splitlines()
        lines[0] = lines[0].replace('"t0"', '"sentinel-tamper"')
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        monkeypatch.delenv("TOLLBOOTH_AUDIT_KEY", raising=False)
        code = run_cli(monkeypatch, "audit", "verify", "--log", str(log))
        assert code == 1
        err = capsys.readouterr().err
        assert "line 2" in err  # break surfaces at the next link
        assert "sentinel-tamper" not in err

    def test_keyed_log_verifies_with_env_key(self, monkeypatch, capsys, tmp_path):
        log = self._write_log(tmp_path / "audit.jsonl", key=b"k3y")
        monkeypatch.setenv("TOLLBOOTH_AUDIT_KEY", "k3y")
        code = run_cli(monkeypatch, "audit", "verify", "--log", str(log))
        assert code == 0
        assert "mode=hmac-sha256" in capsys.readouterr().out

    def test_missing_log_exits_one(self, monkeypatch, capsys, tmp_path):
        monkeypatch.delenv("TOLLBOOTH_AUDIT_KEY", raising=False)
        code = run_cli(
            monkeypatch, "audit", "verify", "--log", str(tmp_path / "absent.jsonl")
        )
        assert code == 1
        assert "cannot read" in capsys.readouterr().err


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

    # S2/N1 scenario: a `url` entry imports as an HTTP upstream (with headers),
    # alongside a stdio entry — nothing skipped.
    def test_import_http_server_with_headers(self, monkeypatch, capsys, tmp_path):
        from tollbooth.config import HttpUpstreamConfig, StdioUpstreamConfig, load_config

        client = self.write_client_config(
            tmp_path,
            {
                "mcpServers": {
                    "fs": {"command": "fs-server"},
                    "remote": {
                        "url": "https://example.com/mcp",
                        "headers": {"Authorization": "Bearer ${REMOTE_TOKEN}"},
                    },
                }
            },
        )
        out = tmp_path / "out.yaml"
        assert run_cli(monkeypatch, "import", str(client), "-o", str(out)) == 0
        captured = capsys.readouterr()
        assert "2 upstream server(s)" in captured.out
        assert "skipped" not in captured.err

        config = load_config(out)  # generated file round-trips through validate
        assert isinstance(config.servers["fs"], StdioUpstreamConfig)
        remote = config.servers["remote"]
        assert isinstance(remote, HttpUpstreamConfig)
        assert remote.url == "https://example.com/mcp"
        assert remote.headers == {"Authorization": "Bearer ${REMOTE_TOKEN}"}

    def test_entry_with_neither_command_nor_url_skipped(self, monkeypatch, capsys, tmp_path):
        client = self.write_client_config(
            tmp_path,
            {
                "mcpServers": {
                    "fs": {"command": "fs-server"},
                    "weird": {"note": "no command or url here"},
                }
            },
        )
        out = tmp_path / "out.yaml"
        assert run_cli(monkeypatch, "import", str(client), "-o", str(out)) == 0
        captured = capsys.readouterr()
        assert "1 upstream server(s)" in captured.out
        assert "skipped 'weird'" in captured.err

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


class TestAuditQueryReplay:
    """R11: query and replay from the CLI."""

    @staticmethod
    def _write_log(path, record="metadata"):
        from tollbooth.audit import AuditLogger

        with open(path, "w", encoding="utf-8") as handle:
            logger = AuditLogger(handle, record=record)
            logger.session_start(gateway_version="0.1.0", config_digest="ab" * 32)
            logger.decision(
                path="request", server="fs", tool="read", decision="allow",
                reason_id="allow-reads", call_id="c1",
                args={"path": "/tmp/replay-arg"},
            )
            logger.decision(
                path="request", server="shell", tool="exec", decision="deny",
                reason_id="no-exec", call_id="c2",
            )
        return logger.session_id

    # R11 scenario: query by decision
    def test_query_by_decision_emits_matching_jsonl(self, monkeypatch, capsys, tmp_path):
        log = tmp_path / "audit.jsonl"
        self._write_log(log)
        code = run_cli(
            monkeypatch, "audit", "query", "--log", str(log), "--decision", "deny"
        )
        assert code == 0
        lines = capsys.readouterr().out.splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["tool"] == "exec"

    # R11 scenario: query by time window
    def test_query_by_time_window(self, monkeypatch, capsys, tmp_path):
        log = tmp_path / "audit.jsonl"
        self._write_log(log)
        all_events = [json.loads(ln) for ln in log.read_text().splitlines()]
        since = all_events[2]["ts"]  # last event only
        code = run_cli(
            monkeypatch, "audit", "query", "--log", str(log), "--since", since
        )
        assert code == 0
        lines = capsys.readouterr().out.splitlines()
        assert [json.loads(ln)["tool"] for ln in lines] == ["exec"]

    # R11 scenario: replay a full-record session
    def test_replay_full_session_shows_payloads(self, monkeypatch, capsys, tmp_path):
        log = tmp_path / "audit.jsonl"
        session = self._write_log(log, record="full")
        code = run_cli(monkeypatch, "audit", "replay", session, "--log", str(log))
        assert code == 0
        out = capsys.readouterr().out
        assert "fs/read" in out
        assert "/tmp/replay-arg" in out

    # R11 scenario: replay a metadata-only session
    def test_replay_metadata_session_degrades_gracefully(
        self, monkeypatch, capsys, tmp_path
    ):
        log = tmp_path / "audit.jsonl"
        session = self._write_log(log, record="metadata")
        code = run_cli(monkeypatch, "audit", "replay", session, "--log", str(log))
        assert code == 0
        out = capsys.readouterr().out
        assert "shell/exec" in out
        assert "deny" in out
        assert "/tmp/replay-arg" not in out

    def test_replay_unknown_session_exits_one(self, monkeypatch, capsys, tmp_path):
        log = tmp_path / "audit.jsonl"
        self._write_log(log)
        code = run_cli(monkeypatch, "audit", "replay", "nope", "--log", str(log))
        assert code == 1
        assert "no events" in capsys.readouterr().err


class TestHookCli:
    """R15: hook subcommand and emitted hooks settings."""

    PAYLOAD = '{"session_id": "s", "tool_name": "fs_read", "tool_input": {}}'

    def test_hook_pre_runs_from_argv(self, monkeypatch, capsys, good_config):
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO(self.PAYLOAD))
        code = run_cli(monkeypatch, "hook", "pre", "-c", str(good_config))
        assert code == 0
        # default deny in GOOD_CONFIG + unmatched native tool → deny JSON
        out = json.loads(capsys.readouterr().out)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_hook_post_runs_from_argv(self, monkeypatch, capsys, good_config):
        import io

        payload = self.PAYLOAD[:-1] + ', "tool_response": "clean text"}'
        monkeypatch.setattr("sys.stdin", io.StringIO(payload))
        code = run_cli(monkeypatch, "hook", "post", "-c", str(good_config))
        assert code == 0
        assert capsys.readouterr().out == ""  # clean result: no output

    # R15 scenario: emit hooks settings
    def test_emit_claude_hooks_settings(self, monkeypatch, capsys, good_config):
        code = run_cli(monkeypatch, "emit-config", "--claude-hooks", "-c", str(good_config))
        assert code == 0
        emitted = json.loads(capsys.readouterr().out)
        hooks = emitted["hooks"]
        assert set(hooks) == {"PreToolUse", "PostToolUse"}
        [pre_entry] = hooks["PreToolUse"]
        [hook] = pre_entry["hooks"]
        assert hook["type"] == "command"
        # absolute paths: binary and config (emitted configs must work in
        # the consumer's environment — lessons.md)
        command = hook["command"]
        assert " hook pre -c " in command
        assert str(good_config.resolve()) in command
        [post_entry] = hooks["PostToolUse"]
        assert " hook post -c " in post_entry["hooks"][0]["command"]

    def test_emit_claude_hooks_validates_config_first(self, monkeypatch, capsys, bad_config):
        code = run_cli(monkeypatch, "emit-config", "--claude-hooks", "-c", str(bad_config))
        assert code == 2
        assert capsys.readouterr().out == ""

    def test_paths_with_spaces_are_shell_quoted(self, monkeypatch, capsys, tmp_path):
        spaced = tmp_path / "my configs"
        spaced.mkdir()
        config = spaced / "tollbooth.yaml"
        config.write_text(GOOD_CONFIG, encoding="utf-8")
        run_cli(monkeypatch, "emit-config", "--claude-hooks", "-c", str(config))
        emitted = json.loads(capsys.readouterr().out)
        command = emitted["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        assert "'" in command  # shlex-quoted path survives the shell
