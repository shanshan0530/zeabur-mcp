"""Service-context network probe tests. All Zeabur traffic is mocked."""

from __future__ import annotations

import asyncio
import inspect
import socket
import ssl
from pathlib import Path

import probe_program
import pytest

import graphql_ops
import main
from graphql_ops import MUTATION_DOCUMENTS

from tests.test_phase_a import (
    EXPECTED_REGISTERED,
    PHASE_A_NINE,
    PROBE_ONE,
    READ_ONLY_OPS_TWO,
    WRITE_TWO,
    _tool_names,
)
from tests.test_phase_b import (
    ENV,
    SVC,
    enable_writes,
    operator_ctx,
    read_ctx,
    _record_gql,
)

ROOT = Path(__file__).resolve().parents[1]
HOST = "probe.example"
PUBLIC_IP = "8.8.8.8"
PUBLIC_URL = "https://probe.example/health"


def _ok_output(**extra):
    rows = {
        "status": "OK",
        "dns_ms": "1.0",
        "resolved_ips": PUBLIC_IP,
        "tcp_ms": "2.0",
        "tls_ms": "3.0",
        "total_ms": "6.0",
    }
    rows.update(extra)
    return "".join(f"{k}={v}\n" for k, v in rows.items())


_DEFAULT_CTX = object()


async def _probe(host=HOST, port=443, url=None, ctx=_DEFAULT_CTX):
    return await main.probe_service_network(
        SVC,
        ENV,
        host,
        operator_ctx() if ctx is _DEFAULT_CTX else ctx,
        port,
        url,
    )


def _ok_exec_handler():
    async def handler(query, variables, redact_keys):
        return _exec_payload(_ok_output())

    return handler


def _exec_payload(output, exit_code=0):
    return {graphql_ops.EXECUTE_COMMAND_RESULT_FIELD: {"exitCode": exit_code, "output": output}}


class _FakeSock:
    def __init__(self, chunks=None, recv_exc=None):
        self.chunks = list(chunks or [b"HTTP/1.1 200 OK\r\n\r\n"])
        self.recv_exc = recv_exc
        self.sent = []
        self.closed = False
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        if self.recv_exc:
            raise self.recv_exc
        if not self.chunks:
            return b""
        return self.chunks.pop(0)

    def close(self):
        self.closed = True


class _FakeTLSContext:
    def __init__(self, sock=None, wrap_exc=None):
        self.sock = sock or _FakeSock()
        self.wrap_exc = wrap_exc
        self.wrapped = None

    def wrap_socket(self, sock, server_hostname=None):
        if self.wrap_exc:
            raise self.wrap_exc
        self.wrapped = self.sock
        self.server_hostname = server_hostname
        return self.sock


def test_public_inventory_is_fourteen_and_probe_exists():
    names = _tool_names()
    assert names == EXPECTED_REGISTERED
    assert len(names) == 14
    assert "probe_service_network" in names
    assert PHASE_A_NINE | WRITE_TWO | READ_ONLY_OPS_TWO <= names
    assert PROBE_ONE <= names


def test_execute_command_is_not_public():
    names = _tool_names()
    assert "execute_command" not in names
    assert "executeCommand" not in names
    assert "execute-command" not in names
    tools = {t.name: t for t in asyncio.run(main.mcp.list_tools())}
    assert "execute_command" not in tools
    assert not hasattr(main, "execute_command")


def test_caller_cannot_provide_command_argv_or_script():
    tools = {t.name: t for t in asyncio.run(main.mcp.list_tools())}
    schema = tools["probe_service_network"].inputSchema
    props = schema["properties"]
    assert set(props) == {
        "service_id",
        "environment_id",
        "target_host",
        "target_port",
        "https_url",
    }
    for forbidden in (
        "command",
        "argv",
        "executable",
        "script",
        "shell",
        "file",
        "path",
        "headers",
        "body",
        "ctx",
        "context",
    ):
        assert forbidden not in props
    required = set(schema.get("required") or [])
    assert required == {"service_id", "environment_id", "target_host"}
    sig = inspect.signature(main.probe_service_network)
    assert list(sig.parameters) == [
        "service_id",
        "environment_id",
        "target_host",
        "ctx",
        "target_port",
        "https_url",
    ]
    assert "command" not in sig.parameters
    assert "argv" not in sig.parameters
    assert "script" not in sig.parameters


def test_read_credential_cannot_probe(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(ctx=read_ctx()))
    assert result.startswith("❌")
    assert "OPERATOR" in result
    assert posted == []


def test_operator_required_when_context_missing(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(ctx=None))
    assert result.startswith("❌")
    assert "OPERATOR" in result
    assert posted == []


def test_writes_enabled_required(monkeypatch):
    assert main.MCP_WRITES_ENABLED is False
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(ctx=operator_ctx()))
    assert "MCP_WRITES_ENABLED" in result or "disabled" in result.lower()
    assert posted == []


def test_valid_external_target_reaches_execute_command(monkeypatch):
    enable_writes(monkeypatch)

    posted = _record_gql(monkeypatch, _ok_exec_handler())
    result = asyncio.run(_probe(url=PUBLIC_URL))
    assert "status=OK" in result
    assert len(posted) == 1
    assert posted[0]["query"] == graphql_ops.M_EXECUTE_COMMAND
    assert posted[0]["variables"]["serviceID"] == SVC
    assert posted[0]["variables"]["environmentID"] == ENV
    command = posted[0]["variables"]["command"]
    assert command[0] == "python3"
    assert command[1] == "-c"
    assert command[2] == main.PROBE_PROGRAM_SOURCE
    assert command[3] == HOST
    assert command[4] == "443"
    assert command[5] == PUBLIC_URL


def test_python_program_is_fixed_internal_and_argv_only(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch, _ok_exec_handler())
    host = "ok.example"
    url = "https://ok.example/x?q=1"
    asyncio.run(_probe(host=host, port=8443, url=url))
    command = posted[0]["variables"]["command"]
    assert command[0] in ("python3", "python")
    assert command[1] == "-c"
    assert command[2] == Path(probe_program.__file__).read_text(encoding="utf-8")
    assert probe_program.PROBE_MARKER in command[2]
    assert command[3] == host
    assert command[4] == "8443"
    assert command[5] == url
    assert host not in command[2]
    assert url not in command[2]
    assert "8443" not in command[2]
    assert "sh" not in command
    assert "bash" not in command
    joined = " ".join(command[:2])
    assert "-c" in command
    assert "sh -c" not in joined
    assert "bash -c" not in joined


def test_no_shell_interpolation_of_caller_values(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch, _ok_exec_handler())
    host = "evil.example"
    asyncio.run(_probe(host=host, url="https://evil.example/a"))
    command = posted[0]["variables"]["command"]
    assert command == [
        "python3",
        "-c",
        main.PROBE_PROGRAM_SOURCE,
        "evil.example",
        "443",
        "https://evil.example/a",
    ]
    assert "rm " not in command[2]
    assert "$( " not in command[2]
    source = inspect.getsource(main.probe_service_network)
    assert "f\"python" not in source
    assert "f'python" not in source
    assert "sh -c" not in source
    assert "shell=True" not in source


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST",
        "127.0.0.1",
        "127.1.2.3",
        "[::1]",
        "::1",
        "0.0.0.0",
    ],
)
def test_localhost_rejected_with_zero_mutation(monkeypatch, host):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(host=host))
    assert "INVALID_TARGET" in result
    assert posted == []


@pytest.mark.parametrize("host", ["10.0.0.8", "192.168.1.20", "172.16.5.5"])
def test_private_ipv4_rejected_with_zero_mutation(monkeypatch, host):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(host=host))
    assert "INVALID_TARGET" in result
    assert posted == []


@pytest.mark.parametrize("host", ["fd12:3456::1", "fe80::1", "[fc00::2]"])
def test_private_ipv6_rejected_with_zero_mutation(monkeypatch, host):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(host=host))
    assert "INVALID_TARGET" in result
    assert posted == []


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.com",
    ],
)
def test_metadata_target_rejected_with_zero_mutation(monkeypatch, host):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(host=host))
    assert "INVALID_TARGET" in result
    assert posted == []


def test_hostname_resolving_to_private_ip_is_rejected_before_connect(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", port))]

    connected = []

    def boom(*args, **kwargs):
        connected.append(args)
        raise AssertionError("must not connect after private resolution")

    monkeypatch.setattr(probe_program.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(probe_program.socket, "create_connection", boom)
    cls, text = probe_program.run_probe("rebind.example", 443, None)
    assert cls == probe_program.STATUS_DNS_PRIVATE_TARGET
    assert "DNS_PRIVATE_TARGET" in text
    assert "failed_stage=DNS" in text
    assert "10.1.2.3" in text
    assert connected == []


def test_https_url_host_mismatch_rejected(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(host=HOST, url="https://other.example/path"))
    assert "INVALID_TARGET" in result
    assert "host mismatch" in result
    assert posted == []


def test_non_https_url_rejected(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(host=HOST, url="http://probe.example/path"))
    assert "INVALID_TARGET" in result
    assert "https only" in result
    assert posted == []


def test_https_url_userinfo_rejected(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(_probe(host=HOST, url="https://user:pass@probe.example/"))
    assert "INVALID_TARGET" in result
    assert posted == []


def test_dns_failure_classified(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(probe_program.socket, "getaddrinfo", fail)
    cls, text = probe_program.run_probe(HOST, 443, None)
    assert cls == probe_program.STATUS_DNS_ERROR
    assert "failed_stage=DNS" in text
    assert "error_class=DNS_ERROR" in text
    assert "dns_ms=" in text


def test_tcp_timeout_classified(monkeypatch):
    def addrs(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))]

    def timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(probe_program.socket, "getaddrinfo", addrs)
    monkeypatch.setattr(probe_program.socket, "create_connection", timeout)
    cls, text = probe_program.run_probe(HOST, 443, None)
    assert cls == probe_program.STATUS_TCP_TIMEOUT
    assert "failed_stage=TCP" in text
    assert "error_class=TCP_TIMEOUT" in text
    assert "tcp_ms=" in text


def test_tls_failure_classified(monkeypatch):
    def addrs(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))]

    monkeypatch.setattr(probe_program.socket, "getaddrinfo", addrs)
    monkeypatch.setattr(
        probe_program.socket,
        "create_connection",
        lambda *a, **k: _FakeSock(),
    )
    monkeypatch.setattr(
        probe_program.ssl,
        "create_default_context",
        lambda: _FakeTLSContext(wrap_exc=ssl.SSLError("handshake failed")),
    )
    cls, text = probe_program.run_probe(HOST, 443, None)
    assert cls == probe_program.STATUS_TLS_ERROR
    assert "failed_stage=TLS" in text
    assert "error_class=TLS_ERROR" in text
    assert "tls_ms=" in text


def test_http_timeout_classified(monkeypatch):
    def addrs(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))]

    http_sock = _FakeSock(recv_exc=socket.timeout("timed out"))
    monkeypatch.setattr(probe_program.socket, "getaddrinfo", addrs)
    monkeypatch.setattr(
        probe_program.socket,
        "create_connection",
        lambda *a, **k: _FakeSock(),
    )
    monkeypatch.setattr(
        probe_program.ssl,
        "create_default_context",
        lambda: _FakeTLSContext(sock=http_sock),
    )
    cls, text = probe_program.run_probe(HOST, 443, PUBLIC_URL)
    assert cls == probe_program.STATUS_HTTP_TIMEOUT
    assert "failed_stage=HTTP" in text
    assert "error_class=HTTP_TIMEOUT" in text
    assert "http_ttfb_ms=" in text


def test_http_error_classified(monkeypatch):
    def addrs(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))]

    http_sock = _FakeSock(recv_exc=OSError("reset"))
    monkeypatch.setattr(probe_program.socket, "getaddrinfo", addrs)
    monkeypatch.setattr(
        probe_program.socket,
        "create_connection",
        lambda *a, **k: _FakeSock(),
    )
    monkeypatch.setattr(
        probe_program.ssl,
        "create_default_context",
        lambda: _FakeTLSContext(sock=http_sock),
    )
    cls, text = probe_program.run_probe(HOST, 443, PUBLIC_URL)
    assert cls == probe_program.STATUS_HTTP_ERROR
    assert "failed_stage=HTTP" in text
    assert "error_class=HTTP_ERROR" in text


def test_python3_unavailable_falls_back_to_python(monkeypatch):
    enable_writes(monkeypatch)
    calls = []

    async def handler(query, variables, redact_keys):
        runtime = variables["command"][0]
        calls.append(runtime)
        if runtime == "python3":
            return _exec_payload("python3: not found\n", exit_code=127)
        assert variables["command"][2] == main.PROBE_PROGRAM_SOURCE
        return _exec_payload(_ok_output())

    posted = _record_gql(monkeypatch, handler)
    result = asyncio.run(_probe())
    assert calls == ["python3", "python"]
    assert len(posted) == 2
    assert all(p["query"] == graphql_ops.M_EXECUTE_COMMAND for p in posted)
    assert posted[1]["variables"]["command"][0] == "python"
    assert "status=OK" in result
    assert "runtime=python" in result


def test_both_runtimes_unavailable(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        runtime = variables["command"][0]
        return _exec_payload(f"{runtime}: not found", exit_code=127)

    posted = _record_gql(monkeypatch, handler)
    result = asyncio.run(_probe())
    assert len(posted) == 2
    assert posted[0]["variables"]["command"][0] == "python3"
    assert posted[1]["variables"]["command"][0] == "python"
    assert "PROBE_RUNTIME_UNAVAILABLE" in result
    assert "status=PROBE_RUNTIME_UNAVAILABLE" in result


def test_structured_failure_does_not_trigger_python_fallback(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        return _exec_payload(
            "status=FAILED\nfailed_stage=DNS\nerror_class=DNS_ERROR\n",
            exit_code=1,
        )

    posted = _record_gql(monkeypatch, handler)
    result = asyncio.run(_probe())
    assert len(posted) == 1
    assert posted[0]["variables"]["command"][0] == "python3"
    assert "DNS_ERROR" in result


def test_bounded_output(monkeypatch):
    enable_writes(monkeypatch)
    huge = "status=OK\n" + ("x" * (main.MAX_PROBE_OUTPUT_CHARS + 200))

    async def handler(query, variables, redact_keys):
        return _exec_payload(huge)

    _record_gql(monkeypatch, handler)
    result = asyncio.run(_probe())
    assert "truncated=true" in result
    assert len(result) < len(huge) + 80


def test_existing_two_write_tools_unchanged():
    tools = {t.name: t for t in asyncio.run(main.mcp.list_tools())}
    redeploy = tools["redeploy_service"].inputSchema["properties"]
    assert set(redeploy) == {"service_id", "environment_id", "confirm"}
    env = tools["set_service_env_var"].inputSchema["properties"]
    assert set(env) == {"service_id", "environment_id", "key", "value", "confirm"}
    redeploy_src = inspect.getsource(main.redeploy_service)
    env_src = inspect.getsource(main.set_service_env_var)
    assert "M_REDEPLOY_SERVICE" in redeploy_src
    assert "M_CREATE_ENVIRONMENT_VARIABLE" in env_src
    assert "M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE" in env_src
    assert "M_EXECUTE_COMMAND" not in redeploy_src
    assert "M_EXECUTE_COMMAND" not in env_src


def test_no_gateway_changes():
    production = [p.name for p in ROOT.iterdir() if p.is_file()]
    assert "gateway" not in " ".join(production).lower()
    for path in (ROOT / "main.py", ROOT / "graphql_ops.py", ROOT / "probe_program.py"):
        text = path.read_text(encoding="utf-8")
        assert "Gateway" not in text
        assert "modify gateway" not in text.lower()


def test_internal_mutation_is_narrow_and_not_a_public_tool():
    document = MUTATION_DOCUMENTS["execute_command"]
    assert document.strip().lower().startswith("mutation")
    assert "exitCode" in document
    assert "output" in document
    assert "[String!]!" in document
    assert "restartService" not in document
    names = _tool_names()
    assert "execute_command" not in names


def test_probe_uses_service_context_execute_mutation(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch, _ok_exec_handler())
    asyncio.run(_probe())
    assert posted[0]["query"] == graphql_ops.M_EXECUTE_COMMAND
    assert "executeCommand" in posted[0]["query"]
    assert posted[0]["variables"]["serviceID"] == SVC
    assert posted[0]["variables"]["environmentID"] == ENV


def test_zeabur_exec_error_classified(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        return {"error": "graphql down", "error_kind": "graphql"}

    posted = _record_gql(monkeypatch, handler)
    result = asyncio.run(_probe())
    assert "ZEABUR_EXEC_ERROR" in result
    assert len(posted) == 1


def test_existing_thirteen_tools_still_registered():
    names = _tool_names()
    assert PHASE_A_NINE | WRITE_TWO | READ_ONLY_OPS_TWO <= names
    assert len(names) == 14
