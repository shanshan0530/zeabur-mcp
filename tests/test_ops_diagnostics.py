"""Read-only ops diagnostics tests. All Zeabur traffic is mocked."""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from pathlib import Path

import httpx
import pytest

import graphql_ops
import main
from graphql_ops import GRAPHQL_DOCUMENTS, MUTATION_DOCUMENTS

from tests.test_phase_a import (
    EXPECTED_REGISTERED,
    READ_ONLY_OPS_TWO,
    WRITE_TWO,
    _FakeResponse,
    _patch_client,
    _tool_names,
)

ROOT = Path(__file__).resolve().parents[1]

NON_SECRET_VALUE = "plain-readable-env-value-xyz"
SHADOW_VALUE = "shadow-enabled-1"
SECRET_ENV_VALUE = "must-never-appear-secret-env-aaa"
SVC = "svc-1"
ENV = "env-1"
PROJ = "proj-1"


def _gql_mock(handler):
    async def fake(query, variables=None, *, redact_keys=None, redact_response=False):
        return await handler(query, variables, redact_keys, redact_response)

    return fake


def test_tool_inventory_is_thirteen_with_two_new_read_tools():
    names = _tool_names()
    assert names == EXPECTED_REGISTERED
    assert len(names) == 13
    assert READ_ONLY_OPS_TWO <= names
    assert WRITE_TWO <= names
    assert "execute_command" not in names
    assert "executeCommand" not in names
    assert "network_probe" not in names
    assert "restart_service" not in names


def test_graphql_documents_remain_queries_and_mutations_unchanged():
    for name, document in GRAPHQL_DOCUMENTS.items():
        stripped = document.strip()
        assert stripped.lower().startswith("query"), name
        assert "mutation" not in document.lower(), name
    assert set(MUTATION_DOCUMENTS) == {
        "redeploy_service",
        "create_environment_variable",
        "update_single_environment_variable",
    }
    assert "get_service_env_var" in GRAPHQL_DOCUMENTS
    assert "get_service_metrics" in GRAPHQL_DOCUMENTS
    joined_mut = "\n".join(MUTATION_DOCUMENTS.values())
    assert "executeCommand" not in joined_mut
    assert "restartService" not in joined_mut
    assert "redeployService" in joined_mut


def test_no_execute_command_or_restart_or_new_write_in_source():
    sources = [
        (ROOT / "main.py").read_text(encoding="utf-8"),
        (ROOT / "graphql_ops.py").read_text(encoding="utf-8"),
    ]
    for text in sources:
        assert "executeCommand" not in text
        assert "restartService" not in text
        assert "network_probe" not in text
        assert "deployFromSpecification" not in text
        assert "deleteEnvironmentVariable" not in text
    env_src = inspect.getsource(main.get_service_env_var)
    assert "await set_service_env_var" not in env_src
    assert "confirm=False" not in env_src
    assert "Q_GET_SERVICE_ENV_VAR" in env_src
    assert "Q_SERVICE_VARIABLE_KEYS" not in env_src


def test_existing_two_write_tools_unchanged():
    tools = {t.name: t for t in asyncio.run(main.mcp.list_tools())}
    redeploy = tools["redeploy_service"].inputSchema["properties"]
    assert set(redeploy) == {"service_id", "environment_id", "confirm"}
    env = tools["set_service_env_var"].inputSchema["properties"]
    assert set(env) == {"service_id", "environment_id", "key", "value", "confirm"}
    assert inspect.signature(main.redeploy_service) == inspect.signature(main.redeploy_service)
    redeploy_src = inspect.getsource(main.redeploy_service)
    env_src = inspect.getsource(main.set_service_env_var)
    assert "M_REDEPLOY_SERVICE" in redeploy_src
    assert "M_CREATE_ENVIRONMENT_VARIABLE" in env_src
    assert "M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE" in env_src


def test_get_service_env_var_returns_non_sensitive_value():
    async def handler(url, body, headers):
        assert body["query"] == graphql_ops.Q_GET_SERVICE_ENV_VAR
        assert "mutation" not in body["query"].lower()
        return _FakeResponse(
            {
                "data": {
                    "service": {
                        "_id": SVC,
                        "variables": [
                            {"key": "LOG_LEVEL", "value": NON_SECRET_VALUE},
                            {"key": "OTHER", "value": "nope"},
                        ],
                    }
                }
            }
        )

    with _patch_client(handler):
        result = asyncio.run(main.get_service_env_var(SVC, ENV, "LOG_LEVEL"))
    assert "status=PRESENT" in result
    assert "key=LOG_LEVEL" in result
    assert f"value={NON_SECRET_VALUE}" in result
    assert "source=UNKNOWN" in result
    assert "effective_default=UNKNOWN" in result
    assert "nope" not in result


def test_drivesoid_shadow_enabled_value_is_readable():
    async def handler(url, body, headers):
        return _FakeResponse(
            {
                "data": {
                    "service": {
                        "_id": SVC,
                        "variables": [
                            {"key": "DRIVESOID_SHADOW_ENABLED", "value": SHADOW_VALUE},
                        ],
                    }
                }
            }
        )

    with _patch_client(handler):
        result = asyncio.run(
            main.get_service_env_var(SVC, ENV, "DRIVESOID_SHADOW_ENABLED")
        )
    assert main._env_key_is_sensitive("DRIVESOID_SHADOW_ENABLED") is False
    assert "status=PRESENT" in result
    assert f"value={SHADOW_VALUE}" in result
    assert "ABSENT" not in result


def test_secret_key_returns_present_without_value():
    async def handler(url, body, headers):
        return _FakeResponse(
            {
                "data": {
                    "service": {
                        "_id": SVC,
                        "variables": [
                            {"key": "API_KEY", "value": SECRET_ENV_VALUE},
                            {"key": "DATABASE_URL", "value": SECRET_ENV_VALUE},
                        ],
                    }
                }
            }
        )

    with _patch_client(handler):
        api_key = asyncio.run(main.get_service_env_var(SVC, ENV, "API_KEY"))
        db_url = asyncio.run(main.get_service_env_var(SVC, ENV, "DATABASE_URL"))
    assert "status=PRESENT" in api_key
    assert "key=API_KEY" in api_key
    assert "value=" not in api_key
    assert SECRET_ENV_VALUE not in api_key
    assert "status=PRESENT" in db_url
    assert SECRET_ENV_VALUE not in db_url
    assert "value=" not in db_url


def test_absent_key_returns_absent_from_service_env():
    async def handler(url, body, headers):
        return _FakeResponse(
            {
                "data": {
                    "service": {
                        "_id": SVC,
                        "variables": [{"key": "PRESENT_KEY", "value": "1"}],
                    }
                }
            }
        )

    with _patch_client(handler):
        result = asyncio.run(main.get_service_env_var(SVC, ENV, "MISSING_KEY"))
    assert "status=ABSENT_FROM_SERVICE_ENV" in result
    assert "key=MISSING_KEY" in result
    assert "source=UNKNOWN" in result
    assert "effective_default=UNKNOWN" in result
    assert "value=" not in result


def test_env_value_never_appears_in_logs(caplog):
    async def handler(url, body, headers):
        return _FakeResponse(
            {
                "data": {
                    "service": {
                        "_id": SVC,
                        "variables": [
                            {"key": "LOG_LEVEL", "value": NON_SECRET_VALUE},
                            {"key": "API_SECRET", "value": SECRET_ENV_VALUE},
                        ],
                    }
                }
            }
        )

    with caplog.at_level(logging.DEBUG):
        with _patch_client(handler):
            readable = asyncio.run(main.get_service_env_var(SVC, ENV, "LOG_LEVEL"))
            hidden = asyncio.run(main.get_service_env_var(SVC, ENV, "API_SECRET"))
    assert NON_SECRET_VALUE in readable
    assert SECRET_ENV_VALUE not in hidden
    assert NON_SECRET_VALUE not in caplog.text
    assert SECRET_ENV_VALUE not in caplog.text


def test_env_read_does_not_reuse_write_dry_run(monkeypatch):
    posted = []

    async def fake(query, variables=None, *, redact_keys=None, redact_response=False):
        posted.append(query)
        return {"service": {"variables": [{"key": "FOO", "value": "bar"}]}}

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_service_env_var(SVC, ENV, "FOO"))
    assert result.startswith("status=PRESENT")
    assert posted == [graphql_ops.Q_GET_SERVICE_ENV_VAR]
    assert graphql_ops.Q_SERVICE_VARIABLE_KEYS not in posted
    assert graphql_ops.M_CREATE_ENVIRONMENT_VARIABLE not in posted
    assert graphql_ops.M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE not in posted


def test_runtime_api_error_is_not_no_logs(monkeypatch):
    async def fake(query, variables=None, **kwargs):
        return {"error": [{"message": "backend exploded"}], "error_kind": "graphql"}

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ))
    assert "status=API_ERROR" in result
    assert "status=NO_LOGS" not in result
    assert "没有运行时日志" not in result


def test_runtime_permission_failure_classified(monkeypatch):
    async def fake(query, variables=None, **kwargs):
        return {
            "error": [{"message": "permission denied for runtimeLogs"}],
            "error_kind": "http",
            "status_code": 403,
        }

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ))
    assert "status=PERMISSION_DENIED" in result
    assert "status=NO_LOGS" not in result
    assert "没有运行时日志" not in result


def test_runtime_timeout_and_network_classified():
    async def timeout_handler(url, body, headers):
        raise httpx.TimeoutException("slow")

    with _patch_client(timeout_handler):
        timeout_result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ))
    assert "status=API_UNAVAILABLE" in timeout_result
    assert "status=NO_LOGS" not in timeout_result
    assert "没有运行时日志" not in timeout_result

    async def network_handler(url, body, headers):
        raise httpx.RequestError("offline")

    with _patch_client(network_handler):
        network_result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ))
    assert "status=API_UNAVAILABLE" in network_result
    assert "status=NO_LOGS" not in network_result
    assert "没有运行时日志" not in network_result


def test_empty_successful_runtime_logs_is_no_logs(monkeypatch):
    async def fake(query, variables=None, **kwargs):
        return {"runtimeLogs": []}

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ))
    assert "status=NO_LOGS" in result
    assert "没有运行时日志" not in result


def test_missing_runtime_logs_field_is_api_error_not_no_logs(monkeypatch):
    async def fake(query, variables=None, **kwargs):
        return {}

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ))
    assert "status=API_ERROR" in result
    assert "status=NO_LOGS" not in result


def test_keyword_filter_works(monkeypatch):
    async def fake(query, variables=None, **kwargs):
        return {
            "runtimeLogs": [
                {"timestamp": "2026-01-01T00:00:00Z", "message": "hello world"},
                {"timestamp": "2026-01-01T00:00:01Z", "message": "error boom"},
            ]
        }

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ, keyword="error"))
    assert "status=OK" in result
    assert "error boom" in result
    assert "hello world" not in result


def test_time_filter_works(monkeypatch):
    async def fake(query, variables=None, **kwargs):
        return {
            "runtimeLogs": [
                {"timestamp": "2026-01-01T00:00:00Z", "message": "too-old"},
                {"timestamp": "2026-01-01T12:00:00Z", "message": "in-range"},
                {"timestamp": "2026-01-02T00:00:00Z", "message": "too-new"},
            ]
        }

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(
        main.get_runtime_logs(
            SVC,
            ENV,
            PROJ,
            start_time="2026-01-01T06:00:00Z",
            end_time="2026-01-01T18:00:00Z",
        )
    )
    assert "in-range" in result
    assert "too-old" not in result
    assert "too-new" not in result


def test_pagination_is_bounded(monkeypatch):
    calls = []

    async def fake(query, variables=None, **kwargs):
        calls.append(dict(variables or {}))
        cursor = (variables or {}).get("timestampCursor")
        if cursor is None:
            return {"runtimeLogs": [{"timestamp": "2026-01-01T12:00:00Z", "message": "p1"}]}
        if cursor == "2026-01-01T12:00:00Z":
            return {"runtimeLogs": [{"timestamp": "2026-01-01T11:00:00Z", "message": "p2"}]}
        if cursor == "2026-01-01T11:00:00Z":
            return {"runtimeLogs": [{"timestamp": "2026-01-01T10:00:00Z", "message": "p3"}]}
        raise AssertionError(f"unbounded pagination cursor={cursor}")

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ, max_pages=2))
    assert len(calls) == 2
    assert "p1" in result
    assert "p2" in result
    assert "p3" not in result


def test_repeated_cursor_stops(monkeypatch):
    calls = []

    async def fake(query, variables=None, **kwargs):
        calls.append(dict(variables or {}))
        return {"runtimeLogs": [{"timestamp": "same-cursor", "message": "loop"}]}

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(main.get_runtime_logs(SVC, ENV, PROJ, max_pages=10))
    assert 1 <= len(calls) <= 2
    assert "loop" in result
    assert "status=OK" in result


def test_max_pages_returns_partial_for_truncated_range(monkeypatch):
    calls = []

    async def fake(query, variables=None, **kwargs):
        calls.append(dict(variables or {}))
        cursor = (variables or {}).get("timestampCursor")
        if cursor is None:
            ts = "2026-01-01T12:00:00Z"
        elif cursor == "2026-01-01T12:00:00Z":
            ts = "2026-01-01T11:00:00Z"
        else:
            raise AssertionError("should have stopped at max_pages")
        return {"runtimeLogs": [{"timestamp": ts, "message": f"at-{ts}"}]}

    monkeypatch.setattr(main, "gql", fake)
    result = asyncio.run(
        main.get_runtime_logs(
            SVC,
            ENV,
            PROJ,
            start_time="2026-01-01T00:00:00Z",
            max_pages=2,
        )
    )
    assert len(calls) == 2
    assert "status=PARTIAL" in result
    assert "max_pages truncated requested range" in result


def _scan_handler(runtime_payload):
    async def handler(url, body, headers):
        query = body["query"]
        if "runtimeLogs" in query and "projects" not in query:
            if isinstance(runtime_payload, Exception):
                raise runtime_payload
            return _FakeResponse(runtime_payload)
        if "services" in query:
            return _FakeResponse(
                {"data": {"services": {"edges": [{"node": {"_id": "s1", "name": "web"}}]}}}
            )
        return _FakeResponse(
            {
                "data": {
                    "projects": {
                        "edges": [
                            {
                                "node": {
                                    "_id": "p1",
                                    "name": "demo",
                                    "environments": [{"_id": "e1", "name": "production"}],
                                }
                            }
                        ]
                    }
                }
            }
        )

    return handler


def test_scan_empty_logs_are_not_clean():
    with _patch_client(_scan_handler({"data": {"runtimeLogs": []}})):
        result = asyncio.run(main.scan_all_logs())
    assert "NO_LOGS" in result
    assert "CLEAN=0" in result
    assert "NO_LOGS=1" in result
    assert "所有服务正常" not in result
    assert "\nCLEAN:" not in result and not result.startswith("CLEAN:")


def test_scan_fetch_error_is_not_clean():
    with _patch_client(
        _scan_handler({"errors": [{"message": "log store down"}]})
    ):
        result = asyncio.run(main.scan_all_logs())
    assert "FETCH_FAILED" in result
    assert "CLEAN=0" in result
    assert "FETCH_FAILED=1" in result
    assert "所有服务正常" not in result
    assert "正常:" not in result


def test_scan_true_clean_logs_remain_clean():
    with _patch_client(
        _scan_handler(
            {
                "data": {
                    "runtimeLogs": [
                        {"timestamp": "2026-01-01T00:00:00Z", "message": "ready"},
                        {"timestamp": "2026-01-01T00:00:01Z", "message": "listening on 8080"},
                    ]
                }
            }
        )
    ):
        result = asyncio.run(main.scan_all_logs())
    assert "CLEAN=1" in result
    assert "ERROR_MATCH=0" in result
    assert "NO_LOGS=0" in result
    assert "FETCH_FAILED=0" in result
    assert "CLEAN: demo/production/web" in result
    assert "ERROR_MATCH:" not in result


def test_scan_error_match_and_summary_counts():
    with _patch_client(
        _scan_handler(
            {
                "data": {
                    "runtimeLogs": [
                        {"timestamp": "2026-01-01T00:00:00Z", "message": "fatal exception"}
                    ]
                }
            }
        )
    ):
        result = asyncio.run(main.scan_all_logs())
    assert "ERROR_MATCH=1" in result
    assert "CLEAN=0" in result
    assert "ERROR_MATCH: demo/production/web" in result
    assert "fatal exception" in result


def test_scan_async_exception_is_fetch_failed_not_skipped():
    with _patch_client(_scan_handler(RuntimeError("boom-scan"))):
        result = asyncio.run(main.scan_all_logs())
    assert "FETCH_FAILED" in result
    assert "IMPLEMENTATION_ERROR" in result
    assert "CLEAN=0" in result
    assert "所有服务正常" not in result


def test_scan_exactly_one_service_query_per_project_environment():
    posted_service_vars = []

    async def handler(url, body, headers):
        query = body["query"]
        if query == graphql_ops.Q_SCAN_SERVICES:
            posted_service_vars.append(dict(body.get("variables") or {}))
            return _FakeResponse(
                {"data": {"services": {"edges": [{"node": {"_id": "s1", "name": "web"}}]}}}
            )
        if query == graphql_ops.Q_SCAN_RUNTIME_LOGS:
            return _FakeResponse(
                {
                    "data": {
                        "runtimeLogs": [
                            {"timestamp": "2026-01-01T00:00:00Z", "message": "ready"}
                        ]
                    }
                }
            )
        return _FakeResponse(
            {
                "data": {
                    "projects": {
                        "edges": [
                            {
                                "node": {
                                    "_id": "p1",
                                    "name": "demo",
                                    "environments": [
                                        {"_id": "e1", "name": "production"},
                                        {"_id": "e2", "name": "staging"},
                                    ],
                                }
                            },
                            {
                                "node": {
                                    "_id": "p2",
                                    "name": "other",
                                    "environments": [{"_id": "e3", "name": "production"}],
                                }
                            },
                        ]
                    }
                }
            }
        )

    with _patch_client(handler):
        asyncio.run(main.scan_all_logs())

    source = inspect.getsource(main.scan_all_logs)
    assert source.count("gql(Q_SCAN_SERVICES") == 1
    assert len(posted_service_vars) == 3
    assert posted_service_vars.count({"projectID": "p1"}) == 2
    assert posted_service_vars.count({"projectID": "p2"}) == 1


def test_deployment_query_contains_cli_proven_fields():
    query = graphql_ops.Q_GET_DEPLOYMENTS
    for field in (
        "_id",
        "status",
        "createdAt",
        "startedAt",
        "finishedAt",
        "ref",
        "commitSHA",
        "commitMessage",
        "scheduledAt",
    ):
        assert field in query
    assert "exitCode" not in query
    assert "restartReason" not in query
    assert "restartCount" not in query
    assert query.strip().lower().startswith("query")


def test_deployments_show_source_proven_timestamps():
    async def handler(url, body, headers):
        assert body["query"] == graphql_ops.Q_GET_DEPLOYMENTS
        assert "projectID" not in (body.get("variables") or {})
        assert body["variables"] == {"serviceID": SVC, "environmentID": ENV}
        assert "startedAt" in body["query"]
        assert "finishedAt" in body["query"]
        assert "ref" in body["query"]
        assert "commitSHA" in body["query"]
        assert "commitMessage" in body["query"]
        assert "scheduledAt" in body["query"]
        assert "exitCode" not in body["query"]
        assert "restartReason" not in body["query"]
        assert "restartCount" not in body["query"]
        return _FakeResponse(
            {
                "data": {
                    "deployments": {
                        "edges": [
                            {
                                "node": {
                                    "_id": "dep-1",
                                    "status": "RUNNING",
                                    "createdAt": "2026-01-01T00:00:00Z",
                                    "startedAt": "2026-01-01T00:00:05Z",
                                    "finishedAt": "2026-01-01T00:01:00Z",
                                    "ref": "main",
                                    "commitSHA": "abc123def456",
                                    "commitMessage": "fix logs",
                                    "scheduledAt": "2026-01-01T00:00:02Z",
                                }
                            }
                        ]
                    }
                }
            }
        )

    with _patch_client(handler):
        result = asyncio.run(main.get_deployments(SVC, ENV, PROJ))
    assert "startedAt: 2026-01-01T00:00:05Z" in result
    assert "finishedAt: 2026-01-01T00:01:00Z" in result
    assert "ref: main" in result
    assert "commitSHA: abc123def456" in result
    assert "commitMessage: fix logs" in result
    assert "scheduledAt: 2026-01-01T00:00:02Z" in result
    assert "dep-1" in result
    assert "exit code" not in result.lower()
    assert "restart reason" not in result.lower()
    assert "restart count" not in result.lower()


def test_deployments_missing_timestamps_are_unsupported():
    async def handler(url, body, headers):
        return _FakeResponse(
            {
                "data": {
                    "deployments": {
                        "edges": [
                            {
                                "node": {
                                    "_id": "dep-2",
                                    "status": "RUNNING",
                                    "createdAt": "2026-01-01T00:00:00Z",
                                }
                            }
                        ]
                    }
                }
            }
        )

    with _patch_client(handler):
        result = asyncio.run(main.get_deployments(SVC, ENV, PROJ))
    assert "startedAt: UNSUPPORTED" in result
    assert "finishedAt: UNSUPPORTED" in result
    assert "ref: UNSUPPORTED" in result
    assert "commitSHA: UNSUPPORTED" in result
    assert "commitMessage: UNSUPPORTED" in result
    assert "scheduledAt: UNSUPPORTED" in result


def test_service_metrics_query_is_readonly():
    posted = []

    async def handler(url, body, headers):
        posted.append(body)
        query = body["query"]
        assert query == graphql_ops.Q_GET_SERVICE_METRICS
        assert query.strip().lower().startswith("query")
        assert "mutation" not in query.lower()
        variables = body["variables"]
        assert variables["serviceID"] == SVC
        assert variables["environmentID"] == ENV
        assert variables["projectID"] == PROJ
        assert variables["metricType"] == "CPU"
        assert "startTime" in variables
        assert "endTime" in variables
        return _FakeResponse(
            {
                "data": {
                    "service": {
                        "metrics": [
                            {"timestamp": "2026-01-01T00:00:00Z", "value": 0.2},
                        ]
                    }
                }
            }
        )

    with _patch_client(handler):
        result = asyncio.run(main.get_service_metrics(SVC, ENV, PROJ, "CPU"))
    assert posted
    assert "status=OK" in result
    assert "metric_type=CPU" in result
    assert "0.2" in result
    assert "OOM" not in result
    assert "uptime" not in result.lower()
    assert "restart" not in result.lower()


def test_service_metrics_rejects_unknown_type_without_network(monkeypatch):
    async def boom(*args, **kwargs):
        raise AssertionError("metrics API must not be called for unknown type")

    monkeypatch.setattr(main, "gql", boom)
    result = asyncio.run(main.get_service_metrics(SVC, ENV, PROJ, "OOM"))
    assert "status=UNSUPPORTED" in result
    assert "CPU" in result


@pytest.mark.parametrize(
    "token",
    [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "PRIVATE_KEY",
        "API_KEY",
        "ACCESS_KEY",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "SESSION",
        "DSN",
        "CONNECTION_STRING",
    ],
)
def test_sensitive_token_detection(token):
    assert main._env_key_is_sensitive(f"X_{token}_Y") is True
    assert main._env_key_is_sensitive("DRIVESOID_SHADOW_ENABLED") is False


def test_runtime_logs_required_args_stay_compatible():
    tools = {t.name: t for t in asyncio.run(main.mcp.list_tools())}
    required = set(tools["get_runtime_logs"].inputSchema["required"])
    assert required == {"service_id", "environment_id", "project_id"}
    props = tools["get_runtime_logs"].inputSchema["properties"]
    for optional in (
        "deployment_id",
        "timestamp_cursor",
        "start_time",
        "end_time",
        "keyword",
        "tail",
        "max_pages",
    ):
        assert optional in props
        assert optional not in required
    sig = inspect.signature(main.get_runtime_logs)
    params = list(sig.parameters)
    assert params[:3] == ["service_id", "environment_id", "project_id"]


def test_no_inline_mutations_or_execute_command_in_main():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "gql(\"\"\"" not in source
    assert "executeCommand" not in source
    assert not re.search(r"\bnetwork_probe\b", source)
    assert "没有运行时日志" not in source
