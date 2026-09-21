"""Phase A contract tests. All GraphQL traffic is mocked; no live Zeabur calls."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.routing import Mount

import graphql_ops
import main
from graphql_ops import GRAPHQL_DOCUMENTS

ROOT = Path(__file__).resolve().parents[1]

EXISTING_SIX = {
    "list_projects",
    "list_services",
    "get_runtime_logs",
    "get_deployments",
    "get_build_logs",
    "scan_all_logs",
}

PHASE_A_EIGHT = {
    "list_projects",
    "list_services",
    "get_service",
    "list_regions",
    "get_me",
    "get_runtime_logs",
    "get_build_logs",
    "get_deployments",
}

PHASE_A_NINE = EXISTING_SIX | PHASE_A_EIGHT

WRITE_TWO = {
    "redeploy_service",
    "set_service_env_var",
}

READ_ONLY_OPS_TWO = {
    "get_service_env_var",
    "get_service_metrics",
}

PROBE_ONE = {
    "probe_service_network",
}

EXPECTED_REGISTERED = PHASE_A_NINE | WRITE_TWO | READ_ONLY_OPS_TWO | PROBE_ONE

DEFER_OR_REJECT = {
    "search_template",
    "search-template",
    "get_repo_id",
    "get-repo-id",
    "search_git_repos",
    "search-git-repos",
    "get_service_variables",
    "get-service-variables",
    "create_project",
    "create-project",
    "create_service",
    "create-service",
    "add_domain",
    "add-domain",
    "update_service_ports",
    "update-service-ports",
    "create_environment_variable",
    "create-environment-variable",
    "update_environment_variable",
    "update-environment-variable",
    "delete_environment_variable",
    "delete-environment-variable",
    "deploy_template",
    "deploy-template",
    "deploy_from_specification",
    "deploy-from-specification",
    "decide_filesystem",
    "decide-filesystem",
    "list_files",
    "list-files",
    "read_file",
    "read-file",
    "file_dir_read",
    "file-dir-read",
    "execute_command",
    "execute-command",
}

TEST_SECRET = "phase-a-test-secret"
TEST_TOKEN = "phase-a-test-token"


def _tool_names() -> set[str]:
    tools = asyncio.run(main.mcp.list_tools())
    return {t.name for t in tools}


def test_existing_six_tools_remain_registered():
    assert EXISTING_SIX <= _tool_names()


def test_phase_a_eight_tools_registered():
    assert PHASE_A_EIGHT <= _tool_names()


def test_complete_inventory_is_exactly_expected():
    names = _tool_names()
    assert PHASE_A_NINE <= names
    assert WRITE_TWO <= names
    assert names == EXPECTED_REGISTERED
    assert len(names) == 14
    assert READ_ONLY_OPS_TWO <= names
    assert PROBE_ONE <= names


def test_defer_and_reject_tools_are_not_registered():
    names = _tool_names()
    assert names.isdisjoint(DEFER_OR_REJECT)


def test_stateless_http_enabled_without_client_filesystem_state():
    assert main.mcp.settings.stateless_http is True
    assert main.mcp.settings.json_response is True
    assert not hasattr(main.mcp, "filesystem")
    source = (ROOT / "main.py").read_text()
    assert "context.filesystem" not in source
    assert "decide-filesystem" not in source
    assert "decide_filesystem" not in source


def test_all_graphql_documents_are_queries_not_mutations():
    for name, document in GRAPHQL_DOCUMENTS.items():
        stripped = document.strip()
        assert stripped.lower().startswith("query"), name
        assert "mutation" not in document.lower(), name


def test_main_has_no_inline_gql_documents():
    text = (ROOT / "main.py").read_text()
    assert "gql(\"\"\"" not in text
    assert "gql('''" not in text


def test_no_graphql_mutation_in_operations_module():
    for name, document in GRAPHQL_DOCUMENTS.items():
        for line in document.splitlines():
            assert not line.strip().lower().startswith("mutation"), name


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, handler, *args, **kwargs):
        self._handler = handler
        self.timeout = kwargs.get("timeout")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None, headers=None):
        return await self._handler(url, json, headers)


def _patch_client(handler):
    def factory(*args, **kwargs):
        return _FakeAsyncClient(handler, *args, **kwargs)

    return patch("httpx.AsyncClient", factory)


@pytest.mark.parametrize(
    "tool_coro,expected_op",
    [
        (lambda: main.list_projects(), "list_projects"),
        (lambda: main.list_services("proj1"), "list_services"),
        (lambda: main.get_runtime_logs("svc1", "env1", "proj1"), "get_runtime_logs"),
        (lambda: main.get_deployments("svc1", "env1", "proj1"), "get_deployments"),
        (lambda: main.get_build_logs("dep1", "proj1", tail=5, errors_only=False), "get_build_logs"),
        (lambda: main.get_service("svc1"), "get_service"),
        (lambda: main.list_regions(), "list_regions"),
        (lambda: main.get_me(), "get_me"),
        (lambda: main.get_service_env_var("svc1", "env1", "FOO"), "get_service_env_var"),
        (lambda: main.get_service_metrics("svc1", "env1", "proj1", "CPU"), "get_service_metrics"),
    ],
)
def test_tools_post_only_intended_readonly_query(tool_coro, expected_op):
    posted = []

    async def handler(url, body, headers):
        posted.append((url, body, headers))
        query = (body or {}).get("query", "")
        assert url == "https://api.zeabur.com/graphql"
        assert query.strip().lower().startswith("query")
        assert "mutation" not in query.lower()
        assert TEST_TOKEN not in query
        assert GRAPHQL_DOCUMENTS[expected_op] == query
        return _FakeResponse({"data": {}})

    with _patch_client(handler):
        result = asyncio.run(tool_coro())

    assert posted, "tool did not call GraphQL"
    assert TEST_TOKEN not in result
    auth = posted[0][2].get("Authorization", "")
    assert auth == f"Bearer {TEST_TOKEN}"


def test_graphql_errors_are_returned_not_raised():
    async def handler(url, body, headers):
        return _FakeResponse({"errors": [{"message": "nope"}]}, status_code=200)

    with _patch_client(handler):
        result = asyncio.run(main.list_projects())
    assert result.startswith("❌")
    assert "nope" in result


def test_http_error_is_returned_not_raised():
    async def handler(url, body, headers):
        return _FakeResponse({"errors": [{"message": "boom"}]}, status_code=500)

    with _patch_client(handler):
        result = asyncio.run(main.get_me())
    assert result.startswith("❌")


def test_timeout_is_returned_not_raised():
    async def handler(url, body, headers):
        raise httpx.TimeoutException("slow")

    with _patch_client(handler):
        result = asyncio.run(main.list_regions())
    assert result.startswith("❌")
    assert "超时" in result


def test_network_error_is_returned_not_raised():
    async def handler(url, body, headers):
        raise httpx.RequestError("offline")

    with _patch_client(handler):
        result = asyncio.run(main.get_service("svc1"))
    assert result.startswith("❌")
    assert "网络请求失败" in result


def test_get_service_formats_domains():
    async def handler(url, body, headers):
        assert body["variables"] == {"id": "svc1"}
        return _FakeResponse(
            {
                "data": {
                    "service": {
                        "_id": "svc1",
                        "name": "web",
                        "status": "RUNNING",
                        "domains": [{"domain": "web.zeabur.app", "status": "READY"}],
                    }
                }
            }
        )

    with _patch_client(handler):
        result = asyncio.run(main.get_service("svc1"))
    assert "web" in result
    assert "web.zeabur.app" in result
    assert TEST_TOKEN not in result


def test_mcp_route_is_mounted_and_guarded():
    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        body = health.json()
        assert body["status"] == "ok"
        assert body["token_set"] is True
        assert TEST_TOKEN not in json.dumps(body)

        unauth = client.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert unauth.status_code == 401

        sse = client.get("/sse")
        assert sse.status_code == 401

        metadata = client.get("/.well-known/oauth-authorization-server")
        assert metadata.status_code == 200
        assert metadata.json()["authorization_endpoint"].endswith("/authorize")
        assert metadata.json()["token_endpoint"].endswith("/token")
        assert metadata.json()["registration_endpoint"].endswith("/register")

        protected = client.get("/.well-known/oauth-protected-resource")
        assert protected.status_code == 200
        assert protected.json()["resource"].endswith("/mcp")


def test_mount_root_keeps_streamable_http_at_mcp():
    assert main.mcp.settings.streamable_http_path == "/mcp"
    mounts = [route for route in main.app.routes if isinstance(route, Mount)]
    assert any(route.path in {"", "/"} for route in mounts)


def test_bearer_auth_accepts_proxy_secret_and_rejects_garbage():
    async def run():
        assert await main._check_bearer_token(f"Bearer {TEST_SECRET}") is True
        assert await main._check_bearer_token("Bearer not-the-secret") is False
        assert await main._check_bearer_token("") is False

    asyncio.run(run())


def test_bearer_auth_accepts_oauth_token_via_store(monkeypatch):
    async def fake_valid(token: str) -> bool:
        return token == "phase-a-oauth-access"

    monkeypatch.setattr(main.oauth, "is_access_token_valid", fake_valid)

    async def run():
        assert await main._check_bearer_token("Bearer phase-a-oauth-access") is True
        assert await main._check_bearer_token("Bearer other") is False

    asyncio.run(run())


def test_scan_all_logs_uses_only_readonly_documents():
    posted_queries = []

    async def handler(url, body, headers):
        query = body["query"]
        posted_queries.append(query)
        assert query.strip().lower().startswith("query")
        assert "mutation" not in query.lower()
        if "runtimeLogs" in query and "projects" not in query:
            return _FakeResponse({"data": {"runtimeLogs": []}})
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

    with _patch_client(handler):
        result = asyncio.run(main.scan_all_logs())
    assert TEST_TOKEN not in result
    assert posted_queries
    assert graphql_ops.Q_SCAN_PROJECTS in posted_queries
    assert graphql_ops.Q_SCAN_SERVICES in posted_queries
    assert graphql_ops.Q_SCAN_RUNTIME_LOGS in posted_queries
