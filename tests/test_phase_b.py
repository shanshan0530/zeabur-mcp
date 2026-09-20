"""Phase B operator-layer contract tests. All Zeabur traffic is mocked."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.responses import JSONResponse
from starlette.requests import Request

import graphql_ops
import main
from graphql_ops import GRAPHQL_DOCUMENTS, MUTATION_DOCUMENTS

from tests.test_phase_a import (
    EXPECTED_REGISTERED,
    PHASE_A_NINE,
    TEST_SECRET,
    TEST_TOKEN,
    WRITE_TWO,
    _FakeResponse,
    _patch_client,
    _tool_names,
)
from tests.test_url_token_auth import TEST_URL_SECRET, _asgi_scope, _guard_status

ROOT = Path(__file__).resolve().parents[1]

FROZEN_READ_SIGNATURES = {
    "list_projects": "() -> str",
    "list_services": "(project_id: str) -> str",
    "get_runtime_logs": "(service_id: str, environment_id: str, project_id: str) -> str",
    "get_deployments": "(service_id: str, environment_id: str, project_id: str) -> str",
    "get_build_logs": "(deployment_id: str, project_id: str, tail: int = 30, errors_only: bool = True) -> str",
    "scan_all_logs": "() -> str",
    "get_service": "(service_id: str) -> str",
    "list_regions": "() -> str",
    "get_me": "() -> str",
}

SVC = "svc-authorized"
ENV = "env-authorized"
POLICY_JSON = json.dumps([{"service_id": SVC, "environment_id": ENV}])
OPERATOR_URL_SECRET = "phase-b-operator-url-secret"
ENV_SECRET_VALUE = "do-not-log-this-env-value"


def make_ctx(capability: str | None):
    scope = {"state": {}}
    if capability is not None:
        scope["state"][main.SCOPE_CAPABILITY_KEY] = capability
    return SimpleNamespace(request_context=SimpleNamespace(request=SimpleNamespace(scope=scope)))


def operator_ctx():
    return make_ctx(main.CAPABILITY_OPERATOR)


def read_ctx():
    return make_ctx(main.CAPABILITY_READ)


def enable_writes(monkeypatch, policy: str = POLICY_JSON):
    monkeypatch.setattr(main, "MCP_WRITES_ENABLED", True)
    monkeypatch.setattr(main, "MCP_OPERATOR_POLICY", policy)


def _record_gql(monkeypatch, handler=None):
    posted: list[dict] = []

    async def fake(query, variables=None, *, redact_keys=None):
        posted.append({"query": query, "variables": variables, "redact_keys": redact_keys})
        if handler:
            return await handler(query, variables, redact_keys)
        return {}

    monkeypatch.setattr(main, "gql", fake)
    return posted


def _guard_capability(
    path: str = "/mcp",
    headers: dict[str, str] | None = None,
    query_string: bytes | str = b"",
) -> tuple[int, str | None]:
    captured: dict[str, str | None] = {"capability": None}

    async def ok_app(scope, receive, send):
        state = scope.get("state") if isinstance(scope.get("state"), dict) else {}
        captured["capability"] = state.get(main.SCOPE_CAPABILITY_KEY)
        await JSONResponse({"ok": True})(scope, receive, send)

    messages: list[dict] = []

    async def run():
        guard = main.MCPAuthGuard(ok_app)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        await guard(_asgi_scope(path, headers, query_string), receive, send)

    asyncio.run(run())
    start = next(m for m in messages if m["type"] == "http.response.start")
    return int(start["status"]), captured["capability"]


def test_original_nine_tools_remain_with_unchanged_signatures():
    names = _tool_names()
    assert PHASE_A_NINE <= names
    for name, expected in FROZEN_READ_SIGNATURES.items():
        assert str(inspect.signature(getattr(main, name))) == expected
    tools = {t.name: t for t in asyncio.run(main.mcp.list_tools())}
    assert "project_id" in tools["list_services"].inputSchema["properties"]
    assert set(tools["get_runtime_logs"].inputSchema["required"]) == {
        "service_id",
        "environment_id",
        "project_id",
    }
    assert set(tools["get_deployments"].inputSchema["required"]) == {
        "service_id",
        "environment_id",
        "project_id",
    }
    build_props = tools["get_build_logs"].inputSchema["properties"]
    assert build_props["tail"]["default"] == 30
    assert build_props["errors_only"]["default"] is True


def test_exactly_two_new_write_tools_and_inventory_is_eleven():
    names = _tool_names()
    assert names == EXPECTED_REGISTERED
    assert len(names) == 11
    assert names - PHASE_A_NINE == WRITE_TWO
    tools = {t.name: t for t in asyncio.run(main.mcp.list_tools())}
    for write_name in WRITE_TWO:
        schema = tools[write_name].inputSchema
        assert "ctx" not in schema.get("properties", {})
        assert "Context" not in json.dumps(schema)


def test_graphql_documents_remain_query_only():
    for name, document in GRAPHQL_DOCUMENTS.items():
        stripped = document.strip()
        assert stripped.lower().startswith("query"), name
        assert "mutation" not in document.lower(), name
    assert "service_variable_keys" in GRAPHQL_DOCUMENTS
    assert not re.search(r"\bvalue\b", graphql_ops.Q_SERVICE_VARIABLE_KEYS)


def test_write_registry_contains_only_approved_mutations():
    assert set(MUTATION_DOCUMENTS) == {
        "redeploy_service",
        "create_environment_variable",
        "update_single_environment_variable",
    }
    for name, document in MUTATION_DOCUMENTS.items():
        stripped = document.strip()
        assert stripped.lower().startswith("mutation"), name
        assert "query" not in stripped.lower().split()[0]
    joined = "\n".join(MUTATION_DOCUMENTS.values())
    assert "redeployService" in joined
    assert "createEnvironmentVariable" in joined
    assert "updateSingleEnvironmentVariable" in joined
    assert "restartService" not in joined
    assert "deployFromSpecification" not in joined
    assert "updateEnvironmentVariable(" not in joined
    assert "deleteEnvironmentVariable" not in joined


def test_no_inline_mutation_strings_in_main():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "gql(\"\"\"" not in source
    assert "gql('''" not in source
    assert "mutation RedeployService" not in source
    assert "createEnvironmentVariable(" not in source
    assert "updateSingleEnvironmentVariable(" not in source
    assert "updateEnvironmentVariable(" not in source
    assert "restartService" not in source
    assert "deployFromSpecification" not in source


def test_mcp_url_secret_maps_to_read(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    status, cap = _guard_capability(query_string=f"token={TEST_URL_SECRET}")
    assert status != 401
    assert cap == main.CAPABILITY_READ


def test_operator_url_secret_maps_to_operator(monkeypatch):
    monkeypatch.setattr(main, "MCP_OPERATOR_URL_SECRET", OPERATOR_URL_SECRET)
    status, cap = _guard_capability(query_string=f"token={OPERATOR_URL_SECRET}")
    assert status != 401
    assert cap == main.CAPABILITY_OPERATOR


def test_proxy_secret_bearer_maps_to_operator():
    status, cap = _guard_capability(headers={"authorization": f"Bearer {TEST_SECRET}"})
    assert status != 401
    assert cap == main.CAPABILITY_OPERATOR


def test_oauth_token_maps_to_read(monkeypatch):
    async def fake_valid(token: str) -> bool:
        return token == "phase-b-oauth-access"

    monkeypatch.setattr(main.oauth, "is_access_token_valid", fake_valid)
    status, cap = _guard_capability(headers={"authorization": "Bearer phase-b-oauth-access"})
    assert status != 401
    assert cap == main.CAPABILITY_READ


def test_invalid_auth_is_unauthorized(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    monkeypatch.setattr(main, "MCP_OPERATOR_URL_SECRET", OPERATOR_URL_SECRET)
    status, cap = _guard_capability(query_string="token=nope")
    assert status == 401
    assert cap is None
    status, cap = _guard_capability(headers={"authorization": "Bearer nope"})
    assert status == 401
    assert cap is None
    status, cap = _guard_capability()
    assert status == 401
    assert cap is None


def test_operator_url_token_is_mcp_only_and_independent(monkeypatch):
    qs = f"token={OPERATOR_URL_SECRET}".encode("ascii")
    assert main._mcp_operator_query_token_authorized({"path": "/mcp", "query_string": qs}) is False

    monkeypatch.setattr(main, "MCP_OPERATOR_URL_SECRET", OPERATOR_URL_SECRET)
    assert main._mcp_operator_query_token_authorized({"path": "/mcp", "query_string": qs}) is True
    assert main._mcp_operator_query_token_authorized({"path": "/sse", "query_string": qs}) is False
    assert main._mcp_operator_query_token_authorized({"path": "/authorize", "query_string": qs}) is False
    assert main._mcp_operator_query_token_authorized({"path": "/health", "query_string": qs}) is False
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert main._mcp_operator_query_token_authorized(
        {"path": "/mcp", "query_string": f"token={TEST_URL_SECRET}".encode("ascii")}
    ) is False
    assert main._mcp_operator_query_token_authorized(
        {"path": "/mcp", "query_string": f"token={TEST_SECRET}".encode("ascii")}
    ) is False

    sse_source = inspect.getsource(main.sse_handler)
    assert "MCP_OPERATOR_URL_SECRET" not in sse_source
    assert "_mcp_operator_query_token_authorized" not in sse_source

    request = Request(_asgi_scope("/sse", query_string=f"token={OPERATOR_URL_SECRET}") | {"method": "GET"})

    async def run():
        resp = await main.sse_handler(request)
        assert resp.status_code == 401

    asyncio.run(run())
    assert _guard_status(path="/mcp", query_string=f"token={OPERATOR_URL_SECRET}") != 401


def test_read_cannot_execute_write_tools(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    redeploy = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=read_ctx()))
    env_set = asyncio.run(
        main.set_service_env_var(SVC, ENV, "K", ENV_SECRET_VALUE, True, ctx=read_ctx())
    )
    assert redeploy.startswith("❌")
    assert "OPERATOR" in redeploy
    assert env_set.startswith("❌")
    assert "OPERATOR" in env_set
    assert posted == []


def test_operator_can_still_execute_all_read_tools():
    posted_queries = []

    async def handler(url, body, headers):
        posted_queries.append(body["query"])
        assert body["query"].strip().lower().startswith("query")
        assert "mutation" not in body["query"].lower()
        return _FakeResponse({"data": {}})

    with _patch_client(handler):
        asyncio.run(main.list_projects())
        asyncio.run(main.list_services("p1"))
        asyncio.run(main.get_runtime_logs("s", "e", "p"))
        asyncio.run(main.get_deployments("s", "e", "p"))
        asyncio.run(main.get_build_logs("d", "p", tail=1, errors_only=False))
        asyncio.run(main.get_service("s"))
        asyncio.run(main.list_regions())
        asyncio.run(main.get_me())
        asyncio.run(main.scan_all_logs())
    assert len(posted_queries) == 9
    assert all(q.strip().lower().startswith("query") for q in posted_queries)


def test_concurrent_read_and_operator_do_not_leak_capability(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    monkeypatch.setattr(main, "MCP_OPERATOR_URL_SECRET", OPERATOR_URL_SECRET)

    async def one(kind: str) -> str:
        captured: dict[str, str] = {}

        async def probe(scope, receive, send):
            captured["cap"] = scope["state"][main.SCOPE_CAPABILITY_KEY]
            await JSONResponse({"ok": True})(scope, receive, send)

        guard = main.MCPAuthGuard(probe)
        if kind == "read":
            scope = _asgi_scope("/mcp", query_string=f"token={TEST_URL_SECRET}")
        elif kind == "operator-url":
            scope = _asgi_scope("/mcp", query_string=f"token={OPERATOR_URL_SECRET}")
        else:
            scope = _asgi_scope("/mcp", headers={"authorization": f"Bearer {TEST_SECRET}"})

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            return None

        await guard(scope, receive, send)
        return captured["cap"]

    async def hammer():
        kinds = (["read", "operator-url", "operator-bearer"] * 20)
        got = await asyncio.gather(*[one(k) for k in kinds])
        expected = []
        for k in kinds:
            expected.append(
                main.CAPABILITY_READ if k == "read" else main.CAPABILITY_OPERATOR
            )
        assert got == expected

    asyncio.run(hammer())


def test_writes_disabled_by_default_zero_mutation(monkeypatch):
    assert main.MCP_WRITES_ENABLED is False
    monkeypatch.setattr(main, "MCP_OPERATOR_POLICY", POLICY_JSON)
    posted = _record_gql(monkeypatch)
    r1 = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=operator_ctx()))
    r2 = asyncio.run(
        main.set_service_env_var(SVC, ENV, "K", ENV_SECRET_VALUE, True, ctx=operator_ctx())
    )
    r3 = asyncio.run(
        main.set_service_env_var(SVC, ENV, "K", ENV_SECRET_VALUE, False, ctx=operator_ctx())
    )
    assert "disabled" in r1.lower() or "MCP_WRITES_ENABLED" in r1
    assert "disabled" in r2.lower() or "MCP_WRITES_ENABLED" in r2
    assert "disabled" in r3.lower() or "MCP_WRITES_ENABLED" in r3
    assert posted == []


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "[]",
        "{not json",
        '{"service_id": "x"}',
        '[{"service_id": "x"}]',
        '[{"environment_id": "e"}]',
        '[{"service_id": 1, "environment_id": "e"}]',
        '[{"service_id": "", "environment_id": "e"}]',
        '[{"service_id": "s*", "environment_id": "e"}]',
        "null",
        "5",
    ],
)
def test_empty_or_malformed_policy_fail_closed(monkeypatch, raw):
    monkeypatch.setattr(main, "MCP_WRITES_ENABLED", True)
    monkeypatch.setattr(main, "MCP_OPERATOR_POLICY", raw)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=operator_ctx()))
    assert result.startswith("❌")
    assert posted == []
    env_result = asyncio.run(
        main.set_service_env_var(SVC, ENV, "K", ENV_SECRET_VALUE, True, ctx=operator_ctx())
    )
    assert env_result.startswith("❌")
    assert posted == []


def test_wildcard_policy_does_not_prefix_match(monkeypatch):
    # Exact match only: a literal "*" target does not authorize other ids.
    enable_writes(
        monkeypatch,
        json.dumps([{"service_id": "*", "environment_id": "*"}]),
    )
    posted = _record_gql(monkeypatch)
    result = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=operator_ctx()))
    assert result.startswith("❌")
    assert posted == []


def test_target_mismatch_zero_mutation(monkeypatch):
    enable_writes(
        monkeypatch,
        json.dumps([{"service_id": "other-svc", "environment_id": ENV}]),
    )
    posted = _record_gql(monkeypatch)
    result = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=operator_ctx()))
    assert "not authorized" in result.lower() or "policy" in result.lower()
    assert posted == []
    env_result = asyncio.run(
        main.set_service_env_var(SVC, ENV, "K", ENV_SECRET_VALUE, False, ctx=operator_ctx())
    )
    assert env_result.startswith("❌")
    assert posted == []


def test_confirm_false_redeploy_zero_network(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(main.redeploy_service(SVC, ENV, False, ctx=operator_ctx()))
    assert "Dry-run" in result
    assert "latest main" not in result.lower()
    assert posted == []


def test_confirmed_redeploy_exactly_one_mocked_mutation(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        return {"redeployService": True}

    posted = _record_gql(monkeypatch, handler)
    result = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=operator_ctx()))
    assert "status=success" in result
    assert SVC in result and ENV in result
    assert "latest main" not in result.lower()
    assert "commit" not in result.lower()
    assert len(posted) == 1
    assert posted[0]["query"] == graphql_ops.M_REDEPLOY_SERVICE
    assert posted[0]["variables"] == {"serviceID": SVC, "environmentID": ENV}


def test_env_dry_run_key_only_read_zero_mutation(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        assert query == graphql_ops.Q_SERVICE_VARIABLE_KEYS
        return {"service": {"variables": [{"key": "EXISTING"}]}}

    posted = _record_gql(monkeypatch, handler)
    create_msg = asyncio.run(
        main.set_service_env_var(SVC, ENV, "NEW", ENV_SECRET_VALUE, False, ctx=operator_ctx())
    )
    update_msg = asyncio.run(
        main.set_service_env_var(SVC, ENV, "EXISTING", ENV_SECRET_VALUE, False, ctx=operator_ctx())
    )
    assert "would create" in create_msg
    assert "would update" in update_msg
    assert ENV_SECRET_VALUE not in create_msg
    assert ENV_SECRET_VALUE not in update_msg
    assert len(posted) == 2
    assert all(p["query"] == graphql_ops.Q_SERVICE_VARIABLE_KEYS for p in posted)
    assert all(
        p["query"]
        not in (
            graphql_ops.M_CREATE_ENVIRONMENT_VARIABLE,
            graphql_ops.M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE,
        )
        for p in posted
    )


def test_env_create_path_key_lookup_plus_one_create(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        if query == graphql_ops.Q_SERVICE_VARIABLE_KEYS:
            return {"service": {"variables": [{"key": "OTHER"}]}}
        return {"createEnvironmentVariable": True}

    posted = _record_gql(monkeypatch, handler)
    result = asyncio.run(
        main.set_service_env_var(SVC, ENV, "NEW_KEY", ENV_SECRET_VALUE, True, ctx=operator_ctx())
    )
    assert "created" in result.lower()
    assert ENV_SECRET_VALUE not in result
    assert [p["query"] for p in posted] == [
        graphql_ops.Q_SERVICE_VARIABLE_KEYS,
        graphql_ops.M_CREATE_ENVIRONMENT_VARIABLE,
    ]
    assert posted[1]["variables"]["key"] == "NEW_KEY"
    assert posted[1]["variables"]["value"] == ENV_SECRET_VALUE
    assert posted[1]["redact_keys"] == {"value"}
    assert graphql_ops.M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE not in [p["query"] for p in posted]


def test_env_update_path_key_lookup_plus_one_update_single(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        if query == graphql_ops.Q_SERVICE_VARIABLE_KEYS:
            return {"service": {"variables": [{"key": "EXISTING"}]}}
        return {"updateSingleEnvironmentVariable": True}

    posted = _record_gql(monkeypatch, handler)
    result = asyncio.run(
        main.set_service_env_var(SVC, ENV, "EXISTING", ENV_SECRET_VALUE, True, ctx=operator_ctx())
    )
    assert "updated" in result.lower()
    assert ENV_SECRET_VALUE not in result
    assert [p["query"] for p in posted] == [
        graphql_ops.Q_SERVICE_VARIABLE_KEYS,
        graphql_ops.M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE,
    ]
    variables = posted[1]["variables"]
    assert variables["oldKey"] == variables["newKey"] == "EXISTING"
    assert variables["value"] == ENV_SECRET_VALUE
    assert posted[1]["redact_keys"] == {"value"}
    assert graphql_ops.M_CREATE_ENVIRONMENT_VARIABLE not in [p["query"] for p in posted]


def test_write_error_fails_without_fallback_or_retry(monkeypatch):
    enable_writes(monkeypatch)

    async def handler(query, variables, redact_keys):
        if query == graphql_ops.M_REDEPLOY_SERVICE:
            return {"error": "boom-redeploy"}
        if query == graphql_ops.Q_SERVICE_VARIABLE_KEYS:
            return {"service": {"variables": []}}
        if query == graphql_ops.M_CREATE_ENVIRONMENT_VARIABLE:
            return {"error": "boom-create"}
        raise AssertionError(f"unexpected extra call: {query}")

    posted = _record_gql(monkeypatch, handler)
    redeploy = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=operator_ctx()))
    assert "boom-redeploy" in redeploy
    env_set = asyncio.run(
        main.set_service_env_var(SVC, ENV, "NEW", ENV_SECRET_VALUE, True, ctx=operator_ctx())
    )
    assert "boom-create" in env_set
    assert ENV_SECRET_VALUE not in env_set
    queries = [p["query"] for p in posted]
    assert queries.count(graphql_ops.M_REDEPLOY_SERVICE) == 1
    assert queries.count(graphql_ops.M_CREATE_ENVIRONMENT_VARIABLE) == 1
    assert graphql_ops.M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE not in queries
    assert graphql_ops.M_REDEPLOY_SERVICE not in queries[2:]


def test_bulk_update_environment_variable_is_never_used():
    sources = [
        (ROOT / "main.py").read_text(encoding="utf-8"),
        (ROOT / "graphql_ops.py").read_text(encoding="utf-8"),
    ]
    for text in sources:
        assert "updateEnvironmentVariable(" not in text
        assert "restartService" not in text
        assert "deployFromSpecification" not in text
        assert "deleteEnvironmentVariable" not in text


def test_env_value_and_auth_secrets_are_not_logged(monkeypatch, caplog):
    enable_writes(monkeypatch)
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    monkeypatch.setattr(main, "MCP_OPERATOR_URL_SECRET", OPERATOR_URL_SECRET)

    async def handler(url, body, headers):
        assert TEST_TOKEN not in json.dumps(body.get("query", ""))
        query = (body or {}).get("query", "")
        if query.strip().lower().startswith("query"):
            return _FakeResponse({"data": {"service": {"variables": []}}})
        return _FakeResponse({"errors": [{"message": "nope"}]}, status_code=500)

    with caplog.at_level(logging.DEBUG):
        with _patch_client(handler):
            result = asyncio.run(
                main.set_service_env_var(
                    SVC, ENV, "SECRET_KEY", ENV_SECRET_VALUE, True, ctx=operator_ctx()
                )
            )
        _guard_capability(query_string=f"token={TEST_URL_SECRET}")
        _guard_capability(query_string=f"token={OPERATOR_URL_SECRET}")
        _guard_capability(headers={"authorization": f"Bearer {TEST_SECRET}"})
        _guard_capability(query_string="token=wrong-url-token")

    text = caplog.text
    assert ENV_SECRET_VALUE not in result
    assert ENV_SECRET_VALUE not in text
    assert TEST_TOKEN not in text
    assert TEST_SECRET not in text
    assert TEST_URL_SECRET not in text
    assert OPERATOR_URL_SECRET not in text
    assert "wrong-url-token" not in text
    assert "Authorization: Bearer" not in text
    assert "token=" not in text


def test_missing_context_fails_closed(monkeypatch):
    enable_writes(monkeypatch)
    posted = _record_gql(monkeypatch)
    result = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=None))
    assert result.startswith("❌")
    assert posted == []

    class Boom:
        @property
        def request_context(self):
            raise ValueError("Context is not available outside of a request")

    result = asyncio.run(main.redeploy_service(SVC, ENV, True, ctx=Boom()))
    assert result.startswith("❌")
    assert posted == []


def test_no_mutation_or_network_at_import_or_list_tools():
    posted = []

    async def boom(*args, **kwargs):
        posted.append((args, kwargs))
        raise AssertionError("gql must not run at import or list_tools")

    original = main.gql
    try:
        main.gql = boom  # type: ignore[method-assign]
        names = _tool_names()
    finally:
        main.gql = original  # type: ignore[method-assign]
    assert posted == []
    assert len(names) == 11


def test_existing_url_token_read_behavior_still_works(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert _guard_status(query_string=f"token={TEST_URL_SECRET}") != 401
    status, cap = _guard_capability(query_string=f"token={TEST_URL_SECRET}")
    assert status != 401
    assert cap == main.CAPABILITY_READ


def test_existing_bearer_read_behavior_still_works():
    assert _guard_status(headers={"authorization": f"Bearer {TEST_SECRET}"}) != 401
    async def run():
        assert await main._check_bearer_token(f"Bearer {TEST_SECRET}") is True
        assert await main._check_bearer_token("Bearer not-the-secret") is False

    asyncio.run(run())


def test_existing_oauth_read_behavior_still_works(monkeypatch):
    source = inspect.getsource(main._check_bearer_token)
    assert "MCP_URL_SECRET" not in source
    assert "MCP_OPERATOR_URL_SECRET" not in source
    assert "query_string" not in source

    async def fake_valid(token: str) -> bool:
        return token == "phase-a-oauth-access"

    monkeypatch.setattr(main.oauth, "is_access_token_valid", fake_valid)

    async def run():
        assert await main._check_bearer_token("Bearer phase-a-oauth-access") is True
        assert await main._check_bearer_token("Bearer other") is False

    asyncio.run(run())
    status, cap = _guard_capability(headers={"authorization": "Bearer phase-a-oauth-access"})
    assert status != 401
    assert cap == main.CAPABILITY_READ


def test_mcp_runtime_pin_requires_1_10():
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "mcp[cli]>=1.10.0,<2.0.0" in text
    assert "mcp[cli]>=1.6.0" not in text


def test_parse_operator_policy_exact_match_tuples():
    parsed = main.parse_operator_policy(POLICY_JSON)
    assert parsed == frozenset({(SVC, ENV)})
    assert main.parse_operator_policy("") == frozenset()
    assert main.parse_operator_policy(None) == frozenset()
    assert main.parse_operator_policy("{bad") is None
    assert main.parse_operator_policy('[{"service_id": "s"}]') is None
    prefix = main.parse_operator_policy(
        json.dumps([{"service_id": SVC[:4], "environment_id": ENV}])
    )
    assert (SVC, ENV) not in prefix
