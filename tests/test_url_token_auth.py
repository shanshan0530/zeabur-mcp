"""URL-token compatibility fallback for Streamable HTTP /mcp only.

MCP_URL_SECRET is independent of MCP_PROXY_SECRET and is disabled when unset.
Does not change OAuth or Bearer-header semantics. Does not authorize /sse.
"""

from __future__ import annotations

import asyncio
import inspect
import logging

from fastapi.testclient import TestClient

import main
from graphql_ops import GRAPHQL_DOCUMENTS

from tests.test_phase_a import EXPECTED_REGISTERED, TEST_SECRET, _tool_names

TEST_URL_SECRET = "phase-a-url-secret"
PING = {"jsonrpc": "2.0", "method": "ping", "id": 1}


def _post_mcp(client: TestClient, **kwargs):
    return client.post("/mcp", json=PING, **kwargs)


def test_bearer_proxy_secret_still_authorizes_mcp():
    with TestClient(main.app) as client:
        resp = _post_mcp(client, headers={"Authorization": f"Bearer {TEST_SECRET}"})
        assert resp.status_code != 401


def test_oauth_bearer_path_unchanged(monkeypatch):
    source = inspect.getsource(main._check_bearer_token)
    assert "MCP_URL_SECRET" not in source
    assert "query_string" not in source
    assert "parse_qs" not in source

    async def fake_valid(token: str) -> bool:
        return token == "phase-a-oauth-access"

    monkeypatch.setattr(main.oauth, "is_access_token_valid", fake_valid)

    async def run():
        assert await main._check_bearer_token("Bearer phase-a-oauth-access") is True
        assert await main._check_bearer_token("Bearer other") is False

    asyncio.run(run())

    with TestClient(main.app) as client:
        resp = _post_mcp(client, headers={"Authorization": "Bearer phase-a-oauth-access"})
        assert resp.status_code != 401


def test_valid_url_token_authorizes_mcp_without_authorization(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    with TestClient(main.app) as client:
        resp = _post_mcp(client, params={"token": TEST_URL_SECRET})
        assert resp.status_code != 401


def test_invalid_query_token_returns_401(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    with TestClient(main.app) as client:
        resp = _post_mcp(client, params={"token": "not-the-url-secret"})
        assert resp.status_code == 401


def test_missing_query_token_returns_401_without_other_auth(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    with TestClient(main.app) as client:
        resp = _post_mcp(client)
        assert resp.status_code == 401


def test_url_token_disabled_when_secret_unset_or_empty(monkeypatch):
    assert not main.MCP_URL_SECRET

    with TestClient(main.app) as client:
        # No silent fallback to MCP_PROXY_SECRET via the query string.
        resp = _post_mcp(client, params={"token": TEST_SECRET})
        assert resp.status_code == 401
        resp = _post_mcp(client, params={"token": TEST_URL_SECRET})
        assert resp.status_code == 401

    monkeypatch.setattr(main, "MCP_URL_SECRET", "")
    with TestClient(main.app) as client:
        resp = _post_mcp(client, params={"token": TEST_URL_SECRET})
        assert resp.status_code == 401
        resp = _post_mcp(client, params={"token": ""})
        assert resp.status_code == 401


def test_valid_bearer_plus_invalid_query_token_still_passes(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    with TestClient(main.app) as client:
        resp = _post_mcp(
            client,
            params={"token": "not-the-url-secret"},
            headers={"Authorization": f"Bearer {TEST_SECRET}"},
        )
        assert resp.status_code != 401


def test_valid_query_token_plus_missing_bearer_passes(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    with TestClient(main.app) as client:
        resp = _post_mcp(client, params={"token": TEST_URL_SECRET})
        assert resp.status_code != 401


def test_url_token_does_not_authorize_sse(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    sse_source = inspect.getsource(main.sse_handler)
    assert "MCP_URL_SECRET" not in sse_source
    assert "_mcp_query_token_authorized" not in sse_source

    with TestClient(main.app) as client:
        resp = client.get("/sse", params={"token": TEST_URL_SECRET})
        assert resp.status_code == 401
        still_unauth = client.get("/sse")
        assert still_unauth.status_code == 401


def test_tool_inventory_remains_exactly_nine_business_tools():
    names = _tool_names()
    assert names == EXPECTED_REGISTERED
    assert len(names) == 9


def test_no_graphql_mutation_or_write_capability_introduced():
    for name, document in GRAPHQL_DOCUMENTS.items():
        stripped = document.strip()
        assert stripped.lower().startswith("query"), name
        assert "mutation" not in document.lower(), name
    from pathlib import Path

    source = Path(main.__file__).read_text(encoding="utf-8")
    assert "mutation" not in source.lower()


def test_query_token_helper_is_mcp_only_and_independent(monkeypatch):
    mcp_qs = f"token={TEST_URL_SECRET}".encode("ascii")
    assert main._mcp_query_token_authorized({"path": "/mcp", "query_string": mcp_qs}) is False

    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert main._mcp_query_token_authorized({"path": "/mcp", "query_string": mcp_qs}) is True
    assert main._mcp_query_token_authorized({"path": "/sse", "query_string": mcp_qs}) is False
    assert main._mcp_query_token_authorized({"path": "/authorize", "query_string": mcp_qs}) is False
    assert main._mcp_query_token_authorized({"path": "/token", "query_string": mcp_qs}) is False
    assert main._mcp_query_token_authorized({"path": "/register", "query_string": mcp_qs}) is False
    assert main._mcp_query_token_authorized({"path": "/health", "query_string": mcp_qs}) is False
    assert main._mcp_query_token_authorized({"path": "/mcp", "query_string": b"token=wrong"}) is False
    # No silent reuse of MCP_PROXY_SECRET.
    assert main._mcp_query_token_authorized(
        {"path": "/mcp", "query_string": f"token={TEST_SECRET}".encode("ascii")}
    ) is False


def test_url_secret_and_query_token_are_not_logged(monkeypatch, caplog):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    with caplog.at_level(logging.DEBUG):
        with TestClient(main.app) as client:
            _post_mcp(client, params={"token": TEST_URL_SECRET})
            _post_mcp(client, params={"token": "wrong-url-token"})
    text = caplog.text
    assert TEST_URL_SECRET not in text
    assert "wrong-url-token" not in text
    assert "token=" not in text
