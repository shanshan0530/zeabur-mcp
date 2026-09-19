"""URL-token compatibility fallback for Streamable HTTP /mcp only.

MCP_URL_SECRET is independent of MCP_PROXY_SECRET and is disabled when unset.
Does not change OAuth or Bearer-header semantics. Does not authorize /sse.

Auth-guard cases invoke MCPAuthGuard against a dummy ASGI app so they do not
re-enter FastMCP's one-shot StreamableHTTP session manager (already started
by the existing mounted-route TestClient test).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from pathlib import Path

from fastapi.responses import JSONResponse
from starlette.requests import Request

import main
from graphql_ops import GRAPHQL_DOCUMENTS

from tests.test_phase_a import EXPECTED_REGISTERED, TEST_SECRET, _tool_names

TEST_URL_SECRET = "phase-a-url-secret"


def _asgi_scope(path: str, headers: dict[str, str] | None = None, query_string: bytes | str = b""):
    qs = query_string if isinstance(query_string, (bytes, bytearray)) else str(query_string).encode("latin-1")
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": qs,
        "headers": [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in (headers or {}).items()
        ],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
    }


def _guard_status(path: str = "/mcp", headers: dict[str, str] | None = None, query_string: bytes | str = b"") -> int:
    async def ok_app(scope, receive, send):
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
    return int(start["status"])


def test_bearer_proxy_secret_still_authorizes_mcp():
    assert _guard_status(headers={"authorization": f"Bearer {TEST_SECRET}"}) != 401


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
    assert _guard_status(headers={"authorization": "Bearer phase-a-oauth-access"}) != 401


def test_valid_url_token_authorizes_mcp_without_authorization(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert _guard_status(query_string=f"token={TEST_URL_SECRET}") != 401


def test_invalid_query_token_returns_401(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert _guard_status(query_string="token=not-the-url-secret") == 401


def test_missing_query_token_returns_401_without_other_auth(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert _guard_status() == 401


def test_url_token_disabled_when_secret_unset_or_empty(monkeypatch):
    assert not main.MCP_URL_SECRET
    # No silent fallback to MCP_PROXY_SECRET via the query string.
    assert _guard_status(query_string=f"token={TEST_SECRET}") == 401
    assert _guard_status(query_string=f"token={TEST_URL_SECRET}") == 401

    monkeypatch.setattr(main, "MCP_URL_SECRET", "")
    assert _guard_status(query_string=f"token={TEST_URL_SECRET}") == 401
    assert _guard_status(query_string="token=") == 401


def test_valid_bearer_plus_invalid_query_token_still_passes(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert (
        _guard_status(
            query_string="token=not-the-url-secret",
            headers={"authorization": f"Bearer {TEST_SECRET}"},
        )
        != 401
    )


def test_valid_query_token_plus_missing_bearer_passes(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    assert _guard_status(query_string=f"token={TEST_URL_SECRET}") != 401


def test_url_token_does_not_authorize_sse(monkeypatch):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    sse_source = inspect.getsource(main.sse_handler)
    assert "MCP_URL_SECRET" not in sse_source
    assert "_mcp_query_token_authorized" not in sse_source

    request = Request(
        _asgi_scope("/sse", query_string=f"token={TEST_URL_SECRET}")
        | {"method": "GET"}
    )

    async def run():
        resp = await main.sse_handler(request)
        assert resp.status_code == 401
        assert await main.check_bearer_auth(request) is False

    asyncio.run(run())


def test_tool_inventory_remains_exactly_nine_business_tools():
    names = _tool_names()
    assert names == EXPECTED_REGISTERED
    assert len(names) == 9


def test_no_graphql_mutation_or_write_capability_introduced():
    for name, document in GRAPHQL_DOCUMENTS.items():
        stripped = document.strip()
        assert stripped.lower().startswith("query"), name
        assert "mutation" not in document.lower(), name
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
    assert main._mcp_query_token_authorized(
        {"path": "/mcp", "query_string": f"token={TEST_SECRET}".encode("ascii")}
    ) is False


def test_url_secret_and_query_token_are_not_logged(monkeypatch, caplog):
    monkeypatch.setattr(main, "MCP_URL_SECRET", TEST_URL_SECRET)
    with caplog.at_level(logging.DEBUG):
        _guard_status(query_string=f"token={TEST_URL_SECRET}")
        _guard_status(query_string="token=wrong-url-token")
    text = caplog.text
    assert TEST_URL_SECRET not in text
    assert "wrong-url-token" not in text
    assert "token=" not in text
