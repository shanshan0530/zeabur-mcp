import os
import json
import asyncio
import logging
import secrets
import traceback
import httpx
from urllib.parse import parse_qs, urlparse
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse, RedirectResponse
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.sse import SseServerTransport
from mcp.server.transport_security import TransportSecuritySettings
from starlette.routing import Mount

import oauth
from authorize_page import render_authorize_page
from graphql_ops import (
    M_CREATE_ENVIRONMENT_VARIABLE,
    M_REDEPLOY_SERVICE,
    M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE,
    Q_GET_BUILD_LOGS,
    Q_GET_DEPLOYMENTS,
    Q_GET_ME,
    Q_GET_RUNTIME_LOGS,
    Q_GET_SERVICE,
    Q_LIST_PROJECTS,
    Q_LIST_REGIONS,
    Q_LIST_SERVICES,
    Q_SCAN_PROJECTS,
    Q_SCAN_RUNTIME_LOGS,
    Q_SCAN_SERVICES,
    Q_SERVICE_VARIABLE_KEYS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("zeabur-mcp")

ZEABUR_TOKEN = os.environ.get("ZEABUR_TOKEN", "").strip()
# 访问口令：Claude 走完整 OAuth 拿动态 token，其他客户端直接把这个原文放进
# Authorization: Bearer 头。留空则不校验（向后兼容，但等于服务完全公开）。
MCP_PROXY_SECRET = os.environ.get("MCP_PROXY_SECRET", "").strip()
# Optional /mcp?token= compatibility fallback for clients that cannot send
# Authorization headers. Independent of MCP_PROXY_SECRET: empty/unset disables
# this path entirely (no silent reuse of MCP_PROXY_SECRET). URL credentials may
# be recorded by proxies; this is intentionally opt-in and independently rotatable.
MCP_URL_SECRET = os.environ.get("MCP_URL_SECRET", "").strip()
# Optional /mcp?token= operator credential. Independent of MCP_URL_SECRET and
# MCP_PROXY_SECRET: empty/unset disables this path; never falls back to another
# secret. Grants OPERATOR capability only.
MCP_OPERATOR_URL_SECRET = os.environ.get("MCP_OPERATOR_URL_SECRET", "").strip()
# Master write gate. Unset / any non-truthy value => write tools refuse before
# any Zeabur mutation. Operator credentials may still use read-only tools.
MCP_WRITES_ENABLED = os.environ.get("MCP_WRITES_ENABLED", "").strip().lower() in {
    "1", "true", "yes", "on",
}
# 显式指定对外域名，用于生成 OAuth 元数据里的 URL；不设置则从请求头拼（不完全可靠）
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").strip()
PORT = int(os.environ.get("PORT", 8765))
GRAPHQL_URL = "https://api.zeabur.com/graphql"

CAPABILITY_READ = "READ"
CAPABILITY_OPERATOR = "OPERATOR"
SCOPE_CAPABILITY_KEY = "zeabur_capability"

def _build_transport_security() -> TransportSecuritySettings:
    """从 PUBLIC_BASE_URL 解析出对外域名，加入 DNS 重绑定防护（MCP SDK 自带机制）的
    allowed_hosts 白名单。不写死域名，方便以后换绑域名时不用改代码。

    没配置 PUBLIC_BASE_URL 时无法生成白名单，这里选择禁用这层防护
    （enable_dns_rebinding_protection=False）而不是把服务锁死在默认的
    "只信任 localhost" 上——这跟 SDK 本身在完全不传 transport_security 时的
    默认行为一致，不是额外发明的降级逻辑，只是把原因用 WARNING 日志说清楚。
    """
    if not PUBLIC_BASE_URL:
        logger.warning(
            "PUBLIC_BASE_URL 未配置，无法为 DNS 重绑定防护生成 allowed_hosts 白名单，"
            "已禁用该防护（enable_dns_rebinding_protection=False）以避免服务被锁死；"
            "强烈建议配置 PUBLIC_BASE_URL 以恢复防护"
        )
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    host = urlparse(PUBLIC_BASE_URL).netloc
    if not host:
        logger.warning(
            "PUBLIC_BASE_URL=%s 格式不对，urlparse 解析不出 host（netloc 为空），"
            "DNS 重绑定防护已禁用，请检查这个环境变量是不是漏了 https:// 前缀",
            PUBLIC_BASE_URL,
        )
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    logger.info("DNS 重绑定防护 allowed_hosts=%s", [host, f"{host}:*"])
    return TransportSecuritySettings(allowed_hosts=[host, f"{host}:*"])


mcp = FastMCP(
    "Zeabur",
    # 无状态模式：每个请求独立处理，不依赖跨请求的 session 状态。
    # 对应 supabase 仓库 server.js 里 StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
    # 的做法；Zeabur 单实例部署下也能避免多副本场景常见的 "session not found" 问题。
    stateless_http=True,
    # 普通 JSON 响应而不是 SSE 流，避免响应被中间件缓冲/破坏的问题。
    json_response=True,
    # DNS 重绑定防护白名单。不传这个参数时 SDK 默认只信任 Host 为 localhost 的请求，
    # 部署在 Zeabur 真实域名后面的服务会被自己的 SDK 拒绝（421 Misdirected Request），
    # 这正是 2026-07-02 排查到的、跟 OAuth 无关的独立 bug。
    transport_security=_build_transport_security(),
)


# ── GraphQL Helper ────────────────────────────────────────────────────────────

def _redact_known_secret_value(value):
    """Replace values that equal configured secrets. Never log the secrets themselves."""
    if not isinstance(value, str) or not value:
        return value
    for secret in (
        ZEABUR_TOKEN,
        MCP_PROXY_SECRET,
        MCP_URL_SECRET,
        MCP_OPERATOR_URL_SECRET,
    ):
        if secret and value == secret:
            return "[REDACTED]"
    return value


def _safe_gql_variables(variables: dict | None, redact_keys: set | frozenset | None = None) -> dict | None:
    """Copy GraphQL variables for logging. Read-only calls keep keys/values;
    callers that pass secret env values must supply redact_keys (e.g. {'value'}).
    """
    if not variables:
        return variables
    redact = set(redact_keys or ())
    safe = {}
    for key, value in variables.items():
        if key in redact:
            safe[key] = "[REDACTED]"
        else:
            safe[key] = _redact_known_secret_value(value)
    return safe


async def gql(query: str, variables: dict = None, *, redact_keys: set | frozenset | None = None) -> dict:
    """调用 Zeabur GraphQL API。所有网络/解析异常均在此处捕获并记录日志，不会向上抛出。

    redact_keys: variable names whose values must never appear in logs (env writes).
    Authorization headers and ZEABUR_TOKEN are never logged.
    """
    if not ZEABUR_TOKEN:
        logger.error("gql 调用失败: ZEABUR_TOKEN 未设置")
        return {"error": "ZEABUR_TOKEN 未设置"}

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ZEABUR_TOKEN}",
    }
    body = {"query": query}
    if variables:
        body["variables"] = variables

    log_vars = _safe_gql_variables(variables, redact_keys)
    redact_body = bool(redact_keys)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(GRAPHQL_URL, json=body, headers=headers)
    except httpx.TimeoutException:
        logger.error(
            "gql 请求超时 | variables=%s\n%s", log_vars, traceback.format_exc()
        )
        return {"error": "请求 Zeabur API 超时（30s），请稍后重试"}
    except httpx.RequestError as e:
        logger.error(
            "gql 网络请求异常: %s | variables=%s\n%s",
            e, log_vars, traceback.format_exc()
        )
        return {"error": f"网络请求失败: {e}"}
    except Exception as e:
        logger.error(
            "gql 请求发生未预期异常: %s | variables=%s\n%s",
            e, log_vars, traceback.format_exc()
        )
        return {"error": f"请求异常: {e}"}

    try:
        data = resp.json()
    except (ValueError, json.JSONDecodeError):
        logger.error(
            "gql 响应非 JSON | status=%s body=%s\n%s",
            resp.status_code,
            "[REDACTED]" if redact_body else resp.text[:500],
            traceback.format_exc(),
        )
        return {"error": f"Zeabur API 返回了非 JSON 响应 (HTTP {resp.status_code})"}

    if resp.status_code >= 400:
        if redact_body:
            logger.error(
                "gql HTTP 错误 status=%s | variables=%s | body=[REDACTED]",
                resp.status_code, log_vars,
            )
            return {"error": f"HTTP {resp.status_code}"}
        logger.error(
            "gql HTTP 错误 status=%s | variables=%s | body=%s",
            resp.status_code, log_vars, data
        )
        return {"error": data.get("errors") or f"HTTP {resp.status_code}: {data}"}

    if "errors" in data:
        if redact_body:
            logger.error(
                "gql GraphQL 错误 | variables=%s | errors=[REDACTED]",
                log_vars,
            )
            return {"error": "GraphQL error"}
        logger.error(
            "gql GraphQL 错误 | variables=%s | errors=%s", log_vars, data["errors"]
        )
        return {"error": data["errors"]}

    return data.get("data", {})


def _err(prefix: str, e: Exception, **ctx) -> str:
    """统一的工具层异常处理：记录堆栈+关键变量，返回给用户的友好提示。"""
    logger.error("%s 异常: %s | ctx=%s\n%s", prefix, e, ctx, traceback.format_exc())
    return f"❌ {prefix} 处理出错，已记录日志: {e}"


def _capability_from_ctx(ctx) -> str | None:
    """Read request-scoped capability. Missing request/context/state => fail closed."""
    if ctx is None:
        return None
    try:
        request_context = ctx.request_context
        request = getattr(request_context, "request", None)
        if request is None:
            return None
        scope = getattr(request, "scope", None)
        if not isinstance(scope, dict):
            return None
        state = scope.get("state")
        if not isinstance(state, dict):
            return None
        cap = state.get(SCOPE_CAPABILITY_KEY)
        if cap in (CAPABILITY_READ, CAPABILITY_OPERATOR):
            return cap
        return None
    except Exception:
        return None


def _write_preflight(ctx) -> str | None:
    """Shared write gates. Returns a refusal string, or None if the mutation may proceed
    past capability / master-gate checks. Target access is whatever ZEABUR_TOKEN can reach.
    """
    if _capability_from_ctx(ctx) != CAPABILITY_OPERATOR:
        return "❌ OPERATOR capability required; write refused"
    if not MCP_WRITES_ENABLED:
        return "❌ Writes are disabled (MCP_WRITES_ENABLED); write refused"
    return None


# ── MCP 工具 ───────────────────────────────────────────────────────────

@mcp.tool()
async def list_projects() -> str:
    """列出所有 Zeabur 项目，返回 project_id、项目名和环境列表（含 环境id）。
    查日志前先调用此工具获取 project_id 和 环境id。"""
    try:
        data = await gql(Q_LIST_PROJECTS)
        if "error" in data:
            return f"❌ {data['error']}"
        edges = data.get("projects", {}).get("edges", [])
        if not edges:
            return "📭 没有项目"
        lines = []
        for e in edges:
            n = e["node"]
            lines.append(f"📦 {n['name']}")
            lines.append(f"   project_id: {n['_id']}")
            for env in n.get("environments", []):
                lines.append(f"   🌍 环境: {env['name']}  environment_id: {env['_id']}")
        return "\n".join(lines)
    except Exception as e:
        return _err("list_projects", e)


@mcp.tool()
async def list_services(project_id: str) -> str:
    """列出指定项目下的所有服务，返回服务名和 service_id。"""
    try:
        data = await gql(Q_LIST_SERVICES, {"projectID": project_id})
        if "error" in data:
            return f"❌ {data['error']}"
        edges = data.get("services", {}).get("edges", [])
        if not edges:
            return "📭 没有服务"
        lines = []
        for e in edges:
            n = e["node"]
            lines.append(f"🔧 {n['name']}  service_id: {n['_id']}")
        return "\n".join(lines)
    except Exception as e:
        return _err("list_services", e, project_id=project_id)


@mcp.tool()
async def get_runtime_logs(service_id: str, environment_id: str, project_id: str) -> str:
    """获取服务运行时日志（启动输出、报错等）。
    service_id 从 list_services 获取，environment_id 和 project_id 从 list_projects 获取。"""
    try:
        data = await gql(Q_GET_RUNTIME_LOGS, {"projectID": project_id, "serviceID": service_id, "environmentID": environment_id})
        if "error" in data:
            return f"❌ {data['error']}"
        logs = data.get("runtimeLogs", [])
        if not logs:
            return "📭 没有运行时日志"
        lines = [f"📋 Runtime 日志（共 {len(logs)} 条，显示最后 50 条）"]
        for entry in logs[-50:]:
            ts = (entry.get("timestamp") or "")[:19]
            lines.append(f"[{ts}] {entry.get('message', '')}")
        return "\n".join(lines)
    except Exception as e:
        return _err("get_runtime_logs", e, service_id=service_id, environment_id=environment_id, project_id=project_id)


@mcp.tool()
async def get_deployments(service_id: str, environment_id: str, project_id: str) -> str:
    """获取服务的部署列表（含 deployment_id 和状态）。
    查 build 日志前需先调用此工具获取 deployment_id。
    project_id 和 environment_id 从 list_projects 获取。"""
    try:
        data = await gql(Q_GET_DEPLOYMENTS, {"serviceID": service_id, "environmentID": environment_id})
        if "error" in data:
            return f"❌ {data['error']}"
        edges = data.get("deployments", {}).get("edges", [])
        if not edges:
            return "📭 没有部署记录"
        lines = ["📋 部署列表"]
        for e in edges:
            n = e["node"]
            ts = (n.get("createdAt") or "")[:19]
            lines.append(f"[{ts}] {n['status']}  deployment_id: {n['_id']}")
        return "\n".join(lines)
    except Exception as e:
        return _err("get_deployments", e, service_id=service_id, environment_id=environment_id, project_id=project_id)


@mcp.tool()
async def get_build_logs(deployment_id: str, project_id: str, tail: int = 30, errors_only: bool = True) -> str:
    """获取指定部署的构建日志（依赖安装、编译过程）。
    deployment_id 从 get_deployments 获取，project_id 从 list_projects 获取。
    tail: 返回最后几条，默认30。
    errors_only: 默认True，只返回包含错误关键词的行，大幅减少无用日志。设为False看全部。"""
    try:
        ERROR_KW = {"error", "err!", "failed", "fatal", "exception", "cannot", "not found", "ts2", "ts1", "syntaxerror", "typeerror", "referenceerror"}
        data = await gql(Q_GET_BUILD_LOGS, {"projectID": project_id, "deploymentID": deployment_id})
        if "error" in data:
            return f"❌ {data['error']}"
        logs = data.get("buildLogs", [])
        if not logs:
            return "📭 没有构建日志"
        if errors_only:
            filtered = [e for e in logs if any(kw in e.get("message", "").lower() for kw in ERROR_KW)]
            if not filtered:
                return f"✅ 构建日志共 {len(logs)} 条，未发现错误关键词。如需查看全部日志，设 errors_only=False"
            logs = filtered
        show = logs[-tail:]
        lines = [f"📋 Build 日志（共 {len(logs)} 条{' (已过滤错误)' if errors_only else ''}，显示最后 {len(show)} 条）"]
        for entry in show:
            ts = (entry.get("timestamp") or "")[:19]
            lines.append(f"[{ts}] {entry.get('message', '')}")
        return "\n".join(lines)
    except Exception as e:
        return _err("get_build_logs", e, deployment_id=deployment_id, project_id=project_id, tail=tail, errors_only=errors_only)


@mcp.tool()
async def scan_all_logs() -> str:
    """并发扫描所有项目下所有服务（含所有环境）的运行时日志，过滤出包含错误关键词的行。
    用于快速排查所有服务健康状态，无需逐个查询。"""
    try:
        ERROR_KEYWORDS = {"error", "exception", "traceback", "failed", "critical", "fatal", "crash"}

        data = await gql(Q_SCAN_PROJECTS)
        if "error" in data:
            return f"❌ 获取项目失败: {data['error']}"

        project_envs = []
        for e in data.get("projects", {}).get("edges", []):
            n = e["node"]
            for env in n.get("environments", []):
                project_envs.append({
                    "project_id": n["_id"], "project_name": n["name"],
                    "env_id": env["_id"], "env_name": env["name"],
                })

        if not project_envs:
            return "📭 没有项目或项目下没有环境"

        async def get_services(pe):
            d = await gql(Q_SCAN_SERVICES, {"projectID": pe["project_id"]})
            if "error" in d:
                logger.error("scan_all_logs 获取服务失败 | project=%s error=%s", pe["project_name"], d["error"])
                return []
            return [
                {"id": s["node"]["_id"], "name": s["node"]["name"],
                 "project_name": pe["project_name"], "project_id": pe["project_id"],
                 "env_id": pe["env_id"], "env_name": pe["env_name"]}
                for s in d.get("services", {}).get("edges", [])
            ]

        all_services_nested = await asyncio.gather(
            *[get_services(pe) for pe in project_envs], return_exceptions=True
        )
        all_services = []
        for item in all_services_nested:
            if isinstance(item, Exception):
                logger.error("scan_all_logs 获取服务时异常: %s\n%s", item, traceback.format_exc())
                continue
            all_services.extend(item)

        if not all_services:
            return "📭 没有服务"

        async def scan_service(service):
            d = await gql(Q_SCAN_RUNTIME_LOGS, {"projectID": service["project_id"], "serviceID": service["id"], "environmentID": service["env_id"]})
            if "error" in d:
                logger.error("scan_all_logs 获取日志失败 | service=%s error=%s", service["name"], d["error"])
                return service, [f"  ⚠️ 获取该服务日志失败: {d['error']}"]
            logs = d.get("runtimeLogs", [])
            errors = [
                f"  [{(e.get('timestamp') or '')[:19]}] {e.get('message', '')}"
                for e in logs
                if any(kw in e.get("message", "").lower() for kw in ERROR_KEYWORDS)
            ]
            return service, errors

        results = await asyncio.gather(
            *[scan_service(s) for s in all_services], return_exceptions=True
        )

        has_errors = []
        clean = []
        for item in results:
            if isinstance(item, Exception):
                logger.error("scan_all_logs 扫描服务时异常: %s\n%s", item, traceback.format_exc())
                continue
            service, errors = item
            label = f"{service['project_name']}/{service['env_name']}/{service['name']}"
            if errors:
                has_errors.append((label, errors))
            else:
                clean.append(label)

        if not has_errors:
            return f"✅ 所有服务正常，未检测到错误\n   扫描了 {len(all_services)} 个服务（{len(project_envs)} 个项目-环境组合）: {', '.join(clean)}"

        lines = [f"🔍 扫描完成：{len(all_services)} 个服务，{len(has_errors)} 个有错误\n"]
        for label, errors in has_errors:
            lines.append(f"❌ {label}")
            lines.extend(errors[-10:])
            lines.append("")

        if clean:
            lines.append(f"✅ 正常: {', '.join(clean)}")

        return "\n".join(lines)
    except Exception as e:
        return _err("scan_all_logs", e)


@mcp.tool()
async def get_service(service_id: str) -> str:
    """获取指定服务的详情（状态与域名）。
    service_id 从 list_services 获取。"""
    try:
        data = await gql(Q_GET_SERVICE, {"id": service_id})
        if "error" in data:
            return f"❌ {data['error']}"
        service = data.get("service")
        if not service:
            return "📭 找不到该服务"
        lines = [
            f"🔧 {service.get('name')}  service_id: {service.get('_id')}",
            f"   状态: {service.get('status')}",
        ]
        domains = service.get("domains") or []
        if not domains:
            lines.append("   🌐 没有绑定域名")
        else:
            for domain in domains:
                lines.append(
                    f"   🌐 {domain.get('domain')}  status: {domain.get('status')}"
                )
        return "\n".join(lines)
    except Exception as e:
        return _err("get_service", e, service_id=service_id)


@mcp.tool()
async def list_regions() -> str:
    """列出当前账号可用的 Zeabur 服务器（官方 list-regions 实际查询 servers，不是共享 region 列表）。"""
    try:
        data = await gql(Q_LIST_REGIONS)
        if "error" in data:
            return f"❌ {data['error']}"
        servers = data.get("servers") or []
        if not servers:
            return "📭 没有服务器"
        lines = ["🖥️  服务器列表（list-regions → GraphQL servers）"]
        for server in servers:
            status = server.get("status") or {}
            online = "online" if status.get("isOnline") else "offline"
            loc = ", ".join(
                part for part in (server.get("city"), server.get("country")) if part
            )
            line = f"🖥️  {server.get('name')}  server_id: {server.get('_id')}  {online}"
            if loc:
                line += f"  ({loc})"
            lines.append(line)
        return "\n".join(lines)
    except Exception as e:
        return _err("list_regions", e)


@mcp.tool()
async def get_me() -> str:
    """获取当前配置的 Zeabur 账号信息（id / username / email）。"""
    try:
        data = await gql(Q_GET_ME)
        if "error" in data:
            return f"❌ {data['error']}"
        me = data.get("me")
        if not me:
            return "📭 无法读取当前账号"
        return (
            f"👤 {me.get('username')}\n"
            f"   user_id: {me.get('_id')}\n"
            f"   email: {me.get('email')}"
        )
    except Exception as e:
        return _err("get_me", e)


@mcp.tool()
async def redeploy_service(
    service_id: str,
    environment_id: str,
    ctx: Context,
    confirm: bool = False,
) -> str:
    """Redeploy a Zeabur service in one environment.

    This is redeploy, not restart, and not "deploy latest main".
    Requires OPERATOR capability, MCP_WRITES_ENABLED, and confirm=true.
    confirm=false performs zero network calls. Target access is whatever
    ZEABUR_TOKEN itself can reach; there is no MCP-side service allowlist.
    """
    try:
        refusal = _write_preflight(ctx)
        if refusal:
            return refusal
        if not confirm:
            return (
                f"Dry-run: would redeploy service_id={service_id} "
                f"environment_id={environment_id}. Set confirm=true to execute. "
                "No network call was made."
            )
        data = await gql(
            M_REDEPLOY_SERVICE,
            {"serviceID": service_id, "environmentID": environment_id},
        )
        if "error" in data:
            return f"❌ Redeploy failed for service_id={service_id} environment_id={environment_id}: {data['error']}"
        ok = data.get("redeployService")
        if ok is True:
            return (
                f"Redeploy accepted: service_id={service_id} "
                f"environment_id={environment_id} status=success"
            )
        return (
            f"❌ Redeploy did not succeed for service_id={service_id} "
            f"environment_id={environment_id} status={ok!r}"
        )
    except Exception as e:
        return _err("redeploy_service", e, service_id=service_id, environment_id=environment_id)


def _variable_keys_from_lookup(data: dict) -> set[str] | None:
    """Return env-var keys, or None on lookup failure.

    valid service + valid variables list => set of keys
    explicit empty variables list => empty set
    missing/null/malformed service or variables => None (do not treat as absent)
    """
    if "error" in data:
        return None
    service = data.get("service")
    if not isinstance(service, dict):
        return None
    if "variables" not in service:
        return None
    variables = service["variables"]
    if not isinstance(variables, list):
        return None
    keys = set()
    for item in variables:
        if not isinstance(item, dict):
            return None
        key = item.get("key")
        if not isinstance(key, str) or not key:
            return None
        keys.add(key)
    return keys


@mcp.tool()
async def set_service_env_var(
    service_id: str,
    environment_id: str,
    key: str,
    value: str,
    ctx: Context,
    confirm: bool = False,
) -> str:
    """Create or update one environment variable on a service/environment.

    Looks up KEYS only (never current values). confirm=false reports would-create
    or would-update and performs no mutation. Does not redeploy afterwards.
    The supplied value is never returned or logged. Target access is whatever
    ZEABUR_TOKEN itself can reach; there is no MCP-side service allowlist.
    """
    try:
        refusal = _write_preflight(ctx)
        if refusal:
            return refusal
        lookup = await gql(
            Q_SERVICE_VARIABLE_KEYS,
            {"serviceID": service_id, "environmentID": environment_id},
        )
        keys = _variable_keys_from_lookup(lookup)
        if keys is None:
            return (
                f"❌ Env key lookup failed for service_id={service_id} "
                f"environment_id={environment_id} key={key}: {lookup.get('error')}"
            )
        exists = key in keys
        if not confirm:
            action = "would update" if exists else "would create"
            return (
                f"Dry-run: {action} key={key} on service_id={service_id} "
                f"environment_id={environment_id}. Set confirm=true to execute. "
                "No mutation was made."
            )
        if not exists:
            result = await gql(
                M_CREATE_ENVIRONMENT_VARIABLE,
                {
                    "serviceID": service_id,
                    "environmentID": environment_id,
                    "key": key,
                    "value": value,
                },
                redact_keys={"value"},
            )
            if "error" in result:
                return (
                    f"❌ Create env var failed for service_id={service_id} "
                    f"environment_id={environment_id} key={key}: {result['error']}"
                )
            return (
                f"Env var created: service_id={service_id} "
                f"environment_id={environment_id} key={key} status=success"
            )
        result = await gql(
            M_UPDATE_SINGLE_ENVIRONMENT_VARIABLE,
            {
                "serviceID": service_id,
                "environmentID": environment_id,
                "oldKey": key,
                "newKey": key,
                "value": value,
            },
            redact_keys={"value"},
        )
        if "error" in result:
            return (
                f"❌ Update env var failed for service_id={service_id} "
                f"environment_id={environment_id} key={key}: {result['error']}"
            )
        return (
            f"Env var updated: service_id={service_id} "
            f"environment_id={environment_id} key={key} status=success"
        )
    except Exception as e:
        return _err(
            "set_service_env_var",
            e,
            service_id=service_id,
            environment_id=environment_id,
            key=key,
        )


# ── FastAPI + 传输层 ──────────────────────────────────────────────────────

# 关键：mcp.streamable_http_app() 要求 FastAPI 的 lifespan 运行 mcp.session_manager.run()，
# 否则 /mcp 端点会在建立会话时直接失败（官方 SDK issue #713 就是这个问题）。
# 这个坑从最初版本的 main.py 就存在，跟鉴权无关，是必须的基础配置。
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp.session_manager.run():
        yield

app = FastAPI(title="Zeabur MCP", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_base_url(request: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    return f"{proto}://{host}"


async def _check_bearer_token(auth_header: str) -> bool:
    """统一鉴权核心逻辑，接收原始 Authorization 头字符串。
    MCP_PROXY_SECRET 未设置时不校验（向后兼容，等于服务公开）。
    已设置时，token 可以是 MCP_PROXY_SECRET 原文（纯字符串比较，走这条不用查数据库，
    放在前面判断可以少一次网络往返），也可以是 OAuth 流程颁发的动态 access_token
    （需要查 Supabase 里的 mcp_oauth_store 表）。"""
    if not MCP_PROXY_SECRET:
        logger.warning("MCP_PROXY_SECRET 未配置，当前处于无鉴权状态，任何人拿到 URL 都能操作你的 Zeabur")
        return True
    bearer_token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else None
    if not bearer_token:
        return False
    if bearer_token == MCP_PROXY_SECRET:
        return True
    if await oauth.is_access_token_valid(bearer_token):
        return True
    return False


async def check_bearer_auth(request: Request) -> bool:
    return await _check_bearer_token(request.headers.get("authorization", ""))


def _mcp_query_token_authorized(scope: dict) -> bool:
    """Narrow /mcp-only URL-token fallback. Does not apply to /sse or OAuth routes.

    Disabled when MCP_URL_SECRET is empty/unset. Never falls back to
    MCP_PROXY_SECRET. Does not log the secret, the supplied token, or the raw
    query string.
    """
    if not MCP_URL_SECRET:
        return False
    path = scope.get("path") or ""
    if path != "/mcp":
        return False
    supplied = _mcp_query_token(scope)
    if supplied is None:
        return False
    try:
        return secrets.compare_digest(supplied, MCP_URL_SECRET)
    except (TypeError, ValueError):
        return False


def _mcp_operator_query_token_authorized(scope: dict) -> bool:
    """Independent /mcp-only operator URL-token. Never falls back to another secret.

    Disabled when MCP_OPERATOR_URL_SECRET is empty/unset. Does not log the secret,
    the supplied token, or the raw query string.
    """
    if not MCP_OPERATOR_URL_SECRET:
        return False
    path = scope.get("path") or ""
    if path != "/mcp":
        return False
    supplied = _mcp_query_token(scope)
    if supplied is None:
        return False
    try:
        return secrets.compare_digest(supplied, MCP_OPERATOR_URL_SECRET)
    except (TypeError, ValueError):
        return False


def _mcp_query_token(scope: dict) -> str | None:
    query_string = scope.get("query_string") or b""
    try:
        raw = (
            query_string.decode("latin-1")
            if isinstance(query_string, (bytes, bytearray))
            else str(query_string)
        )
        params = parse_qs(raw, keep_blank_values=False)
    except Exception:
        return None
    supplied_values = params.get("token") or []
    if not supplied_values:
        return None
    return supplied_values[0]


def _bearer_token(auth_header: str) -> str | None:
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        return token or None
    return None


async def _resolve_request_capability(scope: dict, auth_header: str) -> str | None:
    """Map the current ASGI request to READ / OPERATOR, or None if unauthorized.

    Classification:
    - MCP_PROXY_SECRET Bearer => OPERATOR
    - MCP_OPERATOR_URL_SECRET /mcp?token= => OPERATOR
    - MCP_URL_SECRET /mcp?token= => READ
    - valid OAuth access token => READ
    - MCP_PROXY_SECRET unset (open mode) => READ (writes still fail closed)
    - invalid/no credential => None
    """
    bearer = _bearer_token(auth_header)

    if MCP_PROXY_SECRET and bearer and bearer == MCP_PROXY_SECRET:
        return CAPABILITY_OPERATOR

    if _mcp_operator_query_token_authorized(scope):
        return CAPABILITY_OPERATOR

    if _mcp_query_token_authorized(scope):
        return CAPABILITY_READ

    if bearer and await oauth.is_access_token_valid(bearer):
        return CAPABILITY_READ

    if not MCP_PROXY_SECRET:
        logger.warning("MCP_PROXY_SECRET 未配置，当前处于无鉴权状态，任何人拿到 URL 都能操作你的 Zeabur")
        return CAPABILITY_READ

    return None


async def _parse_body(request: Request) -> dict:
    """兼容 JSON 和 form-urlencoded 两种提交方式（OAuth /token /register 各家客户端实现不完全一致）。"""
    content_type = request.headers.get("content-type", "")
    try:
        if "application/json" in content_type:
            return dict(await request.json())
        form = await request.form()
        return dict(form)
    except Exception as e:
        logger.error("请求体解析失败 content_type=%s | %s\n%s", content_type, e, traceback.format_exc())
        return {}


# ── OAuth 2.1 (PKCE) 端点 ───────────────────────────────────────────

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    base = get_base_url(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    base = get_base_url(request)
    return JSONResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
    })


@app.post("/register")
async def oauth_register(request: Request):
    body = await _parse_body(request)
    try:
        client = await oauth.register_client(body.get("client_name"), body.get("redirect_uris"))
        return JSONResponse(status_code=201, content={
            "client_id": client["client_id"],
            "client_name": client["client_name"],
            "redirect_uris": client["redirect_uris"],
            "grant_types": client["grant_types"],
            "response_types": client["response_types"],
            "token_endpoint_auth_method": client["token_endpoint_auth_method"],
        })
    except Exception as e:
        logger.error("客户端注册失败: %s | body=%s\n%s", e, body, traceback.format_exc())
        return JSONResponse(status_code=400, content={"error": "invalid_client_metadata", "error_description": str(e)})


@app.get("/authorize")
async def oauth_authorize_get(request: Request):
    q = request.query_params
    response_type = q.get("response_type")
    client_id = q.get("client_id")
    redirect_uri = q.get("redirect_uri")
    code_challenge = q.get("code_challenge")
    code_challenge_method = q.get("code_challenge_method")
    state = q.get("state")
    scope = q.get("scope")

    if response_type != "code":
        return PlainTextResponse("只支持 response_type=code", status_code=400)

    try:
        client = await oauth.get_client(client_id)
    except Exception as e:
        logger.error("oauth_authorize_get 查询 client 失败: %s | client_id=%s\n%s", e, client_id, traceback.format_exc())
        return PlainTextResponse("服务器内部错误：OAuth 存储暂时不可用，请稍后重试", status_code=500)

    if not client:
        return PlainTextResponse("未知的 client_id，请先完成动态客户端注册", status_code=400)
    if redirect_uri not in client["redirect_uris"]:
        return PlainTextResponse("redirect_uri 和注册时的不一致", status_code=400)
    if not code_challenge or code_challenge_method != "S256":
        return PlainTextResponse("缺少 PKCE 参数，或 code_challenge_method 不是 S256", status_code=400)

    return HTMLResponse(render_authorize_page({
        "response_type": response_type, "client_id": client_id, "redirect_uri": redirect_uri,
        "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
        "state": state, "scope": scope,
    }))


@app.post("/authorize")
async def oauth_authorize_post(request: Request):
    body = await _parse_body(request)
    response_type = body.get("response_type")
    client_id = body.get("client_id")
    redirect_uri = body.get("redirect_uri")
    code_challenge = body.get("code_challenge")
    code_challenge_method = body.get("code_challenge_method")
    state = body.get("state")
    scope = body.get("scope")
    key = body.get("key")

    oauth_params = {
        "response_type": response_type, "client_id": client_id, "redirect_uri": redirect_uri,
        "code_challenge": code_challenge, "code_challenge_method": code_challenge_method,
        "state": state, "scope": scope,
    }

    if not MCP_PROXY_SECRET:
        logger.warning("MCP_PROXY_SECRET 未配置，拒绝所有授权请求，请先在环境变量里配置")
        return HTMLResponse(
            render_authorize_page(oauth_params, "服务器还没配置 MCP_PROXY_SECRET，无法完成授权，请先去 Zeabur 环境变量里配置。"),
            status_code=500,
        )

    if key != MCP_PROXY_SECRET:
        logger.warning("授权密钥不对，拒绝授权 | client_id=%s", client_id)
        return HTMLResponse(render_authorize_page(oauth_params, "密钥不对，请重新输入。"), status_code=401)

    try:
        client = await oauth.get_client(client_id)
        if not client or redirect_uri not in client["redirect_uris"]:
            return PlainTextResponse("client_id 或 redirect_uri 无效", status_code=400)

        code = await oauth.create_auth_code(client_id, redirect_uri, code_challenge, code_challenge_method, scope)
        sep = "&" if "?" in redirect_uri else "?"
        redirect_url = f"{redirect_uri}{sep}code={code}"
        if state:
            redirect_url += f"&state={state}"
        logger.info("授权成功，重定向回客户端 | client_id=%s", client_id)
        return RedirectResponse(redirect_url, status_code=302)
    except Exception as e:
        logger.error("生成授权码失败: %s | client_id=%s\n%s", e, client_id, traceback.format_exc())
        return PlainTextResponse("服务器内部错误", status_code=500)


@app.post("/token")
async def oauth_token(request: Request):
    body = await _parse_body(request)
    grant_type = body.get("grant_type")
    try:
        if grant_type == "authorization_code":
            code = body.get("code")
            redirect_uri = body.get("redirect_uri")
            client_id = body.get("client_id")
            code_verifier = body.get("code_verifier")

            record = await oauth.consume_auth_code(code)
            if not record:
                return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "授权码无效或已过期"})
            if record["client_id"] != client_id or record["redirect_uri"] != redirect_uri:
                return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "client_id 或 redirect_uri 不匹配"})
            if not oauth.verify_pkce(code_verifier, record["code_challenge"], record["code_challenge_method"]):
                return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "PKCE 校验失败: code_verifier 和 code_challenge 对不上"})

            tokens = await oauth.issue_tokens()
            logger.info("颁发新令牌 | client_id=%s grant_type=%s", client_id, grant_type)
            return JSONResponse(tokens)

        if grant_type == "refresh_token":
            refresh_token = body.get("refresh_token")
            tokens = await oauth.rotate_refresh_token(refresh_token)
            if not tokens:
                return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": "refresh_token 无效或已过期"})
            logger.info("刷新令牌成功 | grant_type=%s", grant_type)
            return JSONResponse(tokens)

        return JSONResponse(status_code=400, content={"error": "unsupported_grant_type", "error_description": f"不支持的 grant_type: {grant_type}"})
    except Exception as e:
        logger.error("颁发令牌失败: %s | grant_type=%s\n%s", e, grant_type, traceback.format_exc())
        return JSONResponse(status_code=400, content={"error": "invalid_grant", "error_description": str(e)})


# ── SSE 传输层（带鉴权） ──────────────────────────────────────────────

_sse = SseServerTransport("/messages/")
app.router.routes.append(Mount("/messages", app=_sse.handle_post_message))

@app.get("/sse")
async def sse_handler(request: Request):
    if not await check_bearer_auth(request):
        logger.warning("拒绝未授权的 /sse 连接 | client=%s", request.client)
        return PlainTextResponse("Unauthorized: 请带上 Authorization: Bearer <token>", status_code=401)
    try:
        async with _sse.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await mcp._mcp_server.run(
                read_stream,
                write_stream,
                mcp._mcp_server.create_initialization_options(),
            )
    except Exception as e:
        logger.error("sse_handler 异常: %s\n%s", e, traceback.format_exc())
        raise

# ── Streamable HTTP 传输层（带鉴权，纯 ASGI 包装，不用 BaseHTTPMiddleware） ──────

class MCPAuthGuard:
    """FastAPI 的 @app.middleware("http") 底层是 Starlette 的 BaseHTTPMiddleware，
    它会把响应体读进内存再转发，破坏流式/长连接响应 —— 这正是 Streamable HTTP 协议依赖的东西。
    改成纯 ASGI 中间件，只在 scope/headers 层面做鉴权判断，不触碰 send/receive 流，
    转发行为和裸挂载完全一致。"""

    def __init__(self, asgi_app):
        self.asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.asgi_app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        auth_header = headers.get("authorization", "")
        capability = await _resolve_request_capability(scope, auth_header)
        if capability is None:
            logger.warning("拒绝未授权的 /mcp 请求 | path=%s", scope.get("path"))
            response = JSONResponse(
                status_code=401,
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": "鉴权失败：请在请求头带 Authorization: Bearer <你的密钥>，或通过 OAuth 授权流程获取令牌。",
                    },
                    "id": None,
                },
            )
            await response(scope, receive, send)
            return
        state = scope.setdefault("state", {})
        if not isinstance(state, dict):
            logger.warning("拒绝 /mcp 请求：scope.state 不可写 | path=%s", scope.get("path"))
            response = JSONResponse(
                status_code=401,
                content={
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": "鉴权失败：请在请求头带 Authorization: Bearer <你的密钥>，或通过 OAuth 授权流程获取令牌。",
                    },
                    "id": None,
                },
            )
            await response(scope, receive, send)
            return
        state[SCOPE_CAPABILITY_KEY] = capability
        try:
            await self.asgi_app(scope, receive, send)
        except Exception as e:
            logger.error("MCPAuthGuard 转发 /mcp 请求时异常: %s | path=%s\n%s", e, scope.get("path"), traceback.format_exc())
            raise


@app.get("/health")
async def health():
    return JSONResponse({
        "status": "ok",
        "token_set": bool(ZEABUR_TOKEN),
        "access_control_enabled": bool(MCP_PROXY_SECRET),
        "oauth_store_configured": bool(oauth.SUPABASE_URL and oauth.SUPABASE_SERVICE_ROLE_KEY),
    })


# 挂载在根路径 "/" 而不是 "/mcp"：mcp.streamable_http_app() 内部默认已经把自己的路由
# 注册在 "/mcp" 这个路径上了（官方 SDK 文档：Streamable HTTP servers are mounted at /mcp）。
# 如果外层再挂到 "/mcp" 前缀下，实际可达路径会变成 "/mcp/mcp"（双重前缀），
# 导致 Claude 连接器注册的 URL（.../mcp）打不到任何路由，这正是上两次连接失败的真正原因。
# 必须放在本文件所有其他路由（含上面的 /health）注册完之后 —— Starlette 路由是按注册顺序
# first-match-wins，根路径的 Mount 如果注册得早，会把后面才定义的具体路径全部吞掉。
_streamable_app = mcp.streamable_http_app()
app.mount("/", MCPAuthGuard(_streamable_app))


if __name__ == "__main__":
    import uvicorn
    if not MCP_PROXY_SECRET:
        logger.warning("MCP_PROXY_SECRET 还没配置，当前 /sse 和 /mcp 对所有人开放，建议尽快配置")
    if MCP_URL_SECRET:
        logger.info("MCP_URL_SECRET 已配置，/mcp 支持 ?token= 兼容鉴权（URL 可能被代理记录，请独立轮换）")
    if MCP_OPERATOR_URL_SECRET:
        logger.info("MCP_OPERATOR_URL_SECRET 已配置，/mcp 支持独立 operator ?token= 鉴权")
    if MCP_WRITES_ENABLED:
        logger.info("MCP_WRITES_ENABLED 已开启，write tools 仍受 OPERATOR 能力约束")
    else:
        logger.info("MCP_WRITES_ENABLED 未开启，write tools 拒绝任何变更")
    if not PUBLIC_BASE_URL:
        logger.warning("PUBLIC_BASE_URL 没配置，OAuth 元数据会尝试从请求头拼 URL，建议显式配置成 Zeabur 分配的域名")
    if not oauth.SUPABASE_URL or not oauth.SUPABASE_SERVICE_ROLE_KEY:
        logger.warning("OAUTH_STORE_SUPABASE_URL / OAUTH_STORE_SUPABASE_SERVICE_ROLE_KEY 没配置，OAuth 动态授权功能不可用（MCP_PROXY_SECRET 固定密钥模式仍可用）")
    uvicorn.run(app, host="0.0.0.0", port=PORT)
