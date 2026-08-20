"""OAuth 2.1 (PKCE) 授权服务器逻辑 —— 持久化存储在 Supabase「晏安的数据库」
(project ref: segsimuoukrovxrgbjfw)，表名 mcp_oauth_store，service='zeabur-mcp'。

与 sue1231511/supabase 仓库共用同一张表：service 字段区分归属服务，
record_type 字段区分记录种类 (client / auth_code / access_token / refresh_token)。

原内存态实现 (client/auth_code/token 全部存 Python 进程内存的 dict) 在 Zeabur
每次重新部署或容器重启后会被清空，导致 Claude 端缓存的旧 access_token 全部失效、
鉴权返回 401——这是本次改造要修的问题，详见 2026-07-02 的排查记录。

安全说明：这张表已开启 RLS 且未配置任何 policy，只有 service_role key 能穿透
RLS 访问，anon/publishable key 完全读不到，因此这里必须用 service_role key
（OAUTH_STORE_SUPABASE_SERVICE_ROLE_KEY），不能用 anon key。
"""
import base64
import hashlib
import secrets
import time
import os
import asyncio
import logging
import traceback
from datetime import datetime, timezone, timedelta
from typing import Optional

from supabase import create_async_client, AsyncClient

logger = logging.getLogger("zeabur-mcp.oauth")

SERVICE_NAME = "zeabur-mcp"
TABLE_NAME = "mcp_oauth_store"

AUTH_CODE_TTL_SECONDS = 5 * 60
ACCESS_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30       # 30 天
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 365     # 1 年

SUPABASE_URL = os.environ.get("OAUTH_STORE_SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("OAUTH_STORE_SUPABASE_SERVICE_ROLE_KEY", "").strip()

_client: Optional[AsyncClient] = None
_client_lock = asyncio.Lock()


def _parse_ts(ts_str: str) -> datetime:
    """兼容 PostgREST 可能返回的 'Z' 结尾格式，Python < 3.11 的 fromisoformat 不支持 'Z'。"""
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"
    return datetime.fromisoformat(ts_str)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _future_iso(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


async def _get_client() -> AsyncClient:
    """懒加载单例，用锁防止并发请求下重复创建客户端实例。"""
    global _client
    if _client is not None:
        return _client
    async with _client_lock:
        if _client is not None:
            return _client
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
            err = RuntimeError(
                "OAUTH_STORE_SUPABASE_URL / OAUTH_STORE_SUPABASE_SERVICE_ROLE_KEY 未配置，"
                "OAuth 持久化存储不可用，请在 Zeabur 环境变量里配置"
            )
            logger.error("oauth._get_client 初始化失败: %s\n%s", err, traceback.format_exc())
            raise err
        try:
            _client = await create_async_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
            logger.info("oauth._get_client Supabase 异步客户端初始化成功")
            return _client
        except Exception as e:
            logger.error("oauth._get_client 创建 Supabase 客户端异常: %s\n%s", e, traceback.format_exc())
            raise


def _random_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


async def register_client(client_name, redirect_uris) -> dict:
    if not redirect_uris or not isinstance(redirect_uris, list):
        raise ValueError("redirect_uris 不能为空")
    client_id = _random_token("client")
    client_name_final = client_name or "unnamed-mcp-client"
    record = {
        "client_id": client_id,
        "client_name": client_name_final,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "created_at": time.time(),
    }
    try:
        client = await _get_client()
        row = {
            "service": SERVICE_NAME,
            "record_type": "client",
            "key": client_id,
            "client_id": client_id,
            "client_name": client_name_final,
            "redirect_uris": redirect_uris,
        }
        await client.table(TABLE_NAME).insert(row).execute()
        logger.info("register_client 新客户端注册 | client_id=%s client_name=%s", client_id, client_name_final)
        return record
    except Exception as e:
        logger.error(
            "register_client 写入 Supabase 失败: %s | client_name=%s redirect_uris=%s\n%s",
            e, client_name, redirect_uris, traceback.format_exc()
        )
        raise


async def get_client(client_id: str) -> Optional[dict]:
    """查询失败（数据库异常）时往上抛出，不吞掉——调用方需要区分
    "client_id 确实不存在" 和 "存储层出故障了" 这两种不同情况。"""
    try:
        client = await _get_client()
        resp = (
            await client.table(TABLE_NAME)
            .select("client_id, client_name, redirect_uris")
            .eq("service", SERVICE_NAME)
            .eq("record_type", "client")
            .eq("key", client_id)
            .limit(1)
            .execute()
        )
        rows = resp.data
        if not rows:
            return None
        row = rows[0]
        return {
            "client_id": row["client_id"],
            "client_name": row["client_name"],
            "redirect_uris": row["redirect_uris"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
    except Exception as e:
        logger.error("get_client 查询 Supabase 失败: %s | client_id=%s\n%s", e, client_id, traceback.format_exc())
        raise


async def create_auth_code(client_id, redirect_uri, code_challenge, code_challenge_method, scope) -> str:
    code = _random_token("code")
    try:
        client = await _get_client()
        row = {
            "service": SERVICE_NAME,
            "record_type": "auth_code",
            "key": code,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "scope": scope,
            "expires_at": _future_iso(AUTH_CODE_TTL_SECONDS),
        }
        await client.table(TABLE_NAME).insert(row).execute()
        return code
    except Exception as e:
        logger.error(
            "create_auth_code 写入 Supabase 失败: %s | client_id=%s redirect_uri=%s\n%s",
            e, client_id, redirect_uri, traceback.format_exc()
        )
        raise


async def consume_auth_code(code: str) -> Optional[dict]:
    """原子消费：直接 DELETE 并用 .select() 让 PostgREST 把被删除的行随响应带回来，
    避免"先 SELECT 再 DELETE"两步操作之间的竞态窗口。
    注意：DELETE 默认 Prefer: return=minimal，不加 .select() 拿不到任何数据，
    这是本次实现里容易漏掉的一点，务必保留 .select()。"""
    try:
        client = await _get_client()
        resp = (
            await client.table(TABLE_NAME)
            .delete()
            .eq("service", SERVICE_NAME)
            .eq("record_type", "auth_code")
            .eq("key", code)
            .select("*")
            .execute()
        )
        rows = resp.data
        if not rows:
            return None
        row = rows[0]
        if datetime.now(timezone.utc) > _parse_ts(row["expires_at"]):
            logger.warning("consume_auth_code 授权码已过期 | code=%s", code)
            return None
        return {
            "client_id": row["client_id"],
            "redirect_uri": row["redirect_uri"],
            "code_challenge": row["code_challenge"],
            "code_challenge_method": row["code_challenge_method"],
            "scope": row["scope"],
        }
    except Exception as e:
        logger.error("consume_auth_code 操作 Supabase 失败: %s | code=%s\n%s", e, code, traceback.format_exc())
        raise


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """纯计算，不涉及 IO，保持同步不变。"""
    if method != "S256" or not code_verifier or not code_challenge:
        return False
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


async def issue_tokens() -> dict:
    access_token = _random_token("at")
    refresh_token = _random_token("rt")
    try:
        client = await _get_client()
        rows = [
            {
                "service": SERVICE_NAME,
                "record_type": "access_token",
                "key": access_token,
                "expires_at": _future_iso(ACCESS_TOKEN_TTL_SECONDS),
            },
            {
                "service": SERVICE_NAME,
                "record_type": "refresh_token",
                "key": refresh_token,
                "expires_at": _future_iso(REFRESH_TOKEN_TTL_SECONDS),
            },
        ]
        await client.table(TABLE_NAME).insert(rows).execute()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
    except Exception as e:
        logger.error("issue_tokens 写入 Supabase 失败: %s\n%s", e, traceback.format_exc())
        raise


async def rotate_refresh_token(refresh_token: str) -> Optional[dict]:
    try:
        client = await _get_client()
        resp = (
            await client.table(TABLE_NAME)
            .delete()
            .eq("service", SERVICE_NAME)
            .eq("record_type", "refresh_token")
            .eq("key", refresh_token)
            .select("*")
            .execute()
        )
        rows = resp.data
        if not rows:
            return None
        row = rows[0]
        if datetime.now(timezone.utc) > _parse_ts(row["expires_at"]):
            return None
        return await issue_tokens()
    except Exception as e:
        logger.error("rotate_refresh_token 操作 Supabase 失败: %s\n%s", e, traceback.format_exc())
        raise


async def is_access_token_valid(token: str) -> bool:
    """鉴权高频路径：fail-closed，任何异常（含 Supabase 暂时不可用）一律按
    「无效」处理，拒绝比放行安全；但异常必须完整记录日志，方便和
    "token 确实无效/过期" 这种正常业务情况区分开，不能真的把异常吞掉不留痕迹。"""
    try:
        client = await _get_client()
        resp = (
            await client.table(TABLE_NAME)
            .select("expires_at")
            .eq("service", SERVICE_NAME)
            .eq("record_type", "access_token")
            .eq("key", token)
            .limit(1)
            .execute()
        )
        rows = resp.data
        if not rows:
            return False
        if datetime.now(timezone.utc) > _parse_ts(rows[0]["expires_at"]):
            return False
        return True
    except Exception as e:
        logger.error("is_access_token_valid 查询 Supabase 异常，按无效处理: %s\n%s", e, traceback.format_exc())
        return False
