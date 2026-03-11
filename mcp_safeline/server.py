"""
SafeLine WAF MCP Server

Implements MCP tools for interacting with the SafeLine WAF API.
The server accepts WAF base URL and API token as configuration parameters.
"""

import os
import json
import httpx
import base64
import datetime
from typing import Any, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types


# ---------------------------------------------------------------------------
# SafeLine API client
# ---------------------------------------------------------------------------


class SafeLineClient:
    """Thin wrapper around the SafeLine HTTP API."""

    def __init__(self, base_url: str, token: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict:
        return {
            "API-TOKEN": self.token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, params: Optional[dict] = None) -> dict:
        with httpx.Client(verify=self.verify_ssl, timeout=30) as client:
            resp = client.get(self._url(path), params=params, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def get_binary(self, path: str, params: Optional[dict] = None) -> bytes:
        with httpx.Client(verify=self.verify_ssl, timeout=30) as client:
            resp = client.get(self._url(path), params=params, headers=self._headers())
            resp.raise_for_status()
            return resp.content

    def post(self, path: str, body: Optional[dict] = None) -> dict:
        with httpx.Client(verify=self.verify_ssl, timeout=30) as client:
            resp = client.post(self._url(path), json=body, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def put(self, path: str, body: Optional[dict] = None) -> dict:
        with httpx.Client(verify=self.verify_ssl, timeout=30) as client:
            resp = client.put(self._url(path), json=body, headers=self._headers())
            resp.raise_for_status()
            return resp.json()

    def delete(self, path: str, body: Optional[dict] = None) -> dict:
        with httpx.Client(verify=self.verify_ssl, timeout=30) as client:
            resp = client.request(
                "DELETE", self._url(path), json=body, headers=self._headers()
            )
            resp.raise_for_status()
            return resp.json()


def _fmt(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _require_ip_group_id(args: dict[str, Any]) -> int:
    group_id = args.get("id", args.get("ip_group_id"))
    if group_id is None:
        raise ValueError("Either 'id' or 'ip_group_id' is required.")
    return group_id


# ---------------------------------------------------------------------------
# Build MCP server
# ---------------------------------------------------------------------------


def create_server(base_url: str, token: str, verify_ssl: bool = False) -> Server:
    client = SafeLineClient(base_url, token, verify_ssl)
    server = Server("mcp-safeline")

    # -----------------------------------------------------------------------
    # Tool list
    # -----------------------------------------------------------------------
    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            # ---- 认证 / profile ----
            types.Tool(
                name="get_profile",
                description="获取当前登录用户的个人信息（验证 Token 是否有效）",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            # ---- 访问频率控制 / ACL Rule ----
            types.Tool(
                name="list_acl_rules",
                description="查看指定频率限制规则下的所有受限用户（ACL Rule）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "acl_rule_template_id": {
                            "type": "integer",
                            "description": "访问频率限制规则 ID（ACLRuleTemplate ID）",
                        },
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                    "required": ["acl_rule_template_id"],
                },
            ),
            types.Tool(
                name="add_acl_rule",
                description="为指定频率限制规则添加受限用户（IP/Session 等）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "acl_rule_template_id": {
                            "type": "integer",
                            "description": "访问频率限制规则 ID",
                        },
                        "acl_rule_template_version": {
                            "type": "integer",
                            "description": "规则版本（可选）",
                        },
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "限制用户列表，如 ['1.2.3.4']",
                        },
                        "target_ip_groups": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "限制 IP 组 ID 列表（可选）",
                        },
                    },
                    "required": ["acl_rule_template_id", "targets"],
                },
            ),
            types.Tool(
                name="delete_acl_rule",
                description="解除指定 ID 的受限用户，可选加入白名单",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "integer",
                            "description": "ACL Rule ID（负数）",
                        },
                        "add_to_white_list": {
                            "type": "boolean",
                            "description": "是否将用户加入白名单",
                        },
                    },
                    "required": ["id", "add_to_white_list"],
                },
            ),
            # ---- ACL Rule Execution Log ----
            types.Tool(
                name="list_acl_execution_logs",
                description="查询访问频率控制执行日志（统计数据）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "acl_rule_template_id": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "按规则 ID 过滤（可选）",
                        },
                        "acl_rule_id": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "按 ACL Rule ID 过滤（可选）",
                        },
                        "timestamp__range": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "时间范围，格式 ['start-end']（可选）",
                        },
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="delete_acl_execution_logs",
                description="删除访问频率控制执行日志",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "日志 ID 列表（可选）",
                        },
                        "acl_rule_template_id": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "按规则 ID 删除（可选）",
                        },
                    },
                },
            ),
            # ---- ACL Rule Template ----
            types.Tool(
                name="list_acl_rule_templates",
                description="查看所有访问频率限制规则（ACL Rule Template）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "按 ID 过滤（可选）",
                        },
                        "name__like": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "按名称模糊查询（可选）",
                        },
                        "match_method__policy__like": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "按访问限制地址模糊查询（可选）",
                        },
                        "acl_rules__target__like": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "按限制用户模糊查询（可选）",
                        },
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="create_acl_rule_template",
                description="新建访问频率限制规则（ACL Rule Template）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "规则名称"},
                        "template_type": {
                            "type": "string",
                            "enum": ["manual", "auto"],
                            "description": "规则类型：manual（手动）或 auto（自动）",
                        },
                        "match_method": {
                            "type": "object",
                            "description": "匹配方式配置：{scope: 'URL Prefix'/'Host'/'All', target_type: 'CIDR'/'Session'/'host', policy: 域名/路径, period: 秒, limit: 次数}",
                        },
                        "action": {
                            "type": "object",
                            "description": '触发动作配置：{action: "forbid" 或 "Limit Rate", limit_rate_limit: 次数, limit_rate_period: 秒}',
                        },
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "IP 列表（可选）",
                        },
                        "target_ip_groups": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "IP 组 ID 列表（可选）",
                        },
                        "expire_period": {
                            "type": "integer",
                            "description": "过期周期（秒），>=1",
                        },
                        "is_enabled": {
                            "type": "boolean",
                            "description": "启用状态（默认 true）",
                        },
                        "dry_run": {
                            "type": "boolean",
                            "description": "观察模式（默认 false）",
                        },
                        "forbidden_page_config": {
                            "type": "object",
                            "description": "自定义拦截页面配置（可选）：{action: 'response', status_code: 403, path: ''}",
                        },
                        "is_inaccurate": {
                            "type": "boolean",
                            "description": "是否模糊匹配（默认 false）",
                        },
                    },
                    "required": ["name", "match_method", "action"],
                },
            ),
            types.Tool(
                name="update_acl_rule_template",
                description="编辑指定 ID 的访问频率限制规则",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "规则 ID"},
                        "name": {"type": "string", "description": "规则名称"},
                        "match_method": {
                            "type": "object",
                            "description": "匹配方式配置",
                        },
                        "action": {"type": "object", "description": "触发动作配置"},
                        "expire_period": {
                            "type": "integer",
                            "description": "过期周期（秒）",
                        },
                        "is_enabled": {"type": "boolean", "description": "启用状态"},
                        "dry_run": {"type": "boolean", "description": "观察模式"},
                        "forbidden_page_config": {
                            "type": "object",
                            "description": "自定义拦截页面配置",
                        },
                    },
                    "required": ["id", "name", "match_method", "action"],
                },
            ),
            types.Tool(
                name="delete_acl_rule_templates",
                description="删除指定 ID 的访问频率限制规则（可批量）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "要删除的规则 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            # ---- ACL White List ----
            types.Tool(
                name="list_acl_whitelist",
                description="查询 ACL 白名单",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target_type": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "类型过滤，可选值: ['IP Group', 'Fingerprint', 'CIDR', 'Session']",
                        },
                        "target": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "IP 或 Session 过滤（可选）",
                        },
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="create_acl_whitelist",
                description="新建 ACL 白名单条目",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "comment": {"type": "string", "description": "备注"},
                        "target_type": {
                            "type": "string",
                            "enum": ["CIDR", "Session", "Fingerprint", "IP Group"],
                            "description": "目标类型",
                        },
                        "target_list": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "IP/Session 列表",
                        },
                        "target_ip_group_list": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "IP 组 ID 列表",
                        },
                    },
                    "required": ["comment", "target_type"],
                },
            ),
            types.Tool(
                name="delete_acl_whitelist",
                description="删除指定 ID 的 ACL 白名单条目",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "白名单条目 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            types.Tool(
                name="clear_acl_rules",
                description="清空指定频率限制规则下的所有受限用户",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "acl_rule_template_id": {
                            "type": "integer",
                            "description": "要清空的频率限制规则 ID",
                        },
                    },
                    "required": ["acl_rule_template_id"],
                },
            ),
            # ---- IP 组 ----
            types.Tool(
                name="list_ip_groups",
                description="获取所有 IP 组信息",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "按 ID 过滤（可选）",
                        },
                        "name__like": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "按名称模糊查询（可选）",
                        },
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="create_ip_group",
                description="新建 IP 组",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "IP 组名称"},
                        "comment": {"type": "string", "description": "备注（可选）"},
                        "original": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "原始 IP/CIDR/范围列表（优先使用）",
                        },
                        "ips": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "IP/CIDR 列表（兼容字段，会映射到 original）",
                        },
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="get_ip_group_details",
                description="获取指定 IP 组的详细信息，包括 IP 成员列表",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "IP 组 ID"},
                    },
                    "required": ["id"],
                },
            ),
            # ---- 系统监控 ----
            types.Tool(
                name="get_system_monitor",
                description="获取 SafeLine WAF 系统监控状态（CPU、内存、磁盘、运行时间等）",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="update_ip_group",
                description="编辑 IP 组名称和备注",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "IP 组 ID"},
                        "name": {"type": "string", "description": "新名称"},
                        "comment": {"type": "string", "description": "新备注"},
                    },
                    "required": ["id", "name"],
                },
            ),
            types.Tool(
                name="delete_ip_group",
                description="删除指定 ID 的 IP 组",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "IP 组 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            types.Tool(
                name="add_ip_to_group",
                description="向 IP 组添加 IP 地址",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "IP 组 ID（推荐）"},
                        "ip_group_id": {"type": "integer", "description": "IP 组 ID"},
                        "ips": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "要添加的 IP/CIDR 列表",
                        },
                    },
                    "required": ["ips"],
                },
            ),
            types.Tool(
                name="delete_ip_from_group",
                description="从 IP 组删除指定 IP 地址",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "IP 组 ID（推荐）"},
                        "ip_group_id": {"type": "integer", "description": "IP 组 ID"},
                        "ips": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "要删除的 IP/CIDR 列表",
                        },
                    },
                    "required": ["ips"],
                },
            ),
            # ---- 统计信息 / Overview ----
            types.Tool(
                name="get_overview",
                description="获取 SafeLine WAF 统计概览信息（请求数、拦截数等）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "duration": {
                            "type": "string",
                            "description": "统计时间范围（如 '1h', '24h', '7d'）",
                        },
                    },
                },
            ),
            # ---- 站点管理 ----
            types.Tool(
                name="list_websites",
                description="获取软件版反向代理站点列表",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "按站点 ID 过滤（可选）",
                        },
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="create_website",
                description="新建软件版反向代理站点",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "站点名称"},
                        "host": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "监听配置列表，每项包含 port/ssl 等字段",
                        },
                        "upstreams": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "上游服务器配置列表，每项包含 host/port/protocol 等字段",
                        },
                        "server_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "域名列表，如 ['*'] 或 ['example.com']",
                        },
                        "comment": {"type": "string", "description": "备注（可选）"},
                        "policy_group": {
                            "type": "integer",
                            "description": "策略组 ID（可选，默认为 3）",
                        },
                    },
                    "required": ["name", "host", "upstreams"],
                },
            ),
            types.Tool(
                name="update_website",
                description="编辑软件版反向代理站点",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "站点 ID"},
                        "name": {"type": "string", "description": "站点名称"},
                        "host": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "监听配置列表",
                        },
                        "upstreams": {
                            "type": "array",
                            "items": {"type": "object"},
                            "description": "上游服务器配置列表",
                        },
                        "server_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "域名列表，如 ['*'] 或 ['example.com']",
                        },
                        "comment": {"type": "string", "description": "备注（可选）"},
                    },
                    "required": ["id", "name", "host", "upstreams"],
                },
            ),
            types.Tool(
                name="delete_website",
                description="删除软件版反向代理站点",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "站点 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            types.Tool(
                name="get_software_reverse_proxy_bypass_state",
                description="获取软件反向代理 Bypass 状态",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="get_software_reverse_proxy_bypass_threshold",
                description="获取软件反向代理自动 Bypass 阈值配置",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="update_software_reverse_proxy_bypass_threshold",
                description="设置软件反向代理自动 Bypass 阈值",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "enable": {
                            "type": "boolean",
                            "description": "是否启用自动 Bypass",
                        },
                        "requests": {
                            "type": "object",
                            "description": "请求数阈值配置：{enable, duration, threshold}",
                        },
                        "cpu_usage": {
                            "type": "object",
                            "description": "CPU 使用率配置：{enable, duration, threshold}",
                        },
                        "disk_usage": {
                            "type": "object",
                            "description": "磁盘使用率配置：{enable, threshold}",
                        },
                        "memory_usage": {
                            "type": "object",
                            "description": "内存使用率配置：{enable, duration, threshold}",
                        },
                    },
                },
            ),
            types.Tool(
                name="get_intrusion_detection_status",
                description="获取入侵检测状态",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="enable_intrusion_detection",
                description="启用入侵检测",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="disable_intrusion_detection",
                description="禁用入侵检测",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="get_detection_engine_degraded_config",
                description="获取检测引擎服务降级配置",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="enable_detection_engine_degraded",
                description="开启检测引擎服务降级",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "threshold": {
                            "type": "integer",
                            "description": "阈值 (默认 80)",
                        },
                        "recover_duration": {
                            "type": "integer",
                            "description": "恢复持续时间 (毫秒)",
                        },
                        "fallback_duration": {
                            "type": "integer",
                            "description": "降级持续时间 (毫秒)",
                        },
                        "threshold_duration": {
                            "type": "integer",
                            "description": "阈值持续时间 (毫秒)",
                        },
                    },
                },
            ),
            types.Tool(
                name="disable_detection_engine_degraded",
                description="关闭检测引擎服务降级",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "threshold": {
                            "type": "integer",
                            "description": "阈值 (默认 80)",
                        },
                        "recover_duration": {
                            "type": "integer",
                            "description": "恢复持续时间 (毫秒)",
                        },
                        "fallback_duration": {
                            "type": "integer",
                            "description": "降级持续时间 (毫秒)",
                        },
                        "threshold_duration": {
                            "type": "integer",
                            "description": "阈值持续时间 (毫秒)",
                        },
                    },
                },
            ),
            # ---- 证书管理 ----
            types.Tool(
                name="list_certs",
                description="获取 SSL 证书列表",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="delete_cert",
                description="删除指定 ID 的 SSL 证书",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "证书 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            # ---- 日志标记 ----
            types.Tool(
                name="get_log_flag_config",
                description="获取攻击日志标记配置",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="update_log_flag_config",
                description="修改攻击日志标记配置",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "config": {
                            "type": "object",
                            "description": "标记配置对象（具体字段参考 API 文档）",
                        },
                    },
                    "required": ["config"],
                },
            ),
            # ---- 筛选 ----
            types.Tool(
                name="get_filter_options",
                description="获取各类筛选可用选项（如攻击日志、IP 组、防护策略等）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filter_type": {
                            "type": "string",
                            "enum": [
                                "acl_manual_users",
                                "acl_auto_users",
                                "acl_templates",
                                "attack_logs",
                                "ip_groups",
                                "policies",
                            ],
                            "description": "筛选类型",
                        },
                    },
                    "required": ["filter_type"],
                },
            ),
            # ---- 筛选器管理 ----
            types.Tool(
                name="list_saved_filters",
                description="获取已保存的筛选器列表",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="create_saved_filter",
                description="新建保存的筛选器",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "筛选器名称"},
                        "filter": {"type": "object", "description": "筛选条件"},
                        "filter_type": {"type": "string", "description": "筛选类型"},
                    },
                    "required": ["name", "filter", "filter_type"],
                },
            ),
            types.Tool(
                name="update_saved_filter",
                description="编辑保存的筛选器",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "筛选器 ID"},
                        "name": {"type": "string", "description": "筛选器名称"},
                        "filter": {"type": "object", "description": "筛选条件"},
                    },
                    "required": ["id", "name", "filter"],
                },
            ),
            types.Tool(
                name="delete_saved_filter",
                description="删除保存的筛选器",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "筛选器 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            # ---- 数据仪表盘 / Dashboard ----
            types.Tool(
                name="get_dashboard_overview",
                description="获取数据仪表盘统计信息（支持防护总览、站点防护、用户行为、攻击检测日志分析）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "start_time": {"type": "integer", "description": "起始时间戳"},
                        "end_time": {"type": "integer", "description": "结束时间戳"},
                        "source": {
                            "type": "string",
                            "enum": [
                                "overall",
                                "overall_website",
                                "overall_user",
                                "detect_log",
                            ],
                            "description": "仪表盘类型：防护总览/站点防护/用户行为/攻击检测日志分析",
                        },
                        "sections": {
                            "type": "object",
                            "description": "数据板块配置，如 {'overall': ['total', 'abnormal'], 'attack_type': true}",
                        },
                        "filter": {"type": "object", "description": "筛选条件（可选）"},
                    },
                    "required": ["start_time", "end_time", "source", "sections"],
                },
            ),
            # ---- 攻击检测日志 / Detect Log ----
            types.Tool(
                name="get_detect_log_aggregate",
                description="按照源 IP 聚合 24 小时内的攻击检测日志",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "condition": {
                            "type": "string",
                            "enum": [
                                "attack_type",
                                "rule_id",
                                "src_ip_keyword",
                                "site_uuid,attack_type,src_ip_keyword",
                            ],
                            "description": "聚合条件",
                        },
                        "time_interval": {
                            "type": "integer",
                            "description": "聚合时间（秒），最大 86400，默认 3600",
                        },
                        "log_size": {
                            "type": "integer",
                            "description": "展示条数，最小 1，最大 1000，默认 100",
                        },
                    },
                },
            ),
            # ---- 防护策略 / Policy ----
            types.Tool(
                name="list_policy_groups",
                description="获取防护策略列表",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "is_default": {
                            "type": "boolean",
                            "description": "是否为默认策略（可选）",
                        },
                    },
                },
            ),
            types.Tool(
                name="create_policy_group",
                description="新建防护策略",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "策略名称"},
                        "comment": {"type": "string", "description": "备注（可选）"},
                    },
                    "required": ["name"],
                },
            ),
            types.Tool(
                name="update_policy_group",
                description="编辑防护策略",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "策略 ID"},
                        "name": {"type": "string", "description": "策略名称"},
                        "comment": {"type": "string", "description": "备注（可选）"},
                        "modules_state": {
                            "type": "boolean",
                            "description": "模块开关（可选）",
                        },
                        "modules_detection_config": {
                            "type": "object",
                            "description": "模块检测配置（可选）",
                        },
                    },
                    "required": ["id", "name"],
                },
            ),
            types.Tool(
                name="delete_policy_groups",
                description="删除防护策略",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "策略 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            types.Tool(
                name="list_policy_rules",
                description="获取自定义规则列表",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "规则 ID 列表",
                        },
                        "is_global": {
                            "type": "boolean",
                            "description": "是否为全局规则（可选）",
                        },
                        "rule_type": {
                            "type": "integer",
                            "description": "规则类型（可选）",
                        },
                        "comment__like": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "规则备注模糊查询",
                        },
                        "attack_type": {
                            "type": "integer",
                            "description": "攻击类型 ID 过滤",
                        },
                        "action": {
                            "type": "string",
                            "description": "动作类型过滤 (deny/allow/forbid)",
                        },
                        "is_enabled": {
                            "type": "boolean",
                            "description": "启用状态过滤",
                        },
                        "count": {"type": "integer", "description": "分页：每页数量"},
                        "offset": {"type": "integer", "description": "分页：偏移量"},
                    },
                },
            ),
            types.Tool(
                name="create_policy_rule",
                description="新建自定义规则",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "规则名称"},
                        "attack_type": {
                            "type": "integer",
                            "description": "攻击类型 ID，-1 表示自定义",
                        },
                        "comment": {"type": "string", "description": "备注"},
                        "description": {"type": "string", "description": "规则描述"},
                        "action": {
                            "type": "string",
                            "description": "执行动作：deny(拦截)、allow(放行)、forbid(封禁)",
                        },
                        "pattern": {
                            "type": "object",
                            "description": "匹配模式，格式为 {$AND: [{cidr: {remote_addr: IP/CIDR}, str: {host: 域名}}]}",
                        },
                        "is_enabled": {"type": "boolean", "description": "是否启用"},
                        "is_global": {
                            "type": "boolean",
                            "description": "是否为全局规则",
                        },
                        "expire_time": {
                            "type": "integer",
                            "description": "过期时间戳（秒）",
                        },
                        "log_option": {
                            "type": "string",
                            "description": "日志选项：Persistence(持久化日志),空(不记录)",
                        },
                        "percentage": {
                            "type": "integer",
                            "description": "采样比例 1-100，默认100",
                        },
                        "duration": {
                            "type": "integer",
                            "description": "持续时间（秒），用于临时生效规则",
                        },
                        "priority": {
                            "type": "integer",
                            "description": "优先级，数字越大优先级越高",
                        },
                        "delay": {"type": "integer", "description": "延迟（秒）"},
                        "session_method": {
                            "type": "object",
                            "description": "会话匹配方式：{type: 'src_ip' 或 'session', param: ''}",
                        },
                        "cron_config": {
                            "type": "object",
                            "description": "定时配置：{type: 'all', start: '00:00', end: '23:59', days: []}",
                        },
                        "websites": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "绑定的站点 ID 列表",
                        },
                        "punish_type": {"type": "string", "description": "惩罚类型"},
                        "punish_time": {
                            "type": "integer",
                            "description": "惩罚时长（秒）",
                        },
                    },
                    "required": ["name", "action", "pattern"],
                },
            ),
            types.Tool(
                name="update_policy_rule",
                description="编辑自定义规则",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "规则 ID"},
                        "name": {"type": "string", "description": "规则名称"},
                        "attack_type": {
                            "type": "integer",
                            "description": "攻击类型 ID",
                        },
                        "comment": {"type": "string", "description": "备注"},
                        "description": {"type": "string", "description": "规则描述"},
                        "pattern": {"type": "object", "description": "匹配模式"},
                        "action": {"type": "string", "description": "执行动作"},
                        "is_enabled": {"type": "boolean", "description": "是否启用"},
                        "is_global": {
                            "type": "boolean",
                            "description": "是否为全局规则",
                        },
                        "expire_time": {"type": "integer", "description": "过期时间戳"},
                        "log_option": {"type": "string", "description": "日志选项"},
                        "percentage": {"type": "integer", "description": "采样比例"},
                        "duration": {"type": "integer", "description": "持续时间"},
                        "priority": {"type": "integer", "description": "优先级"},
                        "delay": {"type": "integer", "description": "延迟"},
                        "websites": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "站点 ID 列表",
                        },
                        "session_method": {
                            "type": "object",
                            "description": "会话匹配方式",
                        },
                        "cron_config": {"type": "object", "description": "定时配置"},
                        "punish_type": {"type": "string", "description": "惩罚类型"},
                        "punish_time": {"type": "integer", "description": "惩罚时长"},
                    },
                    "required": ["id", "name", "action", "pattern"],
                },
            ),
            types.Tool(
                name="delete_policy_rules",
                description="删除自定义规则",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "规则 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            # ---- 智学习 / Traffic Learning ----
            types.Tool(
                name="get_traffic_learning_overview",
                description="获取智学习总览信息",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="list_traffic_learning_intfs",
                description="获取智学习业务列表",
                inputSchema={"type": "object", "properties": {}},
            ),
            types.Tool(
                name="create_traffic_learning_intf",
                description="手动创建智学习业务",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "业务名称"},
                        "website_ids": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "站点 ID 列表",
                        },
                    },
                    "required": ["name", "website_ids"],
                },
            ),
            types.Tool(
                name="update_traffic_learning_intf",
                description="编辑智学习业务",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "业务 ID"},
                        "name": {"type": "string", "description": "业务名称"},
                        "website_ids": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "站点 ID 列表",
                        },
                    },
                    "required": ["id"],
                },
            ),
            types.Tool(
                name="delete_traffic_learning_intfs",
                description="删除智学习业务",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id__in": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "业务 ID 列表",
                        },
                    },
                    "required": ["id__in"],
                },
            ),
            types.Tool(
                name="toggle_traffic_learning_intf",
                description="修改智学习业务模型状态",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "业务 ID"},
                        "enabled": {"type": "boolean", "description": "启用状态"},
                    },
                    "required": ["id", "enabled"],
                },
            ),
            # ---- 报告 / Report ----
            types.Tool(
                name="create_report_task",
                description="手动生成节点状态报告",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "报告名称"},
                        "recipients": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "接收邮箱列表",
                        },
                    },
                    "required": ["name", "recipients"],
                },
            ),
            types.Tool(
                name="update_report_task",
                description="编辑定时报告任务",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "description": "任务 ID"},
                        "name": {"type": "string", "description": "报告名称"},
                        "cron": {"type": "string", "description": "Cron 表达式"},
                        "recipients": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "接收邮箱列表",
                        },
                    },
                    "required": ["id", "name"],
                },
            ),
            types.Tool(
                name="send_report",
                description="立即发送报告到邮箱",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "report_task_id": {
                            "type": "integer",
                            "description": "报告任务 ID",
                        },
                    },
                    "required": ["report_task_id"],
                },
            ),
            # ---- ES 索引管理 ----
            types.Tool(
                name="list_es_indices",
                description="查看 ES 索引信息",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="delete_es_index",
                description="删除指定 ES 归档索引",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "index_name": {"type": "string", "description": "索引名称"},
                    },
                    "required": ["index_name"],
                },
            ),
            types.Tool(
                name="restore_es_index",
                description="恢复 ES 归档索引",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "index_name": {"type": "string", "description": "索引名称"},
                    },
                    "required": ["index_name"],
                },
            ),
            types.Tool(
                name="download_es_indices",
                description="查看索引信息（下载归档）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "index_name": {"type": "string", "description": "索引名称"},
                    },
                },
            ),
            types.Tool(
                name="update_es_index_lifecycle",
                description="修改 ES 索引生命周期配置",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "config": {
                            "type": "object",
                            "description": "生命周期配置对象",
                        },
                    },
                    "required": ["config"],
                },
            ),
            # ---- Config Backup ----
            types.Tool(
                name="list_config_backups",
                description="获取配置备份记录列表",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
            types.Tool(
                name="create_config_backup",
                description="创建新的配置备份",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "comment": {"type": "string", "description": "备注"},
                        "timing": {
                            "type": "string",
                            "enum": ["week", "month", "manual"],
                            "description": "备份时机",
                        },
                        "backup_type": {
                            "type": "string",
                            "enum": ["manual", "auto"],
                            "description": "备份类型",
                        },
                        "enable_auto_backup": {
                            "type": "boolean",
                            "description": "启用自动备份",
                        },
                        "emails": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "通知邮箱列表",
                        },
                        "use_sftp": {"type": "boolean", "description": "使用 SFTP"},
                        "state": {"type": "string", "description": "状态"},
                        "options": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "备份选项",
                        },
                        "password": {"type": "string", "description": "密码"},
                        "tfa_token": {
                            "type": "string",
                            "description": "双因素认证令牌",
                        },
                    },
                    "required": ["backup_type", "timing"],
                },
            ),
            types.Tool(
                name="delete_config_backup",
                description="删除配置备份（支持按ID、全部、最新N条、日期范围删除）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ids": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "要删除的备份ID列表",
                        },
                        "delete_all": {
                            "type": "boolean",
                            "description": "删除所有备份",
                        },
                        "count": {
                            "type": "integer",
                            "description": "删除最新的N个备份",
                        },
                        "before_date": {
                            "type": "string",
                            "description": "删除此日期之前的备份 (格式: YYYY-MM-DD HH:MM:SS)",
                        },
                        "start_date": {
                            "type": "string",
                            "description": "日期范围起始 (格式: YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS)",
                        },
                        "end_date": {
                            "type": "string",
                            "description": "日期范围结束 (格式: YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS)",
                        },
                    },
                },
            ),
            types.Tool(
                name="download_config_backup",
                description="下载配置备份文件（支持按ID、最新N条、日期范围筛选）",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "ids": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "要下载的备份ID列表",
                        },
                        "count": {
                            "type": "integer",
                            "description": "下载最新的N个备份",
                        },
                        "before_date": {
                            "type": "string",
                            "description": "下载此日期之前的备份 (格式: YYYY-MM-DD HH:MM:SS)",
                        },
                        "after_date": {
                            "type": "string",
                            "description": "下载此日期之后的备份 (格式: YYYY-MM-DD HH:MM:SS)",
                        },
                        "start_date": {
                            "type": "string",
                            "description": "日期范围起始 (格式: YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS)",
                        },
                        "end_date": {
                            "type": "string",
                            "description": "日期范围结束 (格式: YYYY-MM-DD 或 YYYY-MM-DD HH:MM:SS)",
                        },
                        "save_path": {
                            "type": "string",
                            "description": "本地保存路径，如 /Users/wendell/Downloads/ （默认下载到此路径）",
                        },
                    },
                },
            ),
        ]

    # -----------------------------------------------------------------------
    # Tool call handler
    # -----------------------------------------------------------------------
    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
        try:
            result = await _dispatch(client, name, arguments)
            return [types.TextContent(type="text", text=_fmt(result))]
        except httpx.HTTPStatusError as e:
            error_body = ""
            try:
                error_body = e.response.json()
            except Exception:
                error_body = e.response.text
            return [
                types.TextContent(
                    type="text",
                    text=_fmt({"error": str(e), "detail": error_body}),
                )
            ]
        except Exception as e:
            return [types.TextContent(type="text", text=_fmt({"error": str(e)}))]

    return server


async def _dispatch(client: SafeLineClient, name: str, args: dict) -> Any:
    """Route tool calls to the appropriate SafeLine API endpoint."""

    # ---- 认证 ----
    if name == "get_profile":
        return client.get("/api/ProfileAPI")

    # ---- ACL Rule ----
    elif name == "list_acl_rules":
        params = {"acl_rule_template_id": args["acl_rule_template_id"]}
        if "count" in args:
            params["count"] = args["count"]
        if "offset" in args:
            params["offset"] = args["offset"]
        return client.get("/api/ACLRuleAPI", params=params)

    elif name == "add_acl_rule":
        body = {
            "acl_rule_template_id": args["acl_rule_template_id"],
            "targets": args["targets"],
        }
        if "acl_rule_template_version" in args:
            body["acl_rule_template_version"] = args["acl_rule_template_version"]
        if "target_ip_groups" in args:
            body["target_ip_groups"] = args["target_ip_groups"]
        return client.post("/api/ACLRuleAPI", body)

    elif name == "delete_acl_rule":
        return client.delete(
            "/api/ACLRuleAPI",
            {
                "id": args["id"],
                "add_to_white_list": args["add_to_white_list"],
            },
        )

    # ---- ACL Execution Log ----
    elif name == "list_acl_execution_logs":
        params = {}
        for key in (
            "acl_rule_template_id",
            "acl_rule_id",
            "timestamp__range",
            "count",
            "offset",
        ):
            if key in args:
                params[key] = args[key]
        return client.get("/api/ACLRuleExecutionLogAPI", params=params)

    elif name == "delete_acl_execution_logs":
        body = {}
        for key in (
            "id__in",
            "acl_rule_template_id",
            "acl_rule_id",
            "timestamp__range",
        ):
            if key in args:
                body[key] = args[key]
        return client.delete("/api/ACLRuleExecutionLogAPI", body)

    # ---- ACL Rule Template ----
    elif name == "list_acl_rule_templates":
        params = {}
        for key in (
            "id__in",
            "name__like",
            "match_method__policy__like",
            "acl_rules__target__like",
            "count",
            "offset",
        ):
            if key in args:
                params[key] = args[key]
        return client.get("/api/ACLRuleTemplateAPI", params=params)

    elif name == "create_acl_rule_template":
        body = {
            "id": 0,
            "create_time": 0,
            "name": args["name"],
            "template_type": args.get("template_type", "auto"),
            "match_method": args.get("match_method", {}),
            "action": args.get("action", {}),
            "targets": args.get("targets", []),
            "target_ip_groups": args.get("target_ip_groups", []),
            "is_enabled": args.get("is_enabled", True),
            "is_inaccurate": args.get("is_inaccurate", False),
            "dry_run": args.get("dry_run", False),
            "forbidden_page_config": args.get(
                "forbidden_page_config",
                {"action": "response", "status_code": 403, "path": ""},
            ),
        }

        if "expire_period" in args:
            body["expire_period"] = args["expire_period"]
        else:
            body["expire_period"] = None

        return client.post("/api/ACLRuleTemplateAPI", body)

    elif name == "update_acl_rule_template":
        body = {
            "id": args["id"],
            "name": args["name"],
            "match_method": args["match_method"],
            "action": args["action"],
        }
        for key in (
            "expire_period",
            "is_enabled",
            "dry_run",
            "forbidden_page_config",
            "is_inaccurate",
        ):
            if key in args:
                body[key] = args[key]
        return client.put("/api/ACLRuleTemplateAPI", body)

    elif name == "delete_acl_rule_templates":
        return client.delete("/api/ACLRuleTemplateAPI", {"id__in": args["id__in"]})

    # ---- ACL White List ----
    elif name == "list_acl_whitelist":
        params = {}
        for key in ("target_type", "target", "comment__like", "count", "offset"):
            if key in args:
                params[key] = args[key]
        return client.get("/api/ACLWhiteListAPI", params=params)

    elif name == "create_acl_whitelist":
        body = {
            "comment": args["comment"],
            "target_type": args["target_type"],
        }
        if "target_list" in args:
            body["target_list"] = args["target_list"]
        if "target_ip_group_list" in args:
            body["target_ip_group_list"] = args["target_ip_group_list"]
        return client.post("/api/ACLWhiteListAPI", body)

    elif name == "delete_acl_whitelist":
        return client.delete("/api/ACLWhiteListAPI", {"id__in": args["id__in"]})

    elif name == "clear_acl_rules":
        return client.delete(
            "/api/ClearACLRuleAPI",
            {"acl_rule_template_id": args["acl_rule_template_id"]},
        )

    # ---- IP 组 ----
    elif name == "list_ip_groups":
        params = {}
        for key in ("id__in", "name__like", "count", "offset"):
            if key in args:
                params[key] = args[key]
        return client.get("/api/IPGroupAPI", params=params)

    elif name == "create_ip_group":
        body = {"name": args["name"]}
        if "comment" in args:
            body["comment"] = args["comment"]
        original = args.get("original", args.get("ips"))
        if original:
            body["original"] = original
        return client.post("/api/IPGroupAPI", body)

    elif name == "get_ip_group_details":
        return client.post("/api/EditIPGroupItem", {"id": args["id"]})

    # ---- 系统监控 ----
    elif name == "get_system_monitor":
        # 调用 NodeInfoAPI 获取系统状态
        data = client.get("/api/NodeInfoAPI")
        # 返回数据包含多个节点
        if isinstance(data, dict) and "data" in data and len(data["data"]) > 0:
            nodes_result = []
            for node_wrapper in data["data"]:
                # 节点实际数据在 node 字段下
                if "node" not in node_wrapper:
                    continue
                node = node_wrapper["node"]
                # 提取系统资源使用率
                cpu_usage = node.get("cpu", 0)
                mem_usage = node.get("mem", 0)
                uptime_sec_raw = node.get("uptime", 0)
                # Handle string type uptime if it occurs (safe conversion)
                if isinstance(uptime_sec_raw, str):
                    try:
                        uptime_sec = int(uptime_sec_raw)
                    except ValueError:
                        uptime_sec = 0
                else:
                    uptime_sec = int(uptime_sec_raw)
                # Convert percentage to 0-100 range if it comes as 0.43
                if cpu_usage < 1.0:
                    cpu_usage *= 100
                if mem_usage < 1.0:
                    mem_usage *= 100

                # 提取磁盘信息
                disk_info = node.get("disk_info", {})
                disk_total = int(disk_info.get("total", 0))
                disk_usage = int(disk_info.get("usage", 0))

                # 转换运行时间格式
                days = uptime_sec // 86400
                hours = (uptime_sec % 86400) // 3600
                minutes = (uptime_sec % 3600) // 60
                uptime_str = f"{days} 天 {hours} 小时 {minutes} 分"

                # 提取服务状态列表 (services is at wrapper level, not node)
                services = node_wrapper.get("services", [])
                service_status = []
                for svc in services[:10]:  # 只取前10个服务避免返回过长
                    service_status.append(
                        {
                            "name": svc.get("name", ""),
                            "status": svc.get("status", ""),
                            "cpu": svc.get("cpu", 0),
                            "mem": svc.get("mem", 0),
                            "hostname": svc.get("hostname", ""),
                        }
                    )

                nodes_result.append(
                    {
                        "id": node_wrapper.get("id", ""),
                        "system": {
                            "cpu_usage": round(cpu_usage, 2),
                            "memory_usage": round(mem_usage, 2),
                            "uptime": uptime_str,
                            "uptime_seconds": uptime_sec,
                        },
                        "disk": {
                            "total_bytes": disk_total,
                            "usage_bytes": disk_usage,
                            "total_gb": round(disk_total / 1024**3, 2),
                            "usage_gb": round(disk_usage / 1024**3, 2),
                            "usage_percent": round(disk_usage / disk_total * 100, 2)
                            if disk_total > 0
                            else 0,
                        },
                        "services": service_status,
                    }
                )

            return {"nodes": nodes_result}
        return {"error": "Unable to retrieve system monitor data"}

    elif name == "update_ip_group":
        body = {"id": args["id"], "name": args["name"]}
        if "comment" in args:
            body["comment"] = args["comment"]
        return client.put("/api/IPGroupAPI", body)

    elif name == "delete_ip_group":
        return client.delete("/api/IPGroupAPI", {"id__in": args["id__in"]})

    elif name == "add_ip_to_group":
        group_id = _require_ip_group_id(args)
        return client.post(
            "/api/EditIPGroupItem",
            {
                "id": group_id,
                "targets": args["ips"],
            },
        )

    elif name == "delete_ip_from_group":
        group_id = _require_ip_group_id(args)
        return client.post(
            "/api/EditIPGroupItem",
            {
                "id": group_id,
                "remove_targets": args["ips"],
            },
        )

    # ---- 统计信息 ----
    elif name == "get_overview":
        params = {}
        if "duration" in args:
            params["duration"] = args["duration"]
        return client.get("/api/OverviewAPI", params=params)

    # ---- 站点管理 ----
    elif name == "list_websites":
        params = {}
        for key in ("id__in", "count", "offset"):
            if key in args:
                params[key] = args[key]
        return client.get("/api/SoftwareReverseProxyWebsiteAPI", params=params)

    elif name == "create_website":
        # Extract ports from host configuration
        ports = []
        for host_config in args.get("host", []):
            port_config = {
                "port": host_config.get("port", 80),
                "ssl": host_config.get("ssl", False),
                "http2": host_config.get("http2", False),
                "is_double_cert": host_config.get("is_double_cert", False),
                "non_http": host_config.get("non_http", False),
                "proxy_protocol": host_config.get("proxy_protocol", False),
                "sni": host_config.get("sni", False),
            }
            ports.append(port_config)

        # Extract upstream servers
        servers = []
        for upstream in args.get("upstreams", []):
            server_config = {
                "host": upstream.get("host", ""),
                "port": upstream.get("port", 80),
                "protocol": upstream.get("protocol", "http"),
                "is_enabled": upstream.get("is_enabled", True),
                "weight": upstream.get("weight", 1),
            }
            servers.append(server_config)

        body = {
            "name": args["name"],
            "ports": ports,
            "server_names": args.get("server_names", ["*"]),
            "url_paths": [{"op": "pre", "url_path": "/", "sni": False}],
            "ssl_cert": None,
            "ssl_gm_cert": None,
            "interface": "",
            "ip": [],
            "operation_mode": "Software Reverse Proxy",
            "policy_group": args.get("policy_group", 3),
            "ssl_ciphers": "",
            "ssl_protocols": [],
            "session_method": {"param": "", "type": "off"},
            "create_time": 0,
            "last_update_time": 0,
            "is_enabled": True,
            "backend_config": {
                "type": "proxy",
                "servers": servers,
                "load_balance_policy": "Round Robin",
                "x_forwarded_for_action": "append",
                "keepalive_config": "default_keepalive_config",
                "keepalive": 0,
                "keepalive_timeout": 0,
                "custom_config": {"ignore_types": [], "custom": {}, "custom_web": []},
                "slow_attack": {"is_enabled": False, "isAuto": False},
                "header_config": [],
            },
            "detector_ip_source": [],
            "policy_rules": [],
            "access_log": {
                "is_enabled": True,
                "log_request_header": False,
                "log_response_header": False,
                "log_option": "Drop",
                "req_body": False,
                "rsp_body": False,
            },
            "health_check_status": "HEALTHY",
            "proxy_ip_list": [],
            "proxy_ip_groups": [],
            "remark": args.get("comment", ""),
            "proxy_bind_config": {
                "enable": False,
                "proxy_bind_ip_list": [],
                "hash_select_ip_method": "remote_addr_and_port",
            },
            "bot_config": {"is_enabled": False},
            "dynamic_resolve_upstream_config": {
                "is_enabled": False,
                "dynamic_resolve_fallback": "next",
                "dynamic_resolve_fail_timeout": 10,
                "resolver_config": {"valid": 0, "resolver_timeout": 30},
            },
            "deep_detection_config": {"is_enabled": False},
            "bot_configs": [],
            "selected_tengine": {"type": "all", "tengine_list": None},
            "anti_tamper_status": "not_enabled",
            "anti_tamper_rules": [],
            "asset_group": 1,
            "ntlm_enabled": False,
            "proxy_protocol": False,
            "realip_config_enable": False,
            "realip_config": {
                "set_real_ip_from": "",
                "real_ip_header": "proxy_protocol",
            },
            "detector_ip_source_from": "default",
            "cookie_security": {"is_enabled": False},
        }
        return client.post("/api/SoftwareReverseProxyWebsiteAPI", body)

    elif name == "update_website":
        # First get the existing site configuration
        existing_sites = client.get(
            "/api/SoftwareReverseProxyWebsiteAPI", params={"id__in": [args["id"]]}
        )
        if not existing_sites or not existing_sites.get("data"):
            return {"error": f"Site with ID {args['id']} not found"}

        existing_site = existing_sites["data"][0]

        # Extract ports from host configuration
        ports = []
        for host_config in args.get("host", []):
            port_config = {
                "port": host_config.get("port", 80),
                "ssl": host_config.get("ssl", False),
                "http2": host_config.get("http2", False),
                "is_double_cert": host_config.get("is_double_cert", False),
                "non_http": host_config.get("non_http", False),
                "proxy_protocol": host_config.get("proxy_protocol", False),
                "sni": host_config.get("sni", False),
            }
            ports.append(port_config)

        # Extract upstream servers
        servers = []
        for upstream in args.get("upstreams", []):
            server_config = {
                "host": upstream.get("host", ""),
                "port": upstream.get("port", 80),
                "protocol": upstream.get("protocol", "http"),
                "is_enabled": upstream.get("is_enabled", True),
                "weight": upstream.get("weight", 1),
            }
            servers.append(server_config)

        body = {
            "id": args["id"],
            "name": args["name"],
            "ports": ports,
            "server_names": args.get(
                "server_names", existing_site.get("server_names", ["*"])
            ),
            "url_paths": existing_site.get(
                "url_paths", [{"op": "pre", "url_path": "/", "sni": False}]
            ),
            "ssl_cert": existing_site.get("ssl_cert"),
            "ssl_gm_cert": existing_site.get("ssl_gm_cert"),
            "interface": existing_site.get("interface", ""),
            "ip": existing_site.get("ip", []),
            "operation_mode": existing_site.get(
                "operation_mode", "Software Reverse Proxy"
            ),
            "policy_group": args.get(
                "policy_group", existing_site.get("policy_group", 3)
            ),
            "ssl_ciphers": existing_site.get("ssl_ciphers", ""),
            "ssl_protocols": existing_site.get("ssl_protocols", []),
            "session_method": existing_site.get(
                "session_method", {"param": "", "type": "off"}
            ),
            "create_time": existing_site.get("create_time", 0),
            "last_update_time": 0,
            "is_enabled": existing_site.get("is_enabled", True),
            "backend_config": {
                "type": "proxy",
                "servers": servers,
                "load_balance_policy": existing_site.get("backend_config", {}).get(
                    "load_balance_policy", "Round Robin"
                ),
                "x_forwarded_for_action": existing_site.get("backend_config", {}).get(
                    "x_forwarded_for_action", "append"
                ),
                "keepalive_config": existing_site.get("backend_config", {}).get(
                    "keepalive_config", "default_keepalive_config"
                ),
                "keepalive": existing_site.get("backend_config", {}).get(
                    "keepalive", 0
                ),
                "keepalive_timeout": existing_site.get("backend_config", {}).get(
                    "keepalive_timeout", 0
                ),
                "custom_config": existing_site.get("backend_config", {}).get(
                    "custom_config",
                    {"ignore_types": [], "custom": {}, "custom_web": []},
                ),
                "slow_attack": existing_site.get("backend_config", {}).get(
                    "slow_attack", {"is_enabled": False, "isAuto": False}
                ),
                "header_config": existing_site.get("backend_config", {}).get(
                    "header_config", []
                ),
            },
            "detector_ip_source": existing_site.get("detector_ip_source", []),
            "policy_rules": existing_site.get("policy_rules", []),
            "access_log": existing_site.get(
                "access_log",
                {
                    "is_enabled": True,
                    "log_request_header": False,
                    "log_response_header": False,
                    "log_option": "Drop",
                    "req_body": False,
                    "rsp_body": False,
                },
            ),
            "health_check_status": existing_site.get("health_check_status", "HEALTHY"),
            "proxy_ip_list": existing_site.get("proxy_ip_list", []),
            "proxy_ip_groups": existing_site.get("proxy_ip_groups", []),
            "remark": args.get("comment", existing_site.get("remark", "")),
            "proxy_bind_config": existing_site.get(
                "proxy_bind_config",
                {
                    "enable": False,
                    "proxy_bind_ip_list": [],
                    "hash_select_ip_method": "remote_addr_and_port",
                },
            ),
            "bot_config": existing_site.get("bot_config", {"is_enabled": False}),
            "dynamic_resolve_upstream_config": existing_site.get(
                "dynamic_resolve_upstream_config",
                {
                    "is_enabled": False,
                    "dynamic_resolve_fallback": "next",
                    "dynamic_resolve_fail_timeout": 10,
                    "resolver_config": {"valid": 0, "resolver_timeout": 30},
                },
            ),
            "deep_detection_config": existing_site.get(
                "deep_detection_config", {"is_enabled": False}
            ),
            "bot_configs": existing_site.get("bot_configs", []),
            "selected_tengine": existing_site.get(
                "selected_tengine", {"type": "all", "tengine_list": None}
            ),
            "anti_tamper_status": existing_site.get(
                "anti_tamper_status", "not_enabled"
            ),
            "anti_tamper_rules": existing_site.get("anti_tamper_rules", []),
            "asset_group": existing_site.get("asset_group", 1),
            "ntlm_enabled": existing_site.get("ntlm_enabled", False),
            "proxy_protocol": existing_site.get("proxy_protocol", False),
            "realip_config_enable": existing_site.get("realip_config_enable", False),
            "realip_config": existing_site.get(
                "realip_config",
                {"set_real_ip_from": "", "real_ip_header": "proxy_protocol"},
            ),
            "detector_ip_source_from": existing_site.get(
                "detector_ip_source_from", "default"
            ),
            "cookie_security": existing_site.get(
                "cookie_security", {"is_enabled": False}
            ),
        }
        return client.put("/api/SoftwareReverseProxyWebsiteAPI", body)

    elif name == "delete_website":
        return client.delete(
            "/api/SoftwareReverseProxyWebsiteAPI", {"id__in": args["id__in"]}
        )

    # ---- Bypass 状态 ----
    elif name == "get_software_reverse_proxy_bypass_state":
        return client.get("/api/SoftwareReverseProxyBypassStateAPI")

    elif name == "get_software_reverse_proxy_bypass_threshold":
        return client.get("/api/SoftwareReverseProxyBypassThresholdAPI")

    elif name == "update_software_reverse_proxy_bypass_threshold":
        body = {}
        for key in ("enable", "requests", "cpu_usage", "disk_usage", "memory_usage"):
            if key in args:
                body[key] = args[key]
        return client.put("/api/SoftwareReverseProxyBypassThresholdAPI", body)

    # ---- 入侵检测 ----
    elif name == "get_intrusion_detection_status":
        return client.get("/api/EnableDisableDetectorAPI")

    elif name == "enable_intrusion_detection":
        return client.put("/api/EnableDisableDetectorAPI", {"is_enabled": True})

    elif name == "disable_intrusion_detection":
        return client.put("/api/EnableDisableDetectorAPI", {"is_enabled": False})

    elif name == "get_detection_engine_degraded_config":
        return client.get("/api/DetectorConfigStateAPI")

    elif name == "enable_detection_engine_degraded":
        body = {
            "is_enabled": True,
            "is_degraded": True,
            "degraded_config": {
                "threshold": args.get("threshold", 80),
                "recover_duration": args.get("recover_duration", 60000),
                "fallback_duration": args.get("fallback_duration", 60000),
                "threshold_duration": args.get("threshold_duration", 5000),
            },
        }
        return client.put("/api/DetectorConfigStateAPI", body)

    elif name == "disable_detection_engine_degraded":
        body = {
            "is_enabled": True,
            "is_degraded": False,
            "degraded_config": {
                "threshold": args.get("threshold", 80),
                "recover_duration": args.get("recover_duration", 60000),
                "fallback_duration": args.get("fallback_duration", 60000),
                "threshold_duration": args.get("threshold_duration", 5000),
            },
        }
        return client.put("/api/DetectorConfigStateAPI", body)

    # ---- 证书管理 ----
    elif name == "list_certs":
        params = {}
        for key in ("count", "offset"):
            if key in args:
                params[key] = args[key]
        return client.get("/api/CertAPI", params=params)

    elif name == "delete_cert":
        return client.delete("/api/CertAPI", {"id__in": args["id__in"]})

    # ---- 日志标记 ----
    elif name == "get_log_flag_config":
        return client.get("/api/LogFlagConfig")

    elif name == "update_log_flag_config":
        return client.put("/api/LogFlagConfig", args["config"])

    # ---- 筛选 ----
    elif name == "get_filter_options":
        filter_type_map = {
            "acl_manual_users": ("GET", "/api/FilterV2API", {"type": "acl_manual"}),
            "acl_auto_users": ("GET", "/api/FilterV2API", {"type": "acl_auto"}),
            "acl_templates": ("GET", "/api/FilterV2API", {"type": "acl_template"}),
            "attack_logs": ("GET", "/api/FilterV2API", {"type": "attack_log"}),
            "ip_groups": ("GET", "/api/FilterV2API", {"type": "ip_group"}),
            "policies": ("GET", "/api/FilterV2API", {"type": "policy"}),
        }
        ft = args["filter_type"]
        if ft not in filter_type_map:
            return {"error": f"Unknown filter_type: {ft}"}
        method, path, params = filter_type_map[ft]
        return client.get(path, params=params)

    # ---- 筛选器管理 ----
    elif name == "list_saved_filters":
        params = {}
        for key in ("count", "offset"):
            if key in args:
                params[key] = args[key]
        return client.get("/api/SavedFilter", params=params)

    elif name == "create_saved_filter":
        return client.post(
            "/api/SavedFilter",
            {
                "name": args["name"],
                "filter": args["filter"],
                "filter_type": args["filter_type"],
            },
        )

    elif name == "update_saved_filter":
        body = {"id": args["id"], "name": args["name"], "filter": args["filter"]}
        return client.put("/api/SavedFilter", body)

    elif name == "delete_saved_filter":
        return client.delete("/api/SavedFilter", {"id__in": args["id__in"]})

    # ---- 数据仪表盘 / Dashboard ----
    elif name == "get_dashboard_overview":
        params = {
            "start_time": args["start_time"],
            "end_time": args["end_time"],
            "source": args["source"],
            "sections": args["sections"],
        }
        if "filter" in args:
            params["filter"] = args["filter"]
        return client.get("/api/dashboard/v1/Overview", params=params)

    # ---- 攻击检测日志 / Detect Log ----
    elif name == "get_detect_log_aggregate":
        params = {}
        if "condition" in args:
            params["condition"] = args["condition"]
        if "time_interval" in args:
            params["time_interval"] = args["time_interval"]
        if "log_size" in args:
            params["log_size"] = args["log_size"]
        return client.get("/api/DetectLogAggregateView", params=params)

    # ---- 防护策略 / Policy ----
    elif name == "list_policy_groups":
        params = {}
        if "is_default" in args:
            params["is_default"] = args["is_default"]
        return client.get("/api/PolicyGroupAPI", params=params)

    elif name == "create_policy_group":
        body = {"name": args["name"]}
        if "comment" in args:
            body["comment"] = args["comment"]
        return client.post("/api/PolicyGroupAPI", body)

    elif name == "update_policy_group":
        body = {"id": args["id"], "name": args["name"]}
        if "comment" in args:
            body["comment"] = args["comment"]
        if "modules_state" in args:
            body["modules_state"] = args["modules_state"]
        if "modules_detection_config" in args:
            body["modules_detection_config"] = args["modules_detection_config"]
        return client.put("/api/PolicyGroupAPI", body)

    elif name == "delete_policy_groups":
        return client.delete("/api/PolicyGroupAPI", {"id__in": args["id__in"]})

    elif name == "list_policy_rules":
        params = {}
        for key in (
            "id__in",
            "is_global",
            "rule_type",
            "comment__like",
            "attack_type",
            "action",
            "is_enabled",
            "count",
            "offset",
        ):
            if key in args:
                params[key] = args[key]
        return client.get("/api/PolicyRuleAPI", params=params)

    elif name == "create_policy_rule":
        body = {
            "name": args["name"],
            "action": args["action"],
            "pattern": args.get("pattern", {"$AND": []}),
            "attack_type": args.get("attack_type", -1),
            "description": args.get("description", ""),
            "comment": args.get("comment", ""),
            "is_enabled": args.get("is_enabled", True),
            "is_global": args.get("is_global", False),
            "expire_time": args.get("expire_time", 0),
            "log_option": args.get("log_option", ""),
            "percentage": args.get("percentage", 100),
            "duration": args.get("duration", 1),
            "priority": args.get("priority", 0),
            "delay": args.get("delay", 0),
            "websites": args.get("websites", []),
            "session_method": args.get(
                "session_method", {"type": "src_ip", "param": ""}
            ),
            "cron_config": args.get(
                "cron_config",
                {"type": "all", "start": "00:00", "end": "23:59", "days": []},
            ),
            "forbidden_page_config": None,
            "modules_list": [],
            "module_management": {"disabled": [], "enabled": []},
            "risk_level": 0,
            "punish_type": args.get("punish_type"),
            "punish_time": args.get("punish_time"),
            "req_rule_id": "",
            "rsp_rule_id": "",
            "mark_flag": "",
            "custom_fsl": "",
            "ignore_skip_remaining": False,
            "hook": 0,
            "is_protected": False,
            "is_expired": False,
            "create_time": 0,
            "last_update_time": 0,
        }
        return client.post("/api/PolicyRuleAPI", body)

    elif name == "update_policy_rule":
        body = {
            "id": args["id"],
            "name": args["name"],
            "pattern": args.get("pattern"),
            "action": args["action"],
            "attack_type": args.get("attack_type", -1),
            "description": args.get("description", ""),
            "comment": args.get("comment", ""),
            "is_enabled": args.get("is_enabled", True),
            "is_global": args.get("is_global", False),
            "expire_time": args.get("expire_time", 0),
            "log_option": args.get("log_option", ""),
            "percentage": args.get("percentage", 100),
            "duration": args.get("duration", 1),
            "priority": args.get("priority", 0),
            "delay": args.get("delay", 0),
            "websites": args.get("websites", []),
            "session_method": args.get(
                "session_method", {"type": "src_ip", "param": ""}
            ),
            "cron_config": args.get(
                "cron_config",
                {"type": "all", "start": "00:00", "end": "23:59", "days": []},
            ),
            "risk_level": 0,
            "punish_type": args.get("punish_type"),
            "punish_time": args.get("punish_time"),
            "forbidden_page_config": None,
            "modules_list": [],
            "module_management": {"disabled": [], "enabled": []},
            "req_rule_id": "",
            "rsp_rule_id": "",
            "mark_flag": "",
            "custom_fsl": "",
            "ignore_skip_remaining": False,
            "hook": 0,
            "is_protected": False,
            "is_expired": False,
            "last_update_time": 0,
        }
        return client.put("/api/PolicyRuleAPI", body)

    elif name == "delete_policy_rules":
        return client.delete("/api/PolicyRuleAPI", {"id__in": args["id__in"]})

    # ---- 智学习 / Traffic Learning ----
    elif name == "get_traffic_learning_overview":
        return client.get("/api/traffic_learning/v1/Overview")

    elif name == "list_traffic_learning_intfs":
        return client.get("/api/traffic_learning/v1/Intf")

    elif name == "create_traffic_learning_intf":
        body = {"name": args["name"], "website_ids": args["website_ids"]}
        return client.post("/api/traffic_learning/v1/Intf", body)

    elif name == "update_traffic_learning_intf":
        body = {"id": args["id"]}
        if "name" in args:
            body["name"] = args["name"]
        if "website_ids" in args:
            body["website_ids"] = args["website_ids"]
        return client.put("/api/traffic_learning/v1/Intf", body)

    elif name == "delete_traffic_learning_intfs":
        return client.delete(
            "/api/traffic_learning/v1/Intf", {"id__in": args["id__in"]}
        )

    elif name == "toggle_traffic_learning_intf":
        return client.post(
            "/api/traffic_learning/v1/ToggleIntf",
            {"id": args["id"], "enabled": args["enabled"]},
        )

    # ---- 报告 / Report ----
    elif name == "create_report_task":
        return client.post(
            "/api/report/v2/ReportTask",
            {"name": args["name"], "recipients": args["recipients"]},
        )

    elif name == "update_report_task":
        body = {"id": args["id"], "name": args["name"]}
        if "cron" in args:
            body["cron"] = args["cron"]
        if "recipients" in args:
            body["recipients"] = args["recipients"]
        return client.put("/api/report/v2/ReportTask", body)

    elif name == "send_report":
        return client.post(
            "/api/report/v2/SendReport", {"report_task_id": args["report_task_id"]}
        )

    # ---- ES 索引管理 ----
    elif name == "list_es_indices":
        return client.get("/api/ESIndices")

    elif name == "delete_es_index":
        return client.delete("/api/ESIndices", {"index_name": args["index_name"]})

    elif name == "restore_es_index":
        return client.put("/api/ESIndices", {"index_name": args["index_name"]})

    elif name == "download_es_indices":
        return client.post(
            "/api/ESDownloadIndices", {"index_name": args.get("index_name", "")}
        )

    elif name == "update_es_index_lifecycle":
        return client.put("/api/ESIndexLifecycle", args["config"])

    # ---- Config Backup ----
    elif name == "list_config_backups":
        return client.get("/api/ConfigBackupAPI")

    elif name == "create_config_backup":
        body = {
            "backup_type": args["backup_type"],
            "timing": args["timing"],
        }
        optional_keys = [
            "comment",
            "enable_auto_backup",
            "emails",
            "use_sftp",
            "state",
            "options",
            "password",
            "tfa_token",
        ]
        for key in optional_keys:
            if key in args:
                body[key] = args[key]
        return client.post("/api/ConfigBackupAPI", body)

    elif name == "delete_config_backup":
        # 1. Fetch all backups
        resp = client.get("/api/ConfigBackupAPI")
        backups = resp.get("data", [])
        if not backups:
            return {"message": "No backups found", "deleted_ids": []}

        # 2. Filter backups based on criteria
        target_ids = set()

        # Helper to parse date string to timestamp
        def parse_date(date_str):
            try:
                if " " in date_str:
                    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                else:
                    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
                return int(dt.timestamp())
            except ValueError:
                return None

        # If specific IDs provided, just use them
        if "ids" in args and args["ids"]:
            target_ids.update(args["ids"])
        else:
            # If not deleting specific IDs, filter based on other criteria
            filtered_backups = backups

            # Filter by before_date (strictly less than)
            if "before_date" in args:
                target = parse_date(args["before_date"])
                if target is not None:
                    filtered_backups = [
                        b
                        for b in filtered_backups
                        if int(b.get("create_time", 0)) < target
                    ]

            # Filter by start_date (inclusive)
            if "start_date" in args:
                target = parse_date(args["start_date"])
                if target is not None:
                    filtered_backups = [
                        b
                        for b in filtered_backups
                        if int(b.get("create_time", 0)) >= target
                    ]

            # Filter by end_date (inclusive)
            if "end_date" in args:
                target = parse_date(args["end_date"])
                if target is not None:
                    filtered_backups = [
                        b
                        for b in filtered_backups
                        if int(b.get("create_time", 0)) <= target
                    ]

            # If delete_all is true, take all filtered backups
            # If count is provided, take the latest N from filtered backups
            if "delete_all" in args and args["delete_all"]:
                target_ids.update(int(b["id"]) for b in filtered_backups if "id" in b)
            elif "count" in args:
                # Sort by create_time descending (latest first)
                sorted_backups = sorted(
                    filtered_backups,
                    key=lambda x: int(x.get("create_time", 0)),
                    reverse=True,
                )
                count = args["count"]
                to_delete = sorted_backups[:count]
                target_ids.update(int(b["id"]) for b in to_delete if "id" in b)
            else:
                # No specific mode selected, default to empty
                pass

        # 3. Perform deletion if we have IDs
        if not target_ids:
            return {"message": "No backups matched the criteria", "deleted_ids": []}

        id_list = list(target_ids)
        result = client.delete("/api/ConfigBackupAPI", {"id__in": id_list})
        return {
            "message": "Deletion successful",
            "deleted_ids": id_list,
            "api_response": result,
        }

    elif name == "download_config_backup":
        # 1. Fetch all backups
        resp = client.get("/api/ConfigBackupAPI")
        backups = resp.get("data", [])
        if not backups:
            return {"message": "No backups found", "backup_data": None}

        # 2. Filter backups based on criteria
        target_ids = set()

        # Helper to parse date string to timestamp
        def parse_date(date_str):
            try:
                if " " in date_str:
                    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                else:
                    dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
                return int(dt.timestamp())
            except ValueError:
                return None

        # If specific IDs provided, just use them
        if "ids" in args and args["ids"]:
            target_ids.update(args["ids"])
        else:
            # If not downloading specific IDs, filter based on other criteria
            filtered_backups = backups

            # Filter by before_date (strictly less than)
            if "before_date" in args:
                target = parse_date(args["before_date"])
                if target is not None:
                    filtered_backups = [
                        b
                        for b in filtered_backups
                        if int(b.get("create_time", 0)) < target
                    ]

            # Filter by after_date (strictly greater than)
            if "after_date" in args:
                target = parse_date(args["after_date"])
                if target is not None:
                    filtered_backups = [
                        b
                        for b in filtered_backups
                        if int(b.get("create_time", 0)) > target
                    ]

            # Filter by start_date (inclusive)
            if "start_date" in args:
                target = parse_date(args["start_date"])
                if target is not None:
                    filtered_backups = [
                        b
                        for b in filtered_backups
                        if int(b.get("create_time", 0)) >= target
                    ]

            # Filter by end_date (inclusive)
            if "end_date" in args:
                target = parse_date(args["end_date"])
                if target is not None:
                    filtered_backups = [
                        b
                        for b in filtered_backups
                        if int(b.get("create_time", 0)) <= target
                    ]

            # Decide what to download from filtered results
            if "count" in args:
                # Sort by create_time descending (latest first)
                sorted_backups = sorted(
                    filtered_backups,
                    key=lambda x: int(x.get("create_time", 0)),
                    reverse=True,
                )
                count = args["count"]
                to_download = sorted_backups[:count]
                target_ids.update(int(b["id"]) for b in to_download if "id" in b)
            else:
                # No count specified, download all filtered results
                target_ids.update(int(b["id"]) for b in filtered_backups if "id" in b)

        # 3. Perform download if we have IDs
        if not target_ids:
            return {"message": "No backups matched the criteria", "backup_data": None}

        id_list = list(target_ids)

        # Build params for download API (repeated id__in)
        params = {}
        for backup_id in id_list:
            if "id__in" not in params:
                params["id__in"] = []
            params["id__in"].append(backup_id)

        # Download binary data
        zip_content = client.get_binary("/api/DownloadConfigBackupAPI", params=params)

        # Return base64 encoded for JSON safety
        base64_data = base64.b64encode(zip_content).decode("utf-8")

        # Generate filename from timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"config_backup_{timestamp}.zip"

        # Determine save path (default to Downloads)
        save_path = args.get("save_path", "/Users/wendell/Downloads/")
        # Ensure path ends with separator
        if not save_path.endswith("/"):
            save_path += "/"

        # Full file path
        full_path = save_path + filename

        # Save to local file system (if running locally)
        try:
            with open(full_path, "wb") as f:
                f.write(zip_content)
            save_status = f"Saved to {full_path}"
        except Exception as e:
            save_status = f"Failed to save: {str(e)}"

        return {
            "message": "Download successful",
            "backup_ids": id_list,
            "backup_data_base64": base64_data,
            "file_size": len(zip_content),
            "file_name": filename,
            "mime_type": "application/zip",
            "save_path": full_path,
            "save_status": save_status,
        }

    else:
        return {"error": f"Unknown tool: {name}"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(description="SafeLine WAF MCP Server")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("SAFELINE_BASE_URL", ""),
        help="SafeLine 管理地址，如 https://192.168.1.1:9443（也可通过环境变量 SAFELINE_BASE_URL 设置）",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SAFELINE_TOKEN", ""),
        help="SafeLine API Token（也可通过环境变量 SAFELINE_TOKEN 设置）",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        default=False,
        help="禁用 SSL 证书验证（自签名证书时使用）",
    )
    args = parser.parse_args()

    if not args.base_url:
        parser.error(
            "必须通过 --base-url 参数或 SAFELINE_BASE_URL 环境变量指定 SafeLine 管理地址"
        )
    if not args.token:
        parser.error("必须通过 --token 参数或 SAFELINE_TOKEN 环境变量指定 API Token")

    server = create_server(args.base_url, args.token, verify_ssl=not args.no_verify_ssl)

    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream, server.create_initialization_options()
            )

    asyncio.run(run())


if __name__ == "__main__":
    main()
