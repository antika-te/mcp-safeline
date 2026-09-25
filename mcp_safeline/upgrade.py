"""SafeLine 系统升级 MCP 工具（detector 引擎 / patch）

四个接口都在 skyview/skyview/update/views/v1/views.py。该模块的 import 路径含
`.v1.`，ExportAPIEntryPoints.export_urlpatterns() 会走版本化分支，
所以真实端点是 /api/update/v1/<ClassName>，而不是 /api/<ClassName>
（直接 POST /api/UploadSystemUpgradePackage 会得到 404）。

升级流程是两步：
  1. upload_upgrade_package：把 .upd 文件 multipart 上传，skyview 解包校验后
     返回 {token, meta}。token 由 TimestampSigner 签发，max_age 6 小时；
     包文件落在 DOWNLOAD_DIR，7 小时后自动删除。
  2. trigger_upgrade：用 token + meta + 管理员密码触发，写入
     SystemUpdateRecords 并推送到 NodeUtils.get_node_list() 的所有节点。

detector 包在上传阶段会额外走版本下限校验（get_upgrade_limitation），
minimum_version 由 minion gRPC 下发，本地无法预知，校验失败会在第 1 步就报错。

password 是管理员的登录密码，不是 API-TOKEN。check_password() 只在
authentication_method == password 时要求；若账号开了 TFA 还要 tfa_token。
触发升级不可逆，会重启相关服务，建议先用 list_upgrade_records /
get_upgrade_result 确认设备状态，并确认没有正在处理的升级任务。

批量升级（apply_patch_sequence）的规则：主包和它的 Minion_restart 包成对安装，
典型顺序是 p1 → restart → p2 → restart。补丁的 changelog 通常要求「本 patch 需和
SL-2023.0034-minion_restart 一起使用，并于 minion_restart 前执行」，因为 patch
只替换镜像/文件，新镜像要等基础平台服务重启后才真正加载。顺序反了补丁会看似
成功实际未生效。
每个含 patch 条目的主包后面必须紧跟一个 restart 包，缺包时直接报错并提示去补丁
下载页拿包，不会装到一半才发现。纯 detector 引擎包不需要 restart 包。
任一失败立即中止，不再装后续包。
"""

import os
import time
from typing import Any

import httpx

_UPGRADE_BASE = "/api/update/v1"
_DEFAULT_TIMEOUT = 600

# 轮询升级结果时的参数。minion_restart 会重启基础平台服务，期间 mgt-api
# 返回 502 且 body 非 JSON，必须容错，否则轮询会在服务恢复前就崩掉。
_POLL_INTERVAL = 20
_POLL_MAX_ROUNDS = 30
_POLL_HTTP_RETRIES = 10


def _upload_package(client, file_path: str) -> dict:
    if not os.path.isfile(file_path):
        raise ValueError(f"升级包不存在或不是文件: {file_path}")

    file_name = os.path.basename(file_path)
    url = f"{client.base_url}{_UPGRADE_BASE}/UploadSystemUpgradePackage"

    with open(file_path, "rb") as f:
        files = {"file": (file_name, f, "application/octet-stream")}
        with httpx.Client(verify=client.verify_ssl, timeout=_DEFAULT_TIMEOUT) as http:
            resp = http.post(url, files=files, headers={"API-TOKEN": client.token})
    resp.raise_for_status()
    return resp.json()


def _trigger(client, token: str, package_name: str, meta: list, args: dict) -> dict:
    body = {
        "token": token,
        "package_name": package_name,
        "upd_meta_data": meta,
        "password": args["password"],
    }
    if args.get("tfa_token"):
        body["tfa_token"] = args["tfa_token"]
    return client.post(f"{_UPGRADE_BASE}/SystemUpgrade", body)


def _poll_result(client, record_id: int) -> dict:
    """轮询到 processing 清空为止。

    minion_restart 会让 mgt-api 短暂 502 并返回非 JSON body，这里按瞬时故障
    重试；重试仍失败才抛出。
    """
    http_errors = 0
    for _ in range(_POLL_MAX_ROUNDS):
        time.sleep(_POLL_INTERVAL)
        try:
            resp = client.get(
                f"{_UPGRADE_BASE}/SystemUpdateResultLog",
                params={"record_id": record_id},
            )
            http_errors = 0
        except Exception:
            http_errors += 1
            if http_errors > _POLL_HTTP_RETRIES:
                raise
            continue

        data = resp.get("data", resp) if isinstance(resp, dict) else {}
        if not data.get("processing"):
            return data
    return {"timeout": True, "record_id": record_id}


def _is_restart_package(package_name: str) -> bool:
    return "restart" in package_name.lower()


_RESTART_PACKAGE_HINT = (
    "检测引擎（detector）包可单独安装；补丁（patch）包必须紧跟一个 Minion_restart "
    "通用补丁包。请到补丁下载页下载对应的 Minion_restart 包并上传到 MCP server "
    "所在主机，然后作为 packages 里的下一项传入。"
)


def _is_restart_package(package_name: str) -> bool:
    return "restart" in package_name.lower()


def _apply_sequence(client, args: dict) -> dict:
    """按 packages 的给定顺序安装升级包，并轮询每一步的结果。

    补丁主包和它的 Minion_restart 包成对安装，典型顺序是 p1 → restart → p2 → restart。
    含 patch 条目的主包下一项必须是 restart 包，否则中止并提示去下载，
    不让用户装到一半才发现补丁不会生效。纯 detector 引擎包不需要 restart 包。
    任一失败立即中止，不再装后续包。
    """
    steps = args.get("packages") or []
    if not steps:
        raise ValueError("packages 不能为空")

    results = []
    for index, path in enumerate(steps):
        name = os.path.basename(path)
        record = {"index": index, "package": name, "status": "pending"}

        uploaded = _upload_package(client, path)
        if "data" not in uploaded:
            record["status"] = "upload_rejected"
            record["response"] = uploaded
            results.append(record)
            # 主包被依赖校验拒绝时，后续包的前置也不会满足，直接中止
            return {
                "completed": False,
                "aborted_at": name,
                "reason": f"上传被拒: {uploaded.get('msg') or uploaded.get('err')}",
                "results": results,
            }
        data = uploaded["data"]

        types_in_package = [m.get("type") for m in data["meta"]]
        is_restart = _is_restart_package(name)
        if not is_restart and "patch" in types_in_package:
            nxt = os.path.basename(steps[index + 1]) if index + 1 < len(steps) else None
            if not (nxt and _is_restart_package(nxt)):
                results.append(record)
                return {
                    "completed": False,
                    "aborted_at": name,
                    "reason": _RESTART_PACKAGE_HINT,
                    "results": results,
                }

        try:
            triggered = _trigger(client, data["token"], name, data["meta"], args)
        except Exception as e:
            record["status"] = "trigger_failed"
            record["error"] = f"{type(e).__name__}: {e}"
            results.append(record)
            return {
                "completed": False,
                "aborted_at": name,
                "reason": f"触发失败: {e}",
                "results": results,
            }

        record["status"] = "triggered"
        record["kind"] = "restart" if is_restart else "main"
        record["record_id"] = triggered.get("data", {}).get("record_id")
        record["versions"] = [m.get("version") for m in data["meta"]]
        results.append(record)

        outcome = _poll_result(client, record["record_id"])
        record["nodes"] = outcome
        if outcome.get("failure"):
            record["status"] = "failed"
            return {
                "completed": False,
                "aborted_at": name,
                "reason": "存在执行失败的节点",
                "results": results,
            }
        if outcome.get("timeout"):
            record["status"] = "timeout"
            return {
                "completed": False,
                "aborted_at": name,
                "reason": "轮询超时，请用 get_upgrade_result 手动确认",
                "results": results,
            }
        record["status"] = "success"

    return {"completed": True, "results": results}


def _build_tools():
    from mcp import types

    return [
        types.Tool(
            name="upload_upgrade_package",
            description=(
                "上传系统升级包（.upd）到 SafeLine，解包并校验后返回 token 和 meta。"
                "这是升级的第一步，只落盘不触发升级，可安全调用。"
                "注意：本工具读取的是 MCP server 本机的文件路径，SafeLine 设备和 MCP server "
                "不在同一台机器时需要先把包放到 MCP server 所在主机。"
                "返回的 token 6 小时内有效，包文件 7 小时后自动清理。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "MCP server 本机上的 .upd 文件绝对路径",
                    }
                },
                "required": ["file_path"],
            },
        ),
        types.Tool(
            name="trigger_upgrade",
            description=(
                "触发系统升级，把已上传的包推送到所有节点。"
                "不可逆操作：会写入升级记录、更新 firmware_update_time，并重启相关服务，"
                "升级期间防护能力可能短暂中断。"
                "需要管理员登录密码（不是 API-TOKEN）；账号开启 TFA 时还需 tfa_token。"
                "token 来自 upload_upgrade_package 的返回值，upd_meta_data 原样回传其 meta。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "token": {
                        "type": "string",
                        "description": "upload_upgrade_package 返回的 token",
                    },
                    "package_name": {
                        "type": "string",
                        "description": "升级包文件名，如 detector-x86_64-5.11.40-334a3d28.upd",
                    },
                    "upd_meta_data": {
                        "type": "array",
                        "description": "upload_upgrade_package 返回的 meta，原样回传",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {
                                    "type": "string",
                                    "enum": ["detector", "patch"],
                                    "description": "detector=检测引擎，patch=系统补丁",
                                },
                                "version": {"type": "string"},
                                "changelog": {"type": "string"},
                            },
                            "required": ["type", "version"],
                        },
                    },
                    "password": {
                        "type": "string",
                        "description": "管理员登录密码",
                    },
                    "tfa_token": {
                        "type": "string",
                        "description": "账号开启两步验证时的动态码，未开启可不传",
                    },
                },
                "required": ["token", "package_name", "upd_meta_data", "password"],
            },
        ),
        types.Tool(
            name="list_upgrade_records",
            description="查询系统升级历史记录（只读），含升级类型、changelog、包名、完成时间。",
            inputSchema={"type": "object", "properties": {}},
        ),
        types.Tool(
            name="get_upgrade_result",
            description=(
                "查询某次升级在各节点上的执行结果（只读）。"
                "返回 processing / success / failure 三个节点 ID 列表，"
                "用于确认升级是否真正生效。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "record_id": {
                        "type": "integer",
                        "description": "升级记录 ID，来自 trigger_upgrade 的返回或 list_upgrade_records",
                    }
                },
                "required": ["record_id"],
            },
        ),
        types.Tool(
            name="apply_patch_sequence",
            description=(
                "按 packages 给定顺序批量安装升级包，并轮询每一步的结果。"
                "补丁主包和它的 Minion_restart 包成对安装，典型顺序是 "
                "p1 → restart → p2 → restart。"
                "含 patch 条目的主包下一项必须是 Minion_restart 包，缺包时会在触发前"
                "直接报错并提示去补丁下载页下载；纯 detector 检测引擎包不需要 restart 包。"
                "顺序不可调换：补丁只替换镜像和文件，新镜像要等基础平台服务重启后才真正加载，"
                "先装 restart 包会让补丁看似成功实际未生效。"
                "任一失败（上传被拒 / 触发失败 / 有节点执行失败 / 轮询超时）立即中止，"
                "后续包都不会执行。"
                "不可逆操作：会重启相关服务，升级期间防护能力可能短暂中断。"
                "文件路径是 MCP server 本机上的绝对路径；需要管理员登录密码（不是 API-TOKEN）。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "packages": {
                        "type": "array",
                        "description": (
                            "升级包文件路径列表，严格按顺序安装。"
                            "补丁包的典型顺序：p1 → restart → p2 → restart。"
                        ),
                        "items": {"type": "string"},
                    },
                    "password": {
                        "type": "string",
                        "description": "管理员登录密码",
                    },
                    "tfa_token": {
                        "type": "string",
                        "description": "账号开启两步验证时的动态码，未开启可不传",
                    },
                },
                "required": ["packages", "password"],
            },
        ),
    ]


def build_upgrade_tools():
    return _build_tools()


def _handle(client, name: str, args: dict) -> Any:
    if name == "upload_upgrade_package":
        return _upload_package(client, args["file_path"])

    if name == "trigger_upgrade":
        body = {
            "token": args["token"],
            "package_name": args["package_name"],
            "upd_meta_data": args["upd_meta_data"],
            "password": args["password"],
        }
        if args.get("tfa_token"):
            body["tfa_token"] = args["tfa_token"]
        return client.post(f"{_UPGRADE_BASE}/SystemUpgrade", body)

    if name == "list_upgrade_records":
        return client.get(f"{_UPGRADE_BASE}/SystemUpdateLog")

    if name == "get_upgrade_result":
        return client.get(
            f"{_UPGRADE_BASE}/SystemUpdateResultLog",
            params={"record_id": args["record_id"]},
        )

    if name == "apply_patch_sequence":
        return _apply_sequence(client, args)

    return None


def handle_upgrade_tool(client, name: str, args: dict) -> Any:
    """处理升级类工具调用，返回 None 表示该工具不属于本模块。"""
    return _handle(client, name, args)
