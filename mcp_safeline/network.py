"""SafeLine 硬件 WAF 网络管理 MCP 工具

按部署模式组织：
  - 反向代理（Hardware Reverse Proxy）：IP / 路由 / VLAN / 聚合 / HA / 默认路由 / 静态路由 / 工作组 / 心跳工作组
  - 透明代理（Hardware Transparent Proxy）：管理 IP / 默认路由 / VLAN / 聚合 / HA / 工作组 / 心跳工作组
  - 透明桥（Hardware Transparent Bridging）：管理 IP / 默认路由 / HA / 工作组 / 心跳工作组

部署模式通过 GET /api/ServerControlledConfigAPI?type=operation_mode 探测，
该端点在 21.07.00x / 23.01.014 / 25.03.00x 三个版本上均返回
SkyviewOptions.operation_mode（值为 SafeLineOperationMode 的可读字符串）。

诊断工具里没有 ping：skyview 只把它做成了 WebSocket（ws/v1/ping，PingConsumer），
没有对应的 REST APIView，所以无法通过 MCP 的 HTTP 客户端调用。
需要 ping 时改用 network_curl / network_traceroute 间接判断连通性。
"""

from typing import Any

import httpx

# SafeLineOperationMode 取值，来自 skyview/skyview/utils/constants/utils.py
MODE_REVERSE_PROXY = "Hardware Reverse Proxy"
MODE_TRANSPARENT_PROXY = "Hardware Transparent Proxy"
MODE_TRANSPARENT_BRIDGE = "Hardware Transparent Bridging"
MODE_ROUTER_PROXY = "Hardware Router Proxy"
MODE_PORT_MIRRORING = "Hardware Port Mirroring"

SOFTWARE_MODES = {
    "Software Reverse Proxy",
    "Software Cluster Reverse Proxy",
    "Software Port Mirroring",
}

# 硬件模式 -> 支持的工作组创建端点
_MODE_WORKGROUP_API = {
    MODE_REVERSE_PROXY: "/api/HardwareReverseProxyWorkGroupAPI",
    MODE_TRANSPARENT_PROXY: "/api/HardwareTransparentProxyWorkGroupAPI",
    MODE_TRANSPARENT_BRIDGE: "/api/HardwareTransparentBridgingWorkGroupAPI",
    # 路由代理复用反向代理端点，只是 reverse_proxy_mode 传 ReverseProxyModeRoute
    MODE_ROUTER_PROXY: "/api/HardwareReverseProxyWorkGroupAPI",
    # 端口镜像用流量检测工作组
    MODE_PORT_MIRRORING: "/api/HardwareTrafficDetectionWorkGroupAPI",
}

# 硬件模式 -> 该模式下的能力说明，写进工具描述供 LLM 参考
_MODE_CAPABILITIES = {
    MODE_REVERSE_PROXY: (
        "当前为硬件反向代理模式，可用操作：接口/地址、VLAN、链路聚合(Bond)、"
        "静态路由、默认网关、HA、数据工作组、心跳工作组。"
    ),
    MODE_TRANSPARENT_PROXY: (
        "当前为硬件透明代理模式，可用操作：接口/地址、VLAN、链路聚合(Bond)、"
        "默认网关、HA、数据工作组（需指定进出方向 direct）、心跳工作组。"
        "透明代理不使用静态路由。"
    ),
    MODE_TRANSPARENT_BRIDGE: (
        "当前为硬件透明桥模式，可用操作：接口/地址、默认网关、HA、数据工作组、心跳工作组。"
        "透明桥不使用静态路由。"
    ),
    MODE_ROUTER_PROXY: (
        "当前为硬件路由代理模式，可用操作：接口/地址、VLAN、链路聚合(Bond)、"
        "静态路由、默认网关、HA、数据工作组（用 create_reverse_proxy_workgroup 且 "
        "reverse_proxy_mode=ReverseProxyModeRoute）、心跳工作组。"
    ),
    MODE_PORT_MIRRORING: (
        "当前为硬件端口镜像模式，可用操作：接口/地址、HA、数据工作组"
        "（用 create_traffic_detection_workgroup）、心跳工作组。不使用静态路由。"
    ),
}


def _extract_modes(resp: Any) -> list[str]:
    """从 ServerControlledConfigAPI 响应中取出 operation_mode 列表。"""
    if isinstance(resp, dict):
        data = resp.get("data", resp)
        if isinstance(data, list):
            return [str(item) for item in data]
        if isinstance(data, dict):
            return [str(item) for item in data.get("operation_mode", [])]
    return []


def detect_mode(client) -> dict:
    """探测当前设备的部署模式。

    返回 {is_hardware, modes, mode, capabilities, workgroup_api}。
    软件版没有网络层配置，is_hardware 为 False。
    """
    resp = client.get("/api/ServerControlledConfigAPI", params={"type": "operation_mode"})
    modes = _extract_modes(resp)

    is_hardware = any(m not in SOFTWARE_MODES for m in modes)
    hardware_modes = [m for m in modes if m not in SOFTWARE_MODES]
    primary = hardware_modes[0] if hardware_modes else (modes[0] if modes else None)

    return {
        "modes": modes,
        "hardware_modes": hardware_modes,
        "mode": primary,
        "is_hardware": is_hardware,
        "capabilities": _MODE_CAPABILITIES.get(primary, "") if is_hardware else "当前为软件版，不涉及硬件网络层配置。",
        "workgroup_api": _MODE_WORKGROUP_API.get(primary) if is_hardware else None,
    }


def _is_ipv4(addr: str) -> bool:
    try:
        parts = str(addr).split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, AttributeError):
        return False


def _normalize_mask(addr: str, mask: Any) -> str:
    """把用户传入的掩码归一化成 skyview 的 IPField 要求的点分十进制形式。

    skyview 的 IPAndMaskSerializer.mask 是 IPField，只接受 255.255.255.0 / ffff:ff00::
    这类地址字符串，不接受裸前缀长度（"24" 会校验失败），所以这里做一次转换。
    IPv6 的掩码由调用方按地址形式传入，不做前缀转换。
    """
    text = str(mask).strip()
    if _is_ipv4(addr):
        if text.isdigit():
            return _prefix_to_mask(int(text))
        return text
    return text


def _prefix_to_mask(prefix: int) -> str:
    prefix = int(prefix)
    if not 0 <= prefix <= 32:
        raise ValueError(f"前缀长度超出范围: {prefix}")
    value = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    return f"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"


# ---------------------------------------------------------------------------
# 工具描述常量
# ---------------------------------------------------------------------------

_TOOLS_BASE = [
    (
        "get_deployment_mode",
        "探测当前设备的部署模式（软件/硬件，以及硬件下的反向代理、透明代理、透明桥、路由代理、端口镜像）。"
        "网络类操作前应先调用此工具，按返回的 capabilities 决定哪些操作可用。",
        {"type": "object", "properties": {}},
    ),
    (
        "list_network_links",
        "列出所有网络接口（device/bond/bridge/vlan），含地址、MTU、索引等属性。"
        "可用 from 参数过滤：WorkGroup（可加入工作组的）、Bonding（可做聚合成员的）、Vlan（可作 VLAN 母接口的）。",
        {
            "type": "object",
            "properties": {
                "from": {
                    "type": "string",
                    "enum": ["WorkGroup", "Bonding", "Vlan", "SSHService", "SNMPService", "WebManagementService", "ICMPEchoService"],
                    "description": "按用途过滤可选接口",
                },
            },
        },
    ),
    (
        "delete_network_links",
        "删除链路聚合(bond)或 VLAN 接口。注意：反向代理模式下，被站点使用的 IP 所在接口不允许删除。",
        {
            "type": "object",
            "properties": {
                "links": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "type": {"type": "string", "enum": ["LinkTypeBond", "LinkTypeVlan"]},
                        },
                        "required": ["name", "type"],
                    },
                    "description": "要删除的接口列表",
                }
            },
            "required": ["links"],
        },
    ),
    (
        "list_link_ips",
        "列出指定接口上的 IP 地址（含掩码与地址模式：physical 物理地址 / virtual 虚拟地址）。",
        {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "接口名，如 eth0、bond0、eth0.100"}},
            "required": ["name"],
        },
    ),
    (
        "add_link_ip",
        "给接口添加 IP 地址。mode 为 physical 时通过 netlink 立即生效；"
        "为 virtual 时由 keepalived 管理，仅在开启 HA 后随 VIP 一起漂移。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "接口名"},
                "addr": {"type": "string", "description": "IP 地址"},
                "mask": {
                    "type": "string",
                    "description": "子网掩码。点分十进制（255.255.255.0）或前缀长度（24）均可，会自动转换",
                },
                "mode": {
                    "type": "string",
                    "enum": ["InetAddrModePhysical", "InetAddrModeVirtual"],
                    "description": "默认 physical",
                },
            },
            "required": ["name", "addr", "mask"],
        },
    ),
    (
        "delete_link_ips",
        "从接口删除 IP 地址。管理口 mgmt 的最后一个 IP 不允许删除。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "接口名"},
                "addrs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "addr": {"type": "string"},
                            "mask": {"type": "string"},
                        },
                        "required": ["addr", "mask"],
                    },
                    "description": "要删除的地址列表",
                },
            },
            "required": ["name", "addrs"],
        },
    ),
    (
        "create_bond",
        "创建链路聚合(bond)接口。成员口不能是 bridge/vlan，且不能已被工作组占用。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "聚合接口名，如 bond0"},
                "link_names": {"type": "array", "items": {"type": "string"}, "description": "成员物理口列表"},
                "mode": {
                    "type": "string",
                    "enum": [
                        "BondModeBalanceRR",
                        "BondModeActiveBackup",
                        "BondModeBalanceXor",
                        "BondModeBroadcast",
                        "BondModeLacp",
                        "BondModeBalanceTLB",
                    ],
                },
                "hash_policy": {
                    "type": "string",
                    "enum": ["BondXmitHashPolicyLayer2", "BondXmitHashPolicyLayer23", "BondXmitHashPolicyLayer34"],
                },
                "primary": {"type": "string", "description": "主备模式下的主口"},
                "attrs": {
                    "type": "object",
                    "description": "高级参数，如 miimon/up_delay/down_delay/arp_interval/lacp_rate 等",
                },
            },
            "required": ["name", "link_names", "mode"],
        },
    ),
    (
        "create_vlan",
        "在接口上创建 VLAN 子接口。母接口必须是 bridge 类型。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "VLAN 接口名，如 eth0.100"},
                "parent": {"type": "string", "description": "母接口名"},
                "protocol": {"type": "string", "enum": ["VlanProtocol8021Q", "VlanProtocol8021AD"]},
                "id": {"type": "integer", "minimum": 1, "maximum": 4094, "description": "VLAN ID"},
            },
            "required": ["name", "parent", "protocol", "id"],
        },
    ),
    (
        "list_static_routes",
        "列出静态路由。透明代理/透明桥/端口镜像模式通常不使用静态路由。",
        {"type": "object", "properties": {}},
    ),
    (
        "create_static_route",
        "添加静态路由（目的网段 + 下一跳）。",
        {
            "type": "object",
            "properties": {
                "addr": {"type": "string", "description": "目的网段地址"},
                "mask": {
                    "type": "string",
                    "description": "子网掩码。点分十进制（255.255.240.0）或前缀长度（20）均可，会自动转换",
                },
                "gateway": {"type": "string", "description": "下一跳网关"},
            },
            "required": ["addr", "mask", "gateway"],
        },
    ),
    (
        "update_static_route",
        "编辑静态路由。底层实现是先删后加，路由 ID 会变化。",
        {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "路由 ID"},
                "addr": {"type": "string"},
                "mask": {"type": "string"},
                "gateway": {"type": "string"},
            },
            "required": ["id", "addr", "mask", "gateway"],
        },
    ),
    (
        "delete_static_routes",
        "批量删除静态路由。",
        {
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}, "description": "路由 ID 列表"}
            },
            "required": ["ids"],
        },
    ),
    (
        "get_default_gateway",
        "获取默认网关（IPv4 / IPv6）。",
        {"type": "object", "properties": {}},
    ),
    (
        "set_default_gateway",
        "设置默认网关。IPv4 与 IPv6 会同时写入，不需要的一方传空字符串。",
        {
            "type": "object",
            "properties": {
                "ipv4_gateway": {"type": "string", "description": "IPv4 默认网关，可为空"},
                "ipv6_gateway": {"type": "string", "description": "IPv6 默认网关，可为空"},
            },
            "required": ["ipv4_gateway", "ipv6_gateway"],
        },
    ),
    (
        "list_workgroups",
        "列出所有工作组（数据组/心跳组），含成员接口与模式。可用 from 过滤。",
        {
            "type": "object",
            "properties": {
                "from": {
                    "type": "string",
                    "enum": ["Website", "TransparentProxyWebsite", "GroupModeTrafficDetection"],
                    "description": "按用途过滤",
                },
            },
        },
    ),
    (
        "update_workgroup_comment",
        "修改工作组的备注。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "工作组名"},
                "comment": {"type": "string", "description": "备注"},
            },
            "required": ["name", "comment"],
        },
    ),
    (
        "delete_workgroups",
        "批量删除工作组。已被站点绑定的工作组需先解绑；HA 使用的心跳组不能删除。",
        {
            "type": "object",
            "properties": {
                "names": {"type": "array", "items": {"type": "string"}, "description": "工作组名列表"}
            },
            "required": ["names"],
        },
    ),
    (
        "get_workgroup_ips",
        "列出工作组内所有接口上的 IP 地址，用于确认站点可绑定的 IP。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "工作组名，不传则返回全部"}
            },
        },
    ),
    (
        "create_heartbeat_workgroup",
        "创建心跳（数据同步）工作组。全局只能有一个心跳组；HA 依赖它，开启 HA 前必须先建。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "工作组名，不传则自动生成"},
                "comment": {"type": "string"},
                "links": {"type": "array", "items": {"type": "string"}, "description": "心跳口列表"},
            },
            "required": ["comment", "links"],
        },
    ),
    (
        "create_reverse_proxy_workgroup",
        "创建硬件反向代理数据工作组。reverse_proxy_mode 为 ReverseProxyModeDirect 时对源 IP 做 SNAT，"
        "为 ReverseProxyModeRoute 时保持源 IP（路由代理模式也用本接口，此时传 Route）。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "comment": {"type": "string"},
                "links": {"type": "array", "items": {"type": "string"}},
                "reverse_proxy_mode": {
                    "type": "string",
                    "enum": ["ReverseProxyModeDirect", "ReverseProxyModeRoute"],
                },
            },
            "required": ["comment", "links"],
        },
    ),
    (
        "create_traffic_detection_workgroup",
        "创建硬件端口镜像（流量检测）数据工作组。send_reset 为 true 时需传 2 个口："
        "第一个做流量检测，第二个做阻断。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "comment": {"type": "string"},
                "links": {"type": "array", "items": {"type": "string"}},
                "cpu_num": {"type": "integer", "minimum": 0},
                "io_cpu_num": {"type": "integer", "minimum": 0},
                "memory": {"type": "integer", "minimum": 0, "description": "内存大页(MB)"},
                "send_reset": {"type": "boolean"},
                "vlan_strip": {"type": "boolean"},
            },
            "required": ["comment", "links", "cpu_num", "memory", "send_reset"],
        },
    ),
    (
        "create_transparent_proxy_workgroup",
        "创建硬件透明代理数据工作组。links 必须恰好 2 个，且需指定进出方向 direct（in/out）。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "comment": {"type": "string"},
                "links": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "direct": {"type": "string", "enum": ["GroupLinkDirectIn", "GroupLinkDirectOut"]},
                        },
                        "required": ["name", "direct"],
                    },
                },
                "whitelist_config": {
                    "type": "object",
                    "properties": {
                        "enable": {"type": "boolean"},
                        "ip_whitelist": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            "required": ["comment", "links", "whitelist_config"],
        },
    ),
    (
        "update_transparent_proxy_workgroup",
        "修改硬件透明代理工作组的白名单配置。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "whitelist_config": {
                    "type": "object",
                    "properties": {
                        "enable": {"type": "boolean"},
                        "ip_whitelist": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["enable"],
                },
            },
            "required": ["name", "whitelist_config"],
        },
    ),
    (
        "create_transparent_bridging_workgroup",
        "创建硬件透明桥数据工作组。links 为字符串列表，order 由数组顺序决定。"
        "如需指定顺序号/阻断模式等高级参数，请使用 create_transparent_bridging_workgroup_v2。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "comment": {"type": "string"},
                "links": {"type": "array", "items": {"type": "string"}},
                "cpu_num": {"type": "integer", "minimum": 0},
                "io_cpu_num": {"type": "integer", "minimum": 0},
                "memory": {"type": "integer", "minimum": 0, "description": "内存大页(MB)"},
                "send_reset": {"type": "boolean"},
            },
            "required": ["comment", "links", "cpu_num", "memory", "send_reset"],
        },
    ),
    (
        "create_transparent_bridging_workgroup_v2",
        "创建硬件透明桥数据工作组（V2，可指定接口顺序号与阻断模式等高级参数）。",
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "comment": {"type": "string"},
                "links": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "order_number": {"type": "integer"},
                        },
                        "required": ["name", "order_number"],
                    },
                },
                "cpu_num": {"type": "integer", "minimum": 0},
                "io_cpu_num": {"type": "integer", "minimum": 0},
                "memory": {"type": "integer", "minimum": 0},
                "send_reset": {"type": "boolean"},
                "blocking_mode": {"type": "string"},
                "tcp_vlan_ignore": {"type": "boolean"},
            },
            "required": ["comment", "links", "cpu_num", "memory", "send_reset"],
        },
    ),
    (
        "get_ha_config",
        "获取 HA 配置与运行状态（主备角色、VRRP 状态、心跳状态、同步状态）。",
        {"type": "object", "properties": {}},
    ),
    (
        "set_ha_config",
        "配置 HA。作为主机 mode=HAMaster 时只需 nopreempt 与 vrid，sync_key 由服务端生成并返回；"
        "作为备机 mode=HABackup 时需填写主机的 sync_key 与 master_address。"
        "前提是已创建心跳工作组。",
        {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "config": {
                    "type": "object",
                    "properties": {
                        "mode": {"type": "string", "enum": ["HAMaster", "HABackup"]},
                        "vrid": {"type": "integer", "minimum": 1, "maximum": 255, "description": "默认 50"},
                        "nopreempt": {"type": "boolean", "description": "抢占模式，仅主机"},
                        "sync_key": {"type": "string", "description": "同步密钥，仅备机"},
                        "master_address": {"type": "string", "description": "主机管理地址，仅备机"},
                    },
                    "required": ["mode"],
                },
            },
            "required": ["enabled", "config"],
        },
    ),
    (
        "list_management_services",
        "列出管理面服务（SSH / SNMP / ICMP Echo / Web 管理）的监听端口、白名单与绑定接口。",
        {"type": "object", "properties": {}},
    ),
    (
        "network_curl",
        "从设备发起一次 HTTP/HTTPS 请求，用于排查业务连通性。",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "gateway_type": {
                    "type": "string",
                    "enum": ["manage", "business"],
                    "description": "出口选择，仅 25.03 及以后支持；旧版本请勿传",
                },
            },
            "required": ["url"],
        },
    ),
    (
        "network_netstat",
        "查看设备上的连接/监听端口汇总（netstat 结果）。",
        {"type": "object", "properties": {}},
    ),
    (
        "network_nslookup",
        "在设备上解析域名，用于排查 DNS。",
        {
            "type": "object",
            "properties": {"hostname": {"type": "string", "description": "IP 或域名"}},
            "required": ["hostname"],
        },
    ),
    (
        "network_traceroute",
        "在设备上追踪到目标地址的路径，用于排查路由。",
        {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "IP 或域名"},
                "gateway_type": {
                    "type": "string",
                    "enum": ["manage", "business"],
                    "description": "出口选择，仅 25.03 及以后支持；旧版本请勿传",
                },
            },
            "required": ["hostname"],
        },
    ),
    (
        "get_business_gateway",
        "查询业务网关配置（只读）。返回被指定为业务网关出口的链路列表及其 IPv4/IPv6 网关地址。"
        "业务网关是设备级单例配置，其作用是把选中的链路挂进 vrf-traffic（路由表 100），"
        "并写入该表的默认路由，从而与管理面（主表 main）的路由彻底隔离。"
        "这是 25.03.007 起新增的能力；更早版本会返回该接口不存在。",
        {"type": "object", "properties": {}},
    ),
    (
        "set_business_gateway",
        "设置业务网关：把选中的链路挂进 vrf-traffic（表 100）并设置该表的默认路由。"
        "整体替换语义——本工具会覆盖既有配置（与页面行为一致），传空 link_names 即解除业务网关。"
        "准入限制（25.03.010 起由后端强制校验）：链路类型只能是未被聚合的物理口（LinkTypeDevice）"
        "或 Bond（LinkTypeBond）；VLAN、Bridge 等虚拟接口会被拒绝，Bond 成员口也会被拒绝。"
        "网关地址必须与所选链路同网段，且不得等于链路自身地址。"
        "注意：多口共享同一个网关地址时，只有与该网关同网段的链路会让默认路由带上出接口，"
        "但所有选中的链路都会被挂进 VRF。"
        "副作用：变更会使受影响工作组下已启用的站点短暂 disable → enable 并重新下发配置（这是设计行为）。",
        {
            "type": "object",
            "properties": {
                "link_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "业务网关链路的接口名列表，如 ['eth1.2']。"
                        "整体替换语义：只传你想保留的链路。传空数组 [] 表示解除业务网关。"
                    ),
                },
                "ipv4_gateway": {
                    "type": "string",
                    "description": "IPv4 网关地址，应与所选链路同网段，如 '192.168.2.254'。不需要时传空串。",
                },
                "ipv6_gateway": {
                    "type": "string",
                    "description": "IPv6 网关地址。不需要时传空串。",
                },
            },
            "required": ["link_names"],
        },
    ),
]


# ---------------------------------------------------------------------------
# 工具注册
# ---------------------------------------------------------------------------


def build_network_tools():
    """构造网络类 MCP 工具列表。"""
    from mcp import types

    return [
        types.Tool(name=name, description=desc, inputSchema=schema)
        for name, desc, schema in _TOOLS_BASE
    ]


def handle_network_tool(client, name: str, args: dict) -> Any:
    """处理网络类工具调用，返回 None 表示该工具不属于本模块。"""
    return _handle(client, name, args)


def _handle(client, name: str, args: dict) -> Any:
    # ---- 部署模式探测 ----
    if name == "get_deployment_mode":
        return detect_mode(client)

    # ---- 接口 ----
    if name == "list_network_links":
        params = {}
        if args.get("from"):
            params["from"] = args["from"]
        return client.get("/api/LinkAPI", params=params)

    if name == "delete_network_links":
        return client.delete("/api/LinkAPI", {"link__in": args["links"]})

    # ---- 接口 IP ----
    if name == "list_link_ips":
        return client.get("/api/LinkIPAPI", params={"name": args["name"]})

    if name == "add_link_ip":
        body = {"name": args["name"], "addr": args["addr"], "mask": _normalize_mask(args["addr"], args["mask"])}
        if args.get("mode"):
            body["mode"] = args["mode"]
        return client.post("/api/LinkIPAPI", body)

    if name == "delete_link_ips":
        addrs = [
            {"addr": item["addr"], "mask": _normalize_mask(item["addr"], item["mask"])}
            for item in args["addrs"]
        ]
        return client.delete("/api/LinkIPAPI", {"name": args["name"], "addrs": addrs})

    # ---- 链路聚合 ----
    if name == "create_bond":
        body = {"name": args["name"], "link_names": args["link_names"], "mode": args["mode"]}
        for key in ("hash_policy", "primary", "attrs"):
            if args.get(key):
                body[key] = args[key]
        return client.post("/api/BondAPI", body)

    # ---- VLAN ----
    if name == "create_vlan":
        return client.post(
            "/api/VlanAPI",
            {"name": args["name"], "parent": args["parent"], "protocol": args["protocol"], "id": args["id"]},
        )

    # ---- 静态路由 ----
    if name == "list_static_routes":
        return client.get("/api/StaticRouteAPI")

    if name == "create_static_route":
        return client.post(
            "/api/StaticRouteAPI",
            {"addr": args["addr"], "mask": _normalize_mask(args["addr"], args["mask"]), "gateway": args["gateway"]},
        )

    if name == "update_static_route":
        return client.put(
            "/api/StaticRouteAPI",
            {
                "id": args["id"],
                "addr": args["addr"],
                "mask": _normalize_mask(args["addr"], args["mask"]),
                "gateway": args["gateway"],
            },
        )

    if name == "delete_static_routes":
        return client.delete("/api/StaticRouteAPI", {"id__in": args["ids"]})

    # ---- 默认网关 ----
    if name == "get_default_gateway":
        return client.get("/api/DefaultGatewayAPI")

    if name == "set_default_gateway":
        return client.post(
            "/api/DefaultGatewayAPI",
            {"ipv4_gateway": args.get("ipv4_gateway", ""), "ipv6_gateway": args.get("ipv6_gateway", "")},
        )

    # ---- 工作组 ----
    if name == "list_workgroups":
        params = {}
        if args.get("from"):
            params["from"] = args["from"]
        return client.get("/api/WorkGroupAPI", params=params)

    if name == "update_workgroup_comment":
        return client.put("/api/WorkGroupAPI", {"name": args["name"], "comment": args["comment"]})

    if name == "delete_workgroups":
        return client.delete("/api/WorkGroupAPI", {"name__in": args["names"]})

    if name == "get_workgroup_ips":
        params = {}
        if args.get("name"):
            params["name"] = args["name"]
        return client.get("/api/WorkGroupToIPAPI", params=params)

    if name == "create_heartbeat_workgroup":
        body = {"comment": args["comment"], "links": args["links"]}
        if args.get("name"):
            body["name"] = args["name"]
        return client.post("/api/HardwareHeartbeatWorkGroupAPI", body)

    if name == "create_reverse_proxy_workgroup":
        body = {"comment": args["comment"], "links": args["links"]}
        if args.get("name"):
            body["name"] = args["name"]
        if args.get("reverse_proxy_mode"):
            body["reverse_proxy_mode"] = args["reverse_proxy_mode"]
        return client.post("/api/HardwareReverseProxyWorkGroupAPI", body)

    if name == "create_transparent_proxy_workgroup":
        body = {"comment": args["comment"], "links": args["links"], "whitelist_config": args["whitelist_config"]}
        if args.get("name"):
            body["name"] = args["name"]
        return client.post("/api/HardwareTransparentProxyWorkGroupAPI", body)

    if name == "update_transparent_proxy_workgroup":
        return client.put(
            "/api/HardwareTransparentProxyWorkGroupAPI",
            {"name": args["name"], "whitelist_config": args["whitelist_config"]},
        )

    if name == "create_traffic_detection_workgroup":
        body = {
            "comment": args["comment"],
            "links": args["links"],
            "cpu_num": args["cpu_num"],
            "memory": args["memory"],
            "send_reset": args["send_reset"],
        }
        if args.get("name"):
            body["name"] = args["name"]
        if "io_cpu_num" in args:
            body["io_cpu_num"] = args["io_cpu_num"]
        if "vlan_strip" in args:
            body["vlan_strip"] = args["vlan_strip"]
        return client.post("/api/HardwareTrafficDetectionWorkGroupAPI", body)

    if name == "create_transparent_bridging_workgroup":
        body = {
            "comment": args["comment"],
            "links": args["links"],
            "cpu_num": args["cpu_num"],
            "memory": args["memory"],
            "send_reset": args["send_reset"],
        }
        if args.get("name"):
            body["name"] = args["name"]
        if "io_cpu_num" in args:
            body["io_cpu_num"] = args["io_cpu_num"]
        return client.post("/api/HardwareTransparentBridgingWorkGroupAPI", body)

    if name == "create_transparent_bridging_workgroup_v2":
        body = {
            "comment": args["comment"],
            "links": args["links"],
            "cpu_num": args["cpu_num"],
            "memory": args["memory"],
            "send_reset": args["send_reset"],
        }
        if args.get("name"):
            body["name"] = args["name"]
        if "io_cpu_num" in args:
            body["io_cpu_num"] = args["io_cpu_num"]
        if args.get("blocking_mode"):
            body["blocking_mode"] = args["blocking_mode"]
        if "tcp_vlan_ignore" in args:
            body["tcp_vlan_ignore"] = args["tcp_vlan_ignore"]
        return client.post("/api/HardwareTransparentBridgingWorkGroupV2API", body)

    # ---- HA ----
    if name == "get_ha_config":
        return client.get("/api/HAConfigAPI")

    if name == "set_ha_config":
        return client.post("/api/HAConfigAPI", {"enabled": args["enabled"], "config": args["config"]})

    # ---- 管理面服务 ----
    if name == "list_management_services":
        return {
            "ssh": client.get("/api/SSHServiceAPI"),
            "snmp": client.get("/api/SNMPServiceAPI"),
            "icmp_echo": client.get("/api/ICMPEchoServiceAPI"),
            "web_management": client.get("/api/HardwareWebManagementServiceAPI"),
        }

    # ---- 网络诊断 ----
    if name == "network_curl":
        params = {"url": args["url"]}
        if args.get("gateway_type"):
            params["gateway_type"] = args["gateway_type"]
        return client.get("/api/CURLAPI", params=params)

    if name == "network_netstat":
        return client.get("/api/NetStatAPI")

    if name == "network_nslookup":
        return client.get("/api/NSLookUpAPI", params={"hostname": args["hostname"]})

    if name == "network_traceroute":
        params = {"hostname": args["hostname"]}
        if args.get("gateway_type"):
            params["gateway_type"] = args["gateway_type"]
        return client.get("/api/TraceRouteAPI", params=params)

    # ---- 业务网关（25.03.007 起新增）----
    if name == "get_business_gateway":
        return _business_gateway_call(client, "get", "/api/BusinessGatewayAPI")

    if name == "set_business_gateway":
        body = {
            "link_names": args.get("link_names", []),
            "ipv4_gateway": args.get("ipv4_gateway", ""),
            "ipv6_gateway": args.get("ipv6_gateway", ""),
        }
        return _business_gateway_call(client, "put", "/api/BusinessGatewayAPI", body)

    return None


# 业务网关是 25.03.007 引入的能力。更早的版本（21.07 / 23.01 / 25.03.005~006）
# 没有这个接口，调用会拿到 Django 的 404 HTML 页（非 JSON），调用方很难判断是
# 「设备版本不支持」还是「路径写错了」。这里在 HTTP 层兜住 404 并归一成明确提示。
_BUSINESS_GATEWAY_MISSING_HINT = (
    "该设备不支持业务网关。业务网关是 25.03.007 起新增的能力，"
    "当前设备版本低于该基线（21.07 / 23.01 系列，或 25.03.006 及更早）。"
    "请改用管理面默认网关（set_default_gateway），或先升级到 25.03.007 及以上。"
)


def _business_gateway_call(client, method: str, path: str, body: Any = None) -> Any:
    """调用业务网关接口；404 时归一成版本提示。"""
    try:
        if method == "put":
            return client.put(path, body)
        return client.get(path)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {"error": _BUSINESS_GATEWAY_MISSING_HINT}
        raise
