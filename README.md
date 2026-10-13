# mcp-safeline
长亭雷池mcp-safeline

## 按调用指定目标设备

每个工具都接受两个**可选**参数 `base_url` 和 `token`，用于把该次调用指向另一台
雷池设备 —— 不需要改配置文件、也不需要重启 MCP server：

```jsonc
// 查指定设备
{ "name": "get_profile", "arguments": {
    "base_url": "https://192.168.1.1:9443",
    "token": "<该设备的 API-TOKEN>"
}}

// 查完切回默认设备，两个参数都不传即可
{ "name": "get_profile", "arguments": {} }
```

- 两个参数**相互独立**：只传 `base_url` 会沿用配置文件里的默认 token，只传 `token`
  则沿用默认地址。
- `base_url` 可省略 scheme（`192.168.1.1` 或 `192.168.1.1:9443` 都行，会补 `https://`），
  也可省略端口，默认 `:9443`。
- 不传时行为与改动前完全一致（用 `--base-url` / `SAFELINE_BASE_URL` 的默认目标）。
- 调用出错时返回体会带 `target` 字段，标明本次实际请求打到了哪台设备。

## 业务网关

`get_business_gateway` / `set_business_gateway` 对应「网络部署 → 路由配置 → 业务网关」。

业务网关是**设备级单例配置**：作用是把选中的链路挂进 `vrf-traffic`（路由表 100），
并写入该表的默认路由，从而与管理面（主表 `main`）的路由彻底隔离。

- **版本基线**：25.03.007 起新增。更早版本（21.07 / 23.01 / 25.03.006 及以前）调用会
  返回明确的「不支持」提示，而不是 404。
- **准入限制**（25.03.010 起由后端强制校验）：链路类型只能是**未被聚合的物理口**或
  **Bond**；VLAN、Bridge 等虚拟接口与 Bond 成员口都会被拒绝。
- **整体替换语义**：`set_business_gateway` 会覆盖既有配置（与页面一致），
  传 `link_names: []` 即解除业务网关。
- **副作用**：变更会使受影响工作组下已启用的站点短暂 disable → enable 并重新下发配置
  （这是产品设计行为，用于让 nginx `bind_dev=vrf-traffic` 生效）。

诊断时用 `network_curl` / `network_traceroute` 的 `gateway_type` 选择出口：
`manage` 走主表，`business` 走 `vrf-traffic`。

# HOW TO USE

```
#cat ~/.config/opencode/opencode.json
"mcp": {
    "safeline": {
      "command": [
        "uv",
        "--directory",
        "/pat/to/mcp-safeline",
        "run",
        "python",
        "-m",
        "mcp_safeline.server",
        "--no-verify-ssl"
      ],
      "enabled": true,
      "environment": {
        "SAFELINE_BASE_URL": "https://192.168.220.5:9443",
        "SAFELINE_TOKEN": "KHgx4pacGwID1dVWVBfNhf7VJZMyWyvZ5YA2M0K2"
      },
      "type": "local"
    }
  }
```
