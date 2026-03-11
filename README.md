# mcp-safeline
长亭雷池mcp-safeline
# HOW TO USE

```
#cat ~/.config/opencode/opencode.json
"mcp": {
    "safeline": {
      "command": [
        "uv",
        "--directory",
        "/Users/wendell/py_projects/mcp-safeline",
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
