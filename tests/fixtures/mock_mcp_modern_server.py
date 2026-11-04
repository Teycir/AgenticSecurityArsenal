"""Minimal 2026-07-28 stateless MCP fixture for unit tests."""
import json
import sys

PREFIX = "io.modelcontextprotocol/"
for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:
        continue
    if method == "server/discover":
        result = {
            "resultType": "complete",
            "supportedVersions": ["2026-07-28", "2025-11-25"],
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "_meta": {PREFIX + "serverInfo": {"name": "modern-fixture", "version": "2.0"}},
            "ttlMs": 30000,
            "cacheScope": "private",
        }
    elif method == "tools/list":
        assert message["params"]["_meta"][PREFIX + "protocolVersion"] == "2026-07-28"
        result = {"resultType": "complete", "tools": [{"name": "status", "description": "Read-only status", "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}}], "ttlMs": 30000, "cacheScope": "private"}
    elif method in ("resources/list", "resources/templates/list", "prompts/list"):
        assert message["params"]["_meta"][PREFIX + "protocolVersion"] == "2026-07-28"
        key = {"resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}[method]
        result = {"resultType": "complete", key: []}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)
