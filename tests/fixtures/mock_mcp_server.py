"""Tiny MCP stdio fixture used only by unit tests."""
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "notifications/initialized":
        continue
    request_id = message.get("id")
    if request_id is None:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}, "resources": {"listChanged": False}, "prompts": {}},
            "serverInfo": {"name": "fixture", "version": "1.0"},
        }
    elif method == "tools/list":
        assert "_meta" not in message.get("params", {})
        if message.get("params", {}).get("cursor") == "page-2":
            result = {"tools": [{"name": "delete_record", "description": "Deletes a record", "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": False}}]}
        else:
            result = {"tools": [{"name": "lookup", "description": "Looks up a record", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"], "additionalProperties": False}, "annotations": {"readOnlyHint": True}}], "nextCursor": "page-2"}
    elif method == "resources/list":
        result = {"resources": [{"uri": "file:///synthetic/demo", "name": "demo"}]}
    elif method == "resources/templates/list":
        result = {"resourceTemplates": [{"uriTemplate": "db://records/{id}", "name": "record"}]}
    elif method == "prompts/list":
        result = {"prompts": [{"name": "summarize", "arguments": [{"name": "topic", "required": True}]}]}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}), flush=True)
