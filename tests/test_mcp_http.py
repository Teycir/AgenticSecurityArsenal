import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from agentsec.mcp_http import MCPHTTPError, inspect_http_server
from agentsec.sarif import to_sarif


class Handler(BaseHTTPRequestHandler):
    reject_origin: bool = True
    require_auth: bool = False
    legacy: bool = False

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        cls.requests: list[tuple[dict[str, str], dict[str, object]]] = []

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        type(self).requests.append((self.headers, body))
        if self.headers.get("Origin") and self.reject_origin:
            self.send_response(403)
            self.end_headers()
            return

        if self.require_auth and self.headers.get("Authorization") != "Bearer test-secret":
            self.send_response(401)
            self.end_headers()
            return
        method = body["method"]
        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        if method == "server/discover" and type(self).legacy:
            data = json.dumps(
                {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": "Method not found"}}
            ).encode()
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if method == "server/discover":
            result = {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}
        elif method == "initialize":
            result = {"protocolVersion": "2025-11-25", "serverInfo": {"name": "legacy-test", "version": "1"}, "capabilities": {}}
        elif method == "tools/list":
            result = {"tools": [{"name": "lookup", "description": "Read-only lookup", "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}}]}
        elif method == "resources/list":
            result = {"resources": []}
        elif method == "resources/templates/list":
            result = {"resourceTemplates": []}
        elif method == "prompts/list":
            result = {"prompts": []}
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)



@pytest.fixture
def server():
    Handler.requests = []
    Handler.reject_origin = True
    Handler.require_auth = False
    Handler.legacy = False
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True); thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}/mcp"
    finally:
        httpd.shutdown()
        thread.join()


def test_remote_inventory_scope_gated_and_origin_probe(server):
    scope = {"targets": [{"origin": server.rsplit("/", 1)[0]}], "accounts": ["alice", "bob"]}
    report = inspect_http_server(server, scope)
    assert report["protocol_era"] == "modern-stateless"
    assert len(report["inventory"]["tools"]["items"]) == 1
    assert len(report["authorization_review_plan"]) == 2
    assert report["findings"][0]["id"] == "MCP-HTTP-002"
    assert report["execution_boundary"]["tools_invoked"] is False


def test_remote_inspector_refuses_out_of_scope_endpoint(server):
    with pytest.raises(MCPHTTPError):
        inspect_http_server(server, {"targets": [{"origin": "http://127.0.0.1:1"}]})


def test_authentication_token_is_not_reported(server):
    Handler.require_auth = True
    scope = {"targets": [{"origin": server.rsplit("/", 1)[0]}], "accounts": []}
    report = inspect_http_server(server, scope, bearer_token="test-secret")
    serialized = json.dumps(report)
    assert "test-secret" not in serialized
    assert report["auth_observation"]["bearer_token_configured"] is True


def test_sarif_export_shape(server):
    scope = {"targets": [{"origin": server.rsplit("/", 1)[0]}], "accounts": []}
    report = inspect_http_server(server, scope)
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 1


def test_legacy_streamable_http_session_and_initialized_notification(server):
    Handler.legacy = True
    scope = {"targets": [{"origin": server.rsplit("/", 1)[0]}], "accounts": []}
    report = inspect_http_server(server, scope)
    assert report["protocol_era"] == "legacy-streamable-http"
    methods = [body["method"] for _headers, body in Handler.requests]
    assert "notifications/initialized" in methods
    assert "tools/list" in methods


def test_untrusted_origin_acceptance_is_reported(server):
    Handler.reject_origin = False
    scope = {"targets": [{"origin": server.rsplit("/", 1)[0]}], "accounts": []}
    report = inspect_http_server(server, scope)
    assert any(f["id"] == "MCP-HTTP-001" for f in report["findings"])
