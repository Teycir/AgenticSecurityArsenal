"""Scope-gated, metadata-only MCP Streamable HTTP inventory."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

MODERN_VERSION = "2026-07-28"
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
META = "io.modelcontextprotocol/"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class MCPHTTPError(RuntimeError):
    """Raised when a remote MCP endpoint cannot be safely inspected."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_endpoint(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise MCPHTTPError("Endpoint must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise MCPHTTPError("Credentials in endpoint URLs are not allowed; use --auth-env")
    if parsed.fragment or parsed.query:
        raise MCPHTTPError("Endpoint query strings and fragments are not allowed")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise MCPHTTPError("Endpoint has an invalid port") from exc


def require_target_in_scope(target: str, scope: dict[str, object]) -> None:
    from agentsec.scope import target_is_allowed

    if not target_is_allowed(target, scope):
        raise MCPHTTPError(f"Target origin is not explicitly authorized: {target}")


def _valid_origin(origin: str) -> bool:
    try:
        p = urlsplit(origin)
        if p.scheme not in {"http", "https"} or not p.hostname:
            return False
        if p.path not in {"", "/"} or p.query or p.fragment:
            return False
        if p.username is not None or p.password is not None:
            return False
        _ = p.port
        return True
    except ValueError:
        return False


def _sse_json(body: bytes) -> dict[str, Any]:
    text = body.decode("utf-8", errors="strict")
    data_lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    if not data_lines:
        raise MCPHTTPError("SSE response contained no data event")
    # Request-scoped SSE may contain notifications before the final response.
    for line in reversed(data_lines):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and ("result" in value or "error" in value):
            return value
    raise MCPHTTPError("SSE response contained no JSON-RPC result")


class StreamableHTTPClient:
    def __init__(self, endpoint: str, timeout: float, bearer_token: str | None = None,
                 origin: str | None = None) -> None:
        _validate_endpoint(endpoint)
        if timeout <= 0 or timeout > 120:
            raise MCPHTTPError("Timeout must be greater than 0 and at most 120 seconds")
        if origin and not _valid_origin(origin):
            raise MCPHTTPError("Origin probe must be a valid HTTP(S) origin without a path")
        self.endpoint = endpoint
        self.timeout = timeout
        self.token = bearer_token
        self.origin = origin
        self.protocol_version: str | None = None
        self.session_id: str | None = None
        self.next_id = 1
        self.last_status: int | None = None
        self.last_headers: dict[str, str] = {}
        self.auth_required = False
        self.origin_rejected = False
        self.origin_probe_accepted = False

    def request(self, method: str, params: dict[str, Any] | None = None,
                *, use_token: bool = False, origin: str | None = None,
                initial: bool = False) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            payload["params"] = dict(params)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "agentic-security-arsenal/0.4.0",
            "Mcp-Method": method,
        }
        if self.protocol_version and not initial:
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self.protocol_version == MODERN_VERSION and not initial:
            payload.setdefault("params", {})["_meta"] = {
                META + "protocolVersion": self.protocol_version,
                META + "clientInfo": {"name": "agentic-security-arsenal", "version": "0.4.0"},
                META + "clientCapabilities": {},
            }
        if self.session_id and not initial:
            headers["MCP-Session-Id"] = self.session_id
        if use_token and self.token:
            headers["Authorization"] = "Bearer " + self.token
        if origin:
            headers["Origin"] = origin
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(self.endpoint, data=data, headers=headers, method="POST")
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            response = opener.open(req, timeout=self.timeout)
            status = response.status
            response_headers = dict(response.headers.items())
            body = response.read(MAX_RESPONSE_BYTES + 1)
            response.close()
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            body = exc.read(MAX_RESPONSE_BYTES + 1)
            exc.close()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MCPHTTPError(f"HTTP request failed: {exc}") from exc
        self.last_status = status
        self.last_headers = {k.lower(): v for k, v in response_headers.items()}
        if len(body) > MAX_RESPONSE_BYTES:
            raise MCPHTTPError("MCP HTTP response exceeded 4 MiB limit")
        if 300 <= status < 400:
            raise MCPHTTPError(f"Redirect refused (HTTP {status}); inspect the declared endpoint directly")
        if status in (401, 403):
            return {"http_status": status, "http_error": "authentication_or_origin_restriction"}
        if status >= 400:
            # Preserve structured JSON-RPC errors for version negotiation.
            try:
                parsed = json.loads(body.decode("utf-8"))
                if isinstance(parsed, dict) and "error" in parsed:
                    return {"http_status": status, **parsed}
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass
            return {"http_status": status, "http_error": body[:512].decode("utf-8", "replace")}
        session = self.last_headers.get("mcp-session-id")
        if session:
            if not re.fullmatch(r"[\x21-\x7e]{1,256}", session):
                raise MCPHTTPError("Server returned an invalid MCP-Session-Id header")
            self.session_id = session
        content_type = self.last_headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            result = _sse_json(body)
        else:
            try:
                result = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise MCPHTTPError("Server returned neither valid JSON nor a supported SSE response") from exc
        if not isinstance(result, dict) or result.get("jsonrpc") != "2.0":
            raise MCPHTTPError("Server returned an invalid JSON-RPC response")
        if result.get("id") != request_id:
            raise MCPHTTPError("JSON-RPC response ID did not match request")
        result["_http_status"] = status
        return result

    def notify(self, method: str, *, use_token: bool = False) -> None:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "User-Agent": "agentic-security-arsenal/0.4.0", "Mcp-Method": method}
        if self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id
        if use_token and self.token:
            headers["Authorization"] = "Bearer " + self.token
        body = json.dumps({"jsonrpc": "2.0", "method": method}, separators=(",", ":")).encode()
        req = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            response = urllib.request.build_opener(_NoRedirect()).open(req, timeout=self.timeout)
            status = response.status
            response.read(MAX_RESPONSE_BYTES + 1)
            response.close()
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MCPHTTPError(f"HTTP notification failed: {exc}") from exc
        if status != 202:
            raise MCPHTTPError(f"Expected HTTP 202 for MCP notification; received HTTP {status}")

    def negotiate(self) -> tuple[dict[str, Any], str]:
        # First send a benign discovery request with a synthetic untrusted Origin.
        # If rejected, retry without Origin; this is a configuration check, not an exploit.
        probe_origin = self.origin or "https://agentsec.invalid"
        discovery = self.request("server/discover", {"_meta": {
            META + "protocolVersion": MODERN_VERSION,
            META + "clientInfo": {"name": "agentic-security-arsenal", "version": "0.4.0"},
            META + "clientCapabilities": {},
        }}, origin=probe_origin, initial=True)
        if discovery.get("http_status") == 403:
            self.origin_rejected = True
            discovery = self.request("server/discover", {"_meta": {
                META + "protocolVersion": MODERN_VERSION,
                META + "clientInfo": {"name": "agentic-security-arsenal", "version": "0.4.0"},
                META + "clientCapabilities": {},
            }}, initial=True)
        elif "result" in discovery or (discovery.get("http_status") in (400, 404, 405) and "error" in discovery):
            # A protocol-level response means the synthetic Origin reached the MCP handler.
            self.origin_probe_accepted = True
        if discovery.get("http_status") in (401, 403):
            self.auth_required = discovery.get("http_status") == 401
            if self.token:
                discovery = self.request("server/discover", {"_meta": {
                    META + "protocolVersion": MODERN_VERSION,
                    META + "clientInfo": {"name": "agentic-security-arsenal", "version": "0.4.0"},
                    META + "clientCapabilities": {},
                }}, use_token=True, initial=True)
            else:
                raise MCPHTTPError("Endpoint requires authentication or rejected the request; provide --auth-env if authorized")
        if "result" in discovery and isinstance(discovery["result"].get("supportedVersions"), list):
            versions = discovery["result"]["supportedVersions"]
            if MODERN_VERSION in versions:
                self.protocol_version = MODERN_VERSION
                meta = discovery["result"].get("_meta", {})
                return {"protocolVersion": MODERN_VERSION,
                        "serverInfo": meta.get(META + "serverInfo", discovery["result"].get("serverInfo", {})),
                        "capabilities": discovery["result"].get("capabilities", {}),
                        "discovery": discovery["result"]}, "modern-stateless"
        # Legacy fallback: use advertised versions where available, otherwise latest legacy.
        supported = discovery.get("result", {}).get("supportedVersions", []) if "result" in discovery else []
        version = next((v for v in LEGACY_VERSIONS if v in supported), LEGACY_VERSIONS[0])
        init = self.request("initialize", {
            "protocolVersion": version, "capabilities": {},
            "clientInfo": {"name": "agentic-security-arsenal", "version": "0.4.0"},
        }, use_token=bool(self.token), initial=True)
        if "result" not in init:
            raise MCPHTTPError(f"MCP initialize failed: {init.get('error', init.get('http_error', init))}")
        result = init["result"]
        self.protocol_version = result.get("protocolVersion", version)
        self.notify("notifications/initialized", use_token=bool(self.token))
        return result, "legacy-streamable-http"

    def list_method(self, method: str) -> dict[str, Any]:
        key = {"tools/list": "tools", "resources/list": "resources",
               "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}[method]
        items: list[Any] = []
        cursor: str | None = None
        for _ in range(100):
            params = {"cursor": cursor} if cursor else {}
            result = self.request(method, params, use_token=bool(self.token))
            if "result" not in result:
                error = result.get("error", result.get("http_error", result))
                if not items and isinstance(error, dict) and error.get("code") == -32601:
                    return {"supported": False, "items": [], "note": "Method not supported"}
                return {"supported": True, "items": items, "error": error}
            page = result["result"].get(key, [])
            if not isinstance(page, list):
                return {"supported": True, "items": items, "error": f"Malformed {key} list"}
            items.extend(page)
            next_cursor = result["result"].get("nextCursor")
            if not next_cursor:
                return {"supported": True, "items": items}
            if not isinstance(next_cursor, str) or next_cursor == cursor:
                return {"supported": True, "items": items, "error": "Invalid or repeated pagination cursor"}
            cursor = next_cursor
        return {"supported": True, "items": items, "error": "Pagination limit exceeded (100 pages)"}


def inspect_http_server(endpoint: str, scope: dict[str, Any], timeout: float = 10.0,
                        bearer_token: str | None = None, origin: str | None = None) -> dict[str, Any]:
    """Inspect only an explicitly scoped endpoint; never calls tools or reads content."""
    _validate_endpoint(endpoint)
    require_target_in_scope(endpoint, scope)
    client = StreamableHTTPClient(endpoint, timeout, bearer_token, origin)
    init, era = client.negotiate()
    inventory = {
        "tools": client.list_method("tools/list"),
        "resources": client.list_method("resources/list"),
        "resources/templates": client.list_method("resources/templates/list"),
        "prompts": client.list_method("prompts/list"),
    }
    findings: list[dict[str, str]] = []
    if client.origin_probe_accepted:
        findings.append({"id": "MCP-HTTP-001", "severity": "medium", "title": "Untrusted Origin probe was accepted",
                         "detail": "The endpoint returned a successful MCP discovery response to the synthetic Origin https://agentsec.invalid. Review its Origin allowlist and DNS-rebinding protections; verify whether this origin should be trusted."})
    if client.origin_rejected:
        findings.append({"id": "MCP-HTTP-002", "severity": "info", "title": "Untrusted Origin probe was rejected",
                         "detail": "The endpoint rejected the synthetic Origin with HTTP 403. This is a positive signal, not proof that all Origin validation paths are correct."})
    if not client.token:
        findings.append({"id": "MCP-AUTH-001", "severity": "info", "title": "No bearer credential supplied",
                         "detail": "The inventory was attempted without a bearer token. This does not establish that authentication is absent; inspect the HTTP status and server-side policy."})
    findings.extend(_inventory_findings(inventory))
    principals = scope.get("accounts", [])
    auth_plan = []
    for principal in principals if isinstance(principals, list) else []:
        for tool in inventory["tools"]["items"]:
            auth_plan.append({"principal": str(principal), "tool": str(tool.get("name", "<unnamed>")),
                              "test": "Manually verify least-privilege authorization for this principal; do not invoke automatically.",
                              "status": "not_tested"})
    return {
        "schema_version": "1.1", "inspector_version": "0.4.0",
        "generated_at": datetime.now(timezone.utc).isoformat(), "transport": "streamable-http",
        "endpoint": endpoint, "protocol_version": client.protocol_version, "protocol_era": era,
        "server_info": init.get("serverInfo", {}), "server_capabilities": init.get("capabilities", {}),
        "inventory": inventory, "authorization_review_plan": auth_plan,
        "auth_observation": {"bearer_token_configured": bool(client.token),
                             "authentication_required_before_inventory": client.auth_required,
                             "note": "No identity switching, OAuth flow, or authorization bypass was attempted."},
        "findings": findings,
        "execution_boundary": {"tools_invoked": False, "resources_read": False, "prompts_retrieved": False,
                                "identity_impersonation": False, "redirects_followed": False,
                                "note": "Metadata-only HTTP inventory. Discovery/list requests are active protocol interactions; no tool call or content retrieval is performed."},
    }


def _inventory_findings(inventory: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for tool in inventory["tools"]["items"]:
        name = str(tool.get("name", "<unnamed>"))
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict):
            findings.append({"id": "MCP-INV-001", "severity": "medium", "title": f"Tool {name} has no inspectable input schema",
                             "detail": "The tool definition omitted a valid inputSchema."})
        if not tool.get("description"):
            findings.append({"id": "MCP-INV-004", "severity": "info", "title": f"Tool {name} has no description",
                             "detail": "Missing descriptions reduce transparency for clients and reviewers."})
        annotations = tool.get("annotations", {})
        if isinstance(annotations, dict) and annotations.get("readOnlyHint") is not True:
            findings.append({"id": "MCP-INV-008", "severity": "info", "title": f"Tool {name} is not declared read-only",
                             "detail": "Review possible side effects. MCP annotations are hints, not security guarantees."})
    for key, title in (("resources", "Server exposes resources"), ("resources/templates", "Server exposes resource templates"),
                       ("prompts", "Server exposes prompts")):
        if inventory[key]["items"]:
            findings.append({"id": "MCP-INV-005", "severity": "info", "title": title,
                             "detail": "Metadata was inventoried; content access controls require separate authorized testing."})
    return findings
