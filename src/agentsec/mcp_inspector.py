"""Passive MCP stdio inventory. Never invokes tools or reads resources/prompts."""
from __future__ import annotations

import json
import os
import queue
import shlex
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
META_PREFIX = "io.modelcontextprotocol/"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024


class MCPInspectionError(RuntimeError):
    """Raised when the MCP server cannot be safely inspected."""


class _StdoutReader:
    def __init__(self, stream: Any) -> None:
        self.stream = stream
        self.messages: queue.Queue[bytes | BaseException | None] = queue.Queue()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        try:
            while True:
                line = self.stream.readline(MAX_MESSAGE_BYTES + 1)
                if not line:
                    self.messages.put(None)
                    return
                if len(line) > MAX_MESSAGE_BYTES:
                    self.messages.put(MCPInspectionError("MCP message exceeded 4 MiB limit"))
                    return
                self.messages.put(line)
        except BaseException as exc:
            self.messages.put(exc)


class MCPStdioClient:
    """Minimal JSON-RPC client for passive MCP initialization and list methods."""

    def __init__(self, command: list[str], timeout: float = 10.0) -> None:
        if not command:
            raise MCPInspectionError("A server command is required")
        if timeout <= 0 or timeout > 120:
            raise MCPInspectionError("Timeout must be greater than 0 and at most 120 seconds")
        self.command = command
        self.timeout = timeout
        self.process: subprocess.Popen[bytes] | None = None
        self.reader: _StdoutReader | None = None
        self.next_id = 1
        self.protocol_version: str | None = None

    def __enter__(self) -> "MCPStdioClient":
        # No shell is used. The user explicitly supplies the executable and arguments.
        self.process = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, shell=False, close_fds=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        assert self.process.stdout is not None
        self.reader = _StdoutReader(self.process.stdout)
        return self

    def __exit__(self, *_: object) -> None:
        if self.process is None:
            return
        if self.process.stdin:
            self.process.stdin.close()
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=1.0)
        if self.process.stdout:
            self.process.stdout.close()

    def _send(self, payload: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise MCPInspectionError("MCP process is not running")
        wire = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        self.process.stdin.write(wire)
        self.process.stdin.flush()

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        request_id = self.next_id
        self.next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        if self.protocol_version == MODERN_PROTOCOL_VERSION:
            message.setdefault("params", {})["_meta"] = {
                META_PREFIX + "protocolVersion": self.protocol_version,
                META_PREFIX + "clientInfo": {"name": "agentic-security-arsenal", "version": "0.7.0"},
                META_PREFIX + "clientCapabilities": {},
            }
        self._send(message)
        assert self.reader is not None
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPInspectionError(f"Timed out waiting for MCP response to {method}")
            try:
                raw = self.reader.messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise MCPInspectionError(f"Timed out waiting for MCP response to {method}") from exc
            if raw is None:
                code = self.process.poll() if self.process else None
                raise MCPInspectionError(f"MCP server closed stdout (exit code: {code})")
            if isinstance(raw, BaseException):
                raise MCPInspectionError(str(raw))
            try:
                response = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise MCPInspectionError("MCP server emitted invalid JSON-RPC on stdout") from exc
            if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
                raise MCPInspectionError("MCP server emitted an invalid JSON-RPC message")
            if response.get("id") == request_id:
                if "error" in response:
                    return {"error": response["error"]}
                result = response.get("result")
                if not isinstance(result, dict):
                    raise MCPInspectionError(f"MCP {method} returned a non-object result")
                return {"result": result}
            # Reject server-initiated requests without executing them. This keeps
            # the passive client from becoming a sampling/elicitation proxy.
            if "method" in response and "id" in response:
                self._send({"jsonrpc": "2.0", "id": response["id"], "error": {"code": -32601, "message": "Client method not supported by passive inspector"}})


def _list_result(client: MCPStdioClient, method: str) -> dict[str, Any]:
    key = {"tools/list": "tools", "resources/list": "resources", "resources/templates/list": "resourceTemplates", "prompts/list": "prompts"}[method]
    items: list[Any] = []
    cursor: str | None = None
    for _ in range(100):
        params = {"cursor": cursor} if cursor else {}
        response = client.request(method, params)
        if "error" in response:
            error = response["error"]
            if not items and isinstance(error, dict) and error.get("code") == -32601:
                return {"supported": False, "items": [], "note": "Method not supported"}
            return {"supported": True, "items": items, "error": error}
        result = response["result"]
        page = result.get(key, [])
        if not isinstance(page, list):
            return {"supported": True, "items": items, "error": f"Malformed {key} list"}
        items.extend(page)
        next_cursor = result.get("nextCursor")
        if not next_cursor:
            return {"supported": True, "items": items}
        if not isinstance(next_cursor, str) or next_cursor == cursor:
            return {"supported": True, "items": items, "error": "Invalid or repeated pagination cursor"}
        cursor = next_cursor
    return {"supported": True, "items": items, "error": "Pagination limit exceeded (100 pages)"}


def _summarize_findings(inventory: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for tool in inventory["tools"]["items"]:
        name = str(tool.get("name", "<unnamed>"))
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict):
            findings.append({"severity": "medium", "id": "MCP-INV-001", "title": f"Tool {name} has no inspectable input schema", "detail": "The tool definition omitted a valid inputSchema; clients may have difficulty validating arguments."})
        elif schema.get("type") != "object":
            findings.append({"severity": "low", "id": "MCP-INV-002", "title": f"Tool {name} uses a non-object input schema", "detail": "Review whether the schema matches the intended tool contract."})
        elif schema.get("additionalProperties") is True:
            findings.append({"severity": "low", "id": "MCP-INV-003", "title": f"Tool {name} allows additional properties", "detail": "Consider rejecting undeclared arguments unless extensibility is intentional."})
        if not tool.get("description"):
            findings.append({"severity": "info", "id": "MCP-INV-004", "title": f"Tool {name} has no description", "detail": "Missing descriptions reduce transparency for clients and reviewers."})
        annotations = tool.get("annotations", {})
        if isinstance(annotations, dict) and annotations.get("readOnlyHint") is not True:
            findings.append({"severity": "info", "id": "MCP-INV-008", "title": f"Tool {name} is not declared read-only", "detail": "Review this tool for side effects and require explicit user approval where appropriate. MCP annotations are hints, not security guarantees."})
    for key, title, detail in (
        ("resources", "Server exposes resources", "Resource metadata was inventoried; access controls and tenant isolation need separate testing."),
        ("resources/templates", "Server exposes resource templates", "Parameterized resource patterns need authorization review."),
        ("prompts", "Server exposes prompts", "Prompt metadata was inventoried; prompt contents were not retrieved."),
    ):
        if inventory[key]["items"]:
            findings.append({"severity": "info", "id": "MCP-INV-005", "title": title, "detail": detail})
    return findings


def inspect_stdio_server(command: list[str], timeout: float = 10.0) -> dict[str, Any]:
    """Launch a local MCP stdio server and enumerate metadata only."""
    with MCPStdioClient(command, timeout=timeout) as client:
        # Probe modern stateless MCP first. Legacy servers commonly answer
        # -32601 or remain silent; both cases fall back to initialize.
        modern_result: dict[str, Any] | None = None
        try:
            discovery = client.request("server/discover", {"_meta": {
                META_PREFIX + "protocolVersion": MODERN_PROTOCOL_VERSION,
                META_PREFIX + "clientInfo": {"name": "agentic-security-arsenal", "version": "0.7.0"},
                META_PREFIX + "clientCapabilities": {},
            }})
            if "result" in discovery and isinstance(discovery["result"].get("supportedVersions"), list):
                modern_result = discovery["result"]
        except MCPInspectionError as exc:
            if "Timed out" not in str(exc):
                raise
        if modern_result is not None and MODERN_PROTOCOL_VERSION in modern_result["supportedVersions"]:
            client.protocol_version = MODERN_PROTOCOL_VERSION
            init_result = {
                "protocolVersion": MODERN_PROTOCOL_VERSION,
                "serverInfo": modern_result.get("_meta", {}).get(META_PREFIX + "serverInfo", modern_result.get("serverInfo", {})),
                "capabilities": modern_result.get("capabilities", {}),
                "discovery": modern_result,
            }
            protocol_era = "modern-stateless"
        else:
            supported = modern_result.get("supportedVersions", []) if modern_result else []
            selected_legacy = next((version for version in LEGACY_PROTOCOL_VERSIONS if version in supported), None)
            requested_legacy = selected_legacy or LEGACY_PROTOCOL_VERSIONS[0]
            init = client.request("initialize", {
                "protocolVersion": requested_legacy,
                "capabilities": {},
                "clientInfo": {"name": "agentic-security-arsenal", "version": "0.7.0"},
            })
            if "error" in init:
                raise MCPInspectionError(f"MCP initialize failed: {init['error']}")
            init_result = init["result"]
            client.protocol_version = init_result.get("protocolVersion", requested_legacy)
            client.notify("notifications/initialized")
            protocol_era = "legacy-handshake"
        inventory = {
            "tools": _list_result(client, "tools/list"),
            "resources": _list_result(client, "resources/list"),
            "resources/templates": _list_result(client, "resources/templates/list"),
            "prompts": _list_result(client, "prompts/list"),
        }
    report: dict[str, Any] = {
        "schema_version": "1.0", "inspector_version": "0.4.0",
        "generated_at": datetime.now(timezone.utc).isoformat(), "transport": "stdio",
        "server_command": command[0], "protocol_version": init_result.get("protocolVersion"),
        "protocol_era": protocol_era,
        "server_info": init_result.get("serverInfo", {}),
        "server_capabilities": init_result.get("capabilities", {}),
        "discovery": init_result.get("discovery"),
        "inventory": inventory, "findings": [],
        "execution_boundary": {
            "tools_invoked": False, "resources_read": False,
            "prompts_retrieved": False, "server_requests_executed": False,
            "note": "Passive metadata inventory only. Listing metadata does not prove authorization enforcement or absence of vulnerabilities.",
        },
    }
    report["findings"] = _summarize_findings(inventory)
    return report


def parse_server_command(value: str) -> list[str]:
    try:
        command = shlex.split(value)
    except ValueError as exc:
        raise MCPInspectionError(f"Invalid command syntax: {exc}") from exc
    if not command:
        raise MCPInspectionError("Server command cannot be empty")
    return command


def write_report(report: dict[str, Any], output: str | Path) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
