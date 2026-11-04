"""Agent-facing capability registry and minimal MCP stdio server.

The server exposes bounded, auditable capabilities. It never executes arbitrary
shell commands. Target interaction is limited to the existing scope-gated HTTP GET
capability; investigation orchestration itself is offline and never runs queued steps.
"""
from __future__ import annotations

import json
import sys
import tempfile
from typing import Any

from agentsec.catalog import filter_catalog, load_catalog
from agentsec.findings import analyze_mcp_inventory
from agentsec.investigation import (
    analyze_openapi,
    generate_hypotheses,
    ingest_burp_xml,
    ingest_nmap_xml,
    ingest_nuclei_jsonl,
    scoped_http_probe,
)
from agentsec.investigation_engine import (
    create_investigation,
    investigation_report,
    next_action,
    record_result,
)
from agentsec.labs import list_scenarios, run_labs
from agentsec.planning import build_plan
from agentsec.scope import load_scope, target_is_allowed

CATALOG_PATH = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "catalog" / "techniques.json")


def _object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "object", "properties": properties, "additionalProperties": False
    }
    if required:
        result["required"] = required
    return result


def _read_json_text(value: str, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object")
    return parsed


def capability_definitions() -> list[dict[str, Any]]:
    """Return stable, machine-readable tool definitions for agent discovery."""
    return [
        {
            "name": "catalog_search",
            "description": "Search the built-in security technique catalog by exact domain or technique ID. Offline; no target interaction.",
            "inputSchema": _object_schema({
                "domain": {"type": "array", "items": {"type": "string"}},
                "ids": {"type": "array", "items": {"type": "string"}},
            }),
        },
        {
            "name": "scope_check",
            "description": "Check whether an exact target origin is permitted by a supplied authorization scope manifest. This checks authorization only; it does not contact the target.",
            "inputSchema": _object_schema({
                "scope_json": {"type": "string", "description": "Complete scope manifest JSON"},
                "target": {"type": "string", "description": "Absolute HTTP(S) target URL"},
            }, ["scope_json", "target"]),
        },
        {
            "name": "assessment_plan",
            "description": "Generate an offline assessment plan from an authorization scope manifest and optional technique domains. It does not contact the target.",
            "inputSchema": _object_schema({
                "scope_json": {"type": "string", "description": "Complete scope manifest JSON"},
                "domains": {"type": "array", "items": {"type": "string"}},
            }, ["scope_json"]),
        },
        {
            "name": "local_lab_list",
            "description": "List deterministic synthetic security labs. No network or external services.",
            "inputSchema": _object_schema({}),
        },
        {
            "name": "local_lab_run",
            "description": "Run deterministic synthetic local security labs and return structured findings. No network or external services.",
            "inputSchema": _object_schema({
                "scenario": {"type": "string", "description": "Optional exact scenario ID"}
            }),
        },
        {
            "name": "mcp_inventory_analyze",
            "description": "Statically analyze a previously captured MCP inventory JSON document. No network access.",
            "inputSchema": _object_schema({
                "inventory_json": {"type": "string", "description": "Complete MCP inventory JSON"}
            }, ["inventory_json"]),
        },
        {
            "name": "openapi_analyze",
            "description": "Statically inspect an OpenAPI JSON document supplied inline; identify endpoints and review candidates. No network access.",
            "inputSchema": _object_schema({"openapi_json": {"type": "string"}}, ["openapi_json"]),
        },
        {
            "name": "scan_result_import",
            "description": "Normalize a supplied Nmap XML, Nuclei JSONL, or Burp XML scan export. Offline parsing only.",
            "inputSchema": _object_schema({"format": {"type": "string", "enum": ["nmap_xml", "nuclei_jsonl", "burp_xml"]}, "content": {"type": "string"}}, ["format", "content"]),
        },
        {
            "name": "hypothesis_generate",
            "description": "Generate explicitly unverified investigation hypotheses from imported report JSON objects. No target interaction.",
            "inputSchema": _object_schema({"reports_json": {"type": "string", "description": "JSON array of normalized reports"}}, ["reports_json"]),
        },
        {
            "name": "http_get_probe",
            "description": "Perform one bounded, non-destructive HTTP GET to an exact-origin authorized target. Redirects are refused; no payloads or state-changing methods.",
            "inputSchema": _object_schema({"scope_json": {"type": "string"}, "url": {"type": "string"}, "timeout": {"type": "number"}}, ["scope_json", "url"]),
        },
        {
            "name": "investigation_create",
            "description": "Create a scope-checked, stateful investigation session from imported evidence. Offline planning only; no validation is executed.",
            "inputSchema": _object_schema({"scope_json": {"type": "string"}, "target": {"type": "string"}, "reports_json": {"type": "string"}, "title": {"type": "string"}}, ["scope_json", "target", "reports_json"]),
        },
        {
            "name": "investigation_next",
            "description": "Return the next queued benign review/validation action from a session. Does not execute it.",
            "inputSchema": _object_schema({"session_json": {"type": "string"}}, ["session_json"]),
        },
        {
            "name": "investigation_record",
            "description": "Record an agent/operator-supplied result for a queued investigation step; observed results remain unconfirmed.",
            "inputSchema": _object_schema({"session_json": {"type": "string"}, "step_id": {"type": "string"}, "outcome": {"type": "string", "enum": ["observed", "not_observed", "inconclusive"]}, "note": {"type": "string"}, "evidence_json": {"type": "string"}}, ["session_json", "step_id", "outcome", "note"]),
        },
        {
            "name": "investigation_report",
            "description": "Summarize investigation state, evidence, candidate paths and remaining actions. No target interaction.",
            "inputSchema": _object_schema({"session_json": {"type": "string"}}, ["session_json"]),
        },
        {
            "name": "skills_list",
            "description": "List independently installable Agent Skills with execution modes, permissions, inputs, outputs, and parallel-safety metadata. Offline only.",
            "inputSchema": _object_schema({}),
        },
        {
            "name": "skill_get",
            "description": "Return the full SKILL.md and metadata for one named skill. Offline only.",
            "inputSchema": _object_schema({"name": {"type": "string"}}, ["name"]),
        },
        {
            "name": "capability_manifest",
            "description": "Return the arsenal's agent-facing capability manifest and execution constraints.",
            "inputSchema": _object_schema({}),
        },
    ]


def capability_manifest() -> dict[str, Any]:
    return {
        "name": "Agentic Security Arsenal",
        "version": "1.6.0",
        "agent_interface": {"mcp": "stdio JSON-RPC", "python_api": "agentsec.agent_api"},
        "design": "agent-first security capability framework",
        "capabilities": capability_definitions(),
        "execution_constraints": {
            "arbitrary_shell": False,
            "automatic_exploitation": False,
            "network_access_by_default": False,
            "scope_required_for_target_interaction": True,
            "synthetic_labs_only": False,
            "active_network_access": "one bounded HTTP GET to an exact-origin authorized target; redirects refused",
            "human_approval_required_for_high_impact_actions": True,
        },
        "result_contract": {
            "format": "JSON-serializable objects",
            "principle": "include status, evidence, limitations, and next-step hints where applicable",
        },
    }


def call_capability(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    args = arguments or {}
    if not isinstance(args, dict):
        raise ValueError("Tool arguments must be an object")
    known = {item["name"]: item for item in capability_definitions()}
    if name not in known:
        raise ValueError(f"Unknown capability: {name}")
    allowed = set(known[name]["inputSchema"]["properties"])
    unexpected = set(args) - allowed
    if unexpected:
        raise ValueError("Unexpected argument(s): " + ", ".join(sorted(unexpected)))

    if name == "skills_list":
        from agentsec.skills import list_skills
        return {"skills": list_skills(), "count": len(list_skills())}
    if name == "skill_get":
        from agentsec.skills import get_skill
        return get_skill(args["name"])
    if name == "investigation_create":
        scope_doc = _read_json_text(args["scope_json"], "scope_json")
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=True) as tmp:
            json.dump(scope_doc, tmp); tmp.flush()
            validated_scope = load_scope(tmp.name)
        try:
            reports = json.loads(args["reports_json"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"reports_json must be valid JSON: {exc}") from exc
        if not isinstance(reports, list):
            raise ValueError("reports_json must be a JSON array")
        return create_investigation(validated_scope, args["target"], reports, args.get("title", "Security investigation"))
    if name == "investigation_next":
        return next_action(_read_json_text(args["session_json"], "session_json"))
    if name == "investigation_record":
        session = _read_json_text(args["session_json"], "session_json")
        evidence = None
        if args.get("evidence_json"):
            try: evidence = json.loads(args["evidence_json"])
            except json.JSONDecodeError as exc: raise ValueError(f"evidence_json must be valid JSON: {exc}") from exc
        return record_result(session, args["step_id"], args["outcome"], args["note"], evidence)
    if name == "investigation_report":
        return investigation_report(_read_json_text(args["session_json"], "session_json"))
    if name == "openapi_analyze":
        return analyze_openapi(_read_json_text(args["openapi_json"], "openapi_json"))
    if name == "scan_result_import":
        fmt, content = args["format"], args["content"]
        if fmt == "nmap_xml": return ingest_nmap_xml(content)
        if fmt == "nuclei_jsonl": return ingest_nuclei_jsonl(content)
        if fmt == "burp_xml": return ingest_burp_xml(content)
        raise ValueError("Unsupported scan result format")
    if name == "hypothesis_generate":
        try: reports = json.loads(args["reports_json"])
        except json.JSONDecodeError as exc: raise ValueError(f"reports_json must be valid JSON: {exc}") from exc
        if not isinstance(reports, list) or not all(isinstance(x, dict) for x in reports):
            raise ValueError("reports_json must be a JSON array of report objects")
        return generate_hypotheses(*reports)
    if name == "http_get_probe":
        scope_doc = _read_json_text(args["scope_json"], "scope_json")
        # Reuse the canonical file-based validator, including expiry and required fields.
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=True) as tmp:
            json.dump(scope_doc, tmp); tmp.flush()
            validated_scope = load_scope(tmp.name)
        return scoped_http_probe(args["url"], validated_scope, timeout=args.get("timeout", 8.0))
    if name == "capability_manifest":
        return capability_manifest()
    if name == "catalog_search":
        items = load_catalog(CATALOG_PATH)
        selected = filter_catalog(items, args.get("domain"), args.get("ids"))
        return {"status": "ok", "count": len(selected), "techniques": selected}
    if name == "scope_check":
        scope = _read_json_text(args["scope_json"], "scope_json")
        target = args["target"]
        permitted = target_is_allowed(target, scope)
        return {
            "status": "authorized" if permitted else "denied",
            "target": target,
            "allowed": permitted,
            "interaction_performed": False,
            "note": "Authorization check only; no network request was made.",
        }
    if name == "assessment_plan":
        scope = _read_json_text(args["scope_json"], "scope_json")
        plan = build_plan(scope, load_catalog(CATALOG_PATH), args.get("domains"))
        return {"status": "ok", "execution_mode": "offline-plan-only",
                "network_access": False, "plan": plan}
    if name == "local_lab_list":
        return {"status": "ok", "execution_mode": "deterministic-local-simulation",
                "network_access": False, "scenarios": list_scenarios()}
    if name == "local_lab_run":
        return run_labs(args.get("scenario"))
    if name == "mcp_inventory_analyze":
        inventory = _read_json_text(args["inventory_json"], "inventory_json")
        return analyze_mcp_inventory(inventory)
    raise ValueError(f"Capability is not implemented: {name}")


class MCPStdioServer:
    """Small MCP stdio server implementing initialize, tools/list and tools/call."""

    def __init__(self, input_stream=None, output_stream=None):
        self.input = input_stream or sys.stdin
        self.output = output_stream or sys.stdout
        self.initialized = False

    def _send(self, payload: dict[str, Any]) -> None:
        self.output.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n")
        self.output.flush()

    def _result(self, request_id: Any, result: dict[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _error(self, request_id: Any, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": code, "message": message}})

    def handle(self, message: dict[str, Any]) -> bool:
        if message.get("jsonrpc") != "2.0" or "method" not in message:
            self._error(message.get("id"), -32600, "Invalid JSON-RPC request")
            return True
        method, request_id = message["method"], message.get("id")
        if method == "notifications/initialized":
            self.initialized = True
            return True
        if method == "initialize":
            params = message.get("params") or {}
            self._result(request_id, {
                "protocolVersion": params.get("protocolVersion", "2025-11-25"),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "agentic-security-arsenal", "version": "1.6.0"},
                "instructions": "Use capability_manifest first. Investigation sessions are stateful planning/evidence workflows; they do not execute validation steps. Target interaction requires explicit scope and separate bounded capabilities.",
            })
            return True
        if method == "ping":
            self._result(request_id, {})
            return True
        if method == "tools/list":
            self._result(request_id, {"tools": capability_definitions()})
            return True
        if method == "tools/call":
            params = message.get("params") or {}
            try:
                output = call_capability(params.get("name", ""), params.get("arguments") or {})
                self._result(request_id, {
                    "content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False)}],
                    "structuredContent": output,
                    "isError": False,
                })
            except Exception as exc:  # noqa: BLE001 - any capability failure must surface as an MCP error response
                self._result(request_id, {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                })
            return True
        if method.startswith("notifications/"):
            return True
        if request_id is not None:
            self._error(request_id, -32601, f"Method not found: {method}")
        return True

    def serve_forever(self) -> int:
        for line in self.input:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
                if not isinstance(message, dict):
                    raise ValueError("JSON-RPC message must be an object")
                self.handle(message)
            except (json.JSONDecodeError, ValueError) as exc:
                self._error(None, -32700, str(exc))
        return 0


def serve_stdio() -> int:
    return MCPStdioServer().serve_forever()
