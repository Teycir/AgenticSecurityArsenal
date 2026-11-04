"""Normalized findings, deterministic MCP inventory analysis, and regression comparison."""
from __future__ import annotations

from collections import Counter
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding(*, rule_id: str, title: str, severity: str, detail: str,
            target: str = "", evidence: Any = None, remediation: str = "",
            confidence: str = "medium") -> dict[str, Any]:
    """Create a stable, machine-readable finding record."""
    return {
        "id": rule_id, "title": title, "severity": severity.lower(),
        "confidence": confidence, "detail": detail, "target": target,
        "evidence": evidence if evidence is not None else [],
        "remediation": remediation,
        "status": "needs-human-validation",
    }


def analyze_mcp_inventory(report: dict[str, Any]) -> dict[str, Any]:
    """Analyze an AgentSec MCP inventory JSON report without contacting its target."""
    inventory = report.get("inventory", report)
    tools_section = inventory.get("tools", {})
    tools = tools_section.get("items", []) if isinstance(tools_section, dict) else []
    findings: list[dict[str, Any]] = []
    target = str(report.get("endpoint", report.get("target", "")))

    names = [str(t.get("name", "<unnamed>")) for t in tools if isinstance(t, dict)]
    duplicates = sorted(n for n, count in Counter(names).items() if count > 1)
    for name in duplicates:
        findings.append(finding(rule_id="ASA-MCP-006", title=f"Duplicate tool name: {name}",
            severity="medium", confidence="high", target=target, evidence={"tool_name": name},
            detail="Multiple tool definitions share a name, which can create ambiguous routing or review.",
            remediation="Ensure tool names are unique and clients reject ambiguous definitions."))

    for tool in tools:
        if not isinstance(tool, dict):
            findings.append(finding(rule_id="ASA-MCP-007", title="Malformed tool definition",
                severity="medium", confidence="high", target=target, evidence=tool,
                detail="The inventory contains a tool entry that is not an object.",
                remediation="Return schema-valid tool definitions and validate server responses."))
            continue
        name = str(tool.get("name", "<unnamed>"))
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict):
            findings.append(finding(rule_id="ASA-MCP-001", title=f"Tool {name} lacks an inspectable input schema",
                severity="medium", confidence="high", target=target, evidence={"tool": tool},
                detail="The tool definition omitted a valid inputSchema; argument validation cannot be assessed.",
                remediation="Publish a complete JSON Schema and validate arguments server-side."))
        else:
            if schema.get("type") != "object":
                findings.append(finding(rule_id="ASA-MCP-002", title=f"Tool {name} has a non-object input schema",
                    severity="low", confidence="high", target=target, evidence={"schema": schema},
                    detail="Review whether the input schema matches the intended tool contract.",
                    remediation="Use an object schema with explicit properties where applicable."))
            if schema.get("additionalProperties") is True:
                findings.append(finding(rule_id="ASA-MCP-003", title=f"Tool {name} accepts additional properties",
                    severity="low", confidence="high", target=target, evidence={"schema": schema},
                    detail="Undeclared arguments may be accepted by clients or downstream handlers.",
                    remediation="Set additionalProperties to false unless extensibility is intentional."))
        if not str(tool.get("description", "")).strip():
            findings.append(finding(rule_id="ASA-MCP-004", title=f"Tool {name} lacks a description",
                severity="info", confidence="high", target=target, evidence={"tool_name": name},
                detail="Missing descriptions reduce transparency for operators and model-facing clients.",
                remediation="Document purpose, side effects, required authorization, and data handling."))
        annotations = tool.get("annotations")
        if not isinstance(annotations, dict) or annotations.get("readOnlyHint") is not True:
            findings.append(finding(rule_id="ASA-MCP-005", title=f"Tool {name} is not declared read-only",
                severity="info", confidence="low", target=target, evidence={"annotations": annotations or {}},
                detail="The tool is not declared read-only. MCP annotations are hints, not security guarantees.",
                remediation="Review side effects and enforce explicit approval and authorization server-side."))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["id"], f["title"]))
    counts = Counter(f["severity"] for f in findings)
    return {"schema_version": "1.0", "tool": "Agentic Security Arsenal", "target": target,
            "analysis": "static-mcp-inventory", "findings": findings,
            "summary": {"total": len(findings), "by_severity": dict(counts)},
            "limitations": ["Static metadata analysis only; no tools were invoked.",
                            "Findings require human validation and do not prove exploitability."]}


def compare_reports(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare finding sets using stable rule ID + target + title identity."""
    def key(f: dict[str, Any]) -> tuple[str, str, str]:
        return (str(f.get("id", "")), str(f.get("target", "")), str(f.get("title", "")))
    old = {key(f): f for f in baseline.get("findings", [])}
    new = {key(f): f for f in current.get("findings", [])}
    added = [new[k] for k in sorted(new.keys() - old.keys())]
    resolved = [old[k] for k in sorted(old.keys() - new.keys())]
    changed = []
    for k in sorted(old.keys() & new.keys()):
        if old[k].get("severity") != new[k].get("severity"):
            changed.append({"identity": list(k), "from": old[k].get("severity"), "to": new[k].get("severity")})
    return {"schema_version": "1.0", "added": added, "resolved": resolved,
            "severity_changes": changed,
            "summary": {"added": len(added), "resolved": len(resolved), "severity_changes": len(changed)}}
