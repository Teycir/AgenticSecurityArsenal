"""Small SARIF 2.1.0 exporter for AgentSec findings."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SEVERITY = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in findings:
        rule_id = str(finding.get("id", "AGENTSEC-UNKNOWN"))
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id.replace("-", " "),
            "shortDescription": {"text": str(finding.get("title", rule_id))},
            "help": {"text": str(finding.get("detail", ""))},
        })
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": SEVERITY.get(str(finding.get("severity", "info")).lower(), "note"),
            "message": {"text": str(finding.get("detail", finding.get("title", rule_id)))},
            "properties": {"title": str(finding.get("title", rule_id)),
                           "source": "agentic-security-arsenal",
                           "assessmentStatus": "needs-human-validation"},
        }
        if report.get("endpoint"):
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(report["endpoint"])}}}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Agentic Security Arsenal", "version": str(report.get("inspector_version", "0.5.0")),
                                  "rules": list(rules.values())}},
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}],
            "results": results,
        }],
    }
