from agentsec.findings import analyze_mcp_inventory, compare_reports


def test_analyze_mcp_inventory_emits_normalized_findings_and_summary():
    report = {"endpoint": "https://example.invalid/mcp", "inventory": {"tools": {"items": [
        {"name": "unsafe", "inputSchema": {"type": "object", "additionalProperties": True}},
        {"name": "unsafe", "inputSchema": {"type": "object"}},
        {"name": "opaque"},
    ]}}}
    result = analyze_mcp_inventory(report)
    assert result["analysis"] == "static-mcp-inventory"
    assert result["summary"]["total"] == len(result["findings"])
    assert all({"id", "severity", "confidence", "evidence", "remediation", "status"} <= f.keys()
               for f in result["findings"])
    assert any(f["id"] == "ASA-MCP-006" for f in result["findings"])
    assert any(f["id"] == "ASA-MCP-003" for f in result["findings"])


def test_compare_reports_detects_added_resolved_and_severity_changes():
    old = {"findings": [
        {"id": "A", "target": "x", "title": "one", "severity": "low"},
        {"id": "B", "target": "x", "title": "two", "severity": "high"},
    ]}
    new = {"findings": [
        {"id": "A", "target": "x", "title": "one", "severity": "high"},
        {"id": "C", "target": "x", "title": "three", "severity": "medium"},
    ]}
    result = compare_reports(old, new)
    assert result["summary"] == {"added": 1, "resolved": 1, "severity_changes": 1}
