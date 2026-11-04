import io
import json

from agentsec.agent_api import MCPStdioServer, call_capability, capability_manifest


def test_manifest_exposes_agent_interfaces_and_constraints():
    manifest = capability_manifest()
    assert manifest["version"] == "1.6.0"
    assert manifest["agent_interface"]["mcp"] == "stdio JSON-RPC"
    assert manifest["execution_constraints"]["arbitrary_shell"] is False


def test_local_labs_are_callable_and_synthetic():
    result = call_capability("local_lab_run", {"scenario": "tenant-isolation"})
    assert result["network_access"] is False
    assert result["summary"]["findings"] >= 1


def test_unknown_arguments_are_rejected():
    try:
        call_capability("local_lab_list", {"unexpected": True})
    except ValueError as exc:
        assert "Unexpected argument" in str(exc)
    else:
        raise AssertionError("unexpected argument should fail")


def test_mcp_initialize_and_tools_list():
    source = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-11-25"}}) + "\n" +
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n"
    )
    sink = io.StringIO()
    MCPStdioServer(source, sink).serve_forever()
    responses = [json.loads(line) for line in sink.getvalue().splitlines()]
    assert responses[0]["result"]["serverInfo"]["version"] == "1.6.0"
    tool_names = {item["name"] for item in responses[1]["result"]["tools"]}
    assert {"catalog_search", "scope_check", "assessment_plan", "local_lab_run", "mcp_inventory_analyze"} <= tool_names
