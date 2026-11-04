from pathlib import Path
import sys

import pytest

from agentsec.mcp_inspector import (
    MCPInspectionError,
    inspect_stdio_server,
    parse_server_command,
)

FIXTURE = Path(__file__).parent / "fixtures" / "mock_mcp_server.py"


def test_passive_inspector_enumerates_all_surfaces_and_pages():
    report = inspect_stdio_server([sys.executable, str(FIXTURE)])
    inventory = report["inventory"]
    assert len(inventory["tools"]["items"]) == 2
    assert len(inventory["resources"]["items"]) == 1
    assert len(inventory["resources/templates"]["items"]) == 1
    assert len(inventory["prompts"]["items"]) == 1
    assert report["execution_boundary"]["tools_invoked"] is False
    assert report["execution_boundary"]["resources_read"] is False
    assert any(item["id"] == "MCP-INV-008" for item in report["findings"])


def test_command_parser_does_not_accept_empty_command():
    with pytest.raises(MCPInspectionError):
        parse_server_command("  ")


def test_inspector_rejects_invalid_timeout():
    with pytest.raises(MCPInspectionError):
        inspect_stdio_server([sys.executable, str(FIXTURE)], timeout=121)


def test_inspector_reports_missing_executable():
    with pytest.raises(FileNotFoundError):
        inspect_stdio_server(["/definitely/not/a/real/path/agentsec-command-that-does-not-exist"])


def test_modern_stateless_protocol_is_negotiated_and_used_per_request():
    modern_fixture = Path(__file__).parent / "fixtures" / "mock_mcp_modern_server.py"
    report = inspect_stdio_server([sys.executable, str(modern_fixture)])
    assert report["protocol_era"] == "modern-stateless"
    assert report["protocol_version"] == "2026-07-28"
    assert report["server_info"]["name"] == "modern-fixture"
    assert report["inventory"]["tools"]["items"][0]["name"] == "status"
