import json
from datetime import datetime, timedelta, timezone

import pytest

from agentsec.agent_api import call_capability, capability_definitions, capability_manifest
from agentsec.investigation_engine import (
    create_investigation, investigation_report, next_action, record_result,
)
from agentsec.scope import ScopeError


def scope(origin="https://lab.example"):
    return {
        "engagement": "authorized test lab",
        "authorized_by": "test owner",
        "valid_until": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "targets": [{"origin": origin}],
    }


def reports():
    return [
        {"source": "nmap_xml", "observations": [
            {"id": "nmap-open-port", "host": "https://lab.example", "port": "443", "service": "https"}
        ]},
        {"source": "nuclei_jsonl", "observations": [
            {"template_id": "header-check", "matched_at": "https://lab.example", "severity": "info"}
        ]},
    ]


def test_session_create_requires_exact_authorized_target():
    session = create_investigation(scope(), "https://lab.example/path", reports(), "test")
    assert session["scope_checked"] is True
    assert len(session["hypotheses"]) == 2
    assert session["status"] == "in_progress"
    with pytest.raises(ScopeError):
        create_investigation(scope(), "https://other.example", reports())


def test_attack_path_is_candidate_only_and_labeled_non_causal():
    session = create_investigation(scope(), "https://lab.example", reports())
    assert len(session["candidate_attack_paths"]) == 1
    path = session["candidate_attack_paths"][0]
    assert path["status"] == "candidate_only"
    assert path["relationship"] == "shared_target_context_only"


def test_next_record_report_loop_and_duplicate_refusal():
    session = create_investigation(scope(), "https://lab.example", reports())
    action = next_action(session)["next_action"]
    assert action["status"] == "queued"
    updated = record_result(session, action["step_id"], "observed", "Header present", {"header": "X-Test"})
    assert updated["evidence_log"][0]["source"] == "agent_or_operator_supplied"
    with pytest.raises(ValueError, match="already has"):
        record_result(updated, action["step_id"], "observed", "duplicate")
    summary = investigation_report(updated)
    assert summary["summary"]["recorded_outcomes"]["observed"] == 1
    assert "No vulnerability is marked confirmed" in summary["conclusion"]


def test_outcome_validation_and_no_auto_execution():
    session = create_investigation(scope(), "https://lab.example", reports())
    action = next_action(session)["next_action"]
    with pytest.raises(ValueError):
        record_result(session, action["step_id"], "exploited", "not allowed")
    assert session["safety"]["automatic_exploitation"] is False
    assert next_action(session)["network_access"] is False


def test_mcp_capabilities_exposed_and_callable():
    names = {item["name"] for item in capability_definitions()}
    assert {"investigation_create", "investigation_next", "investigation_record", "investigation_report"} <= names
    assert capability_manifest()["version"] == "1.6.0"
    created = call_capability("investigation_create", {
        "scope_json": json.dumps(scope()), "target": "https://lab.example",
        "reports_json": json.dumps(reports()), "title": "API review",
    })
    nxt = call_capability("investigation_next", {"session_json": json.dumps(created)})
    assert nxt["status"] == "action_available"
    summary = call_capability("investigation_report", {"session_json": json.dumps(created)})
    assert summary["summary"]["hypotheses"] == 2


def test_mcp_rejects_unexpected_arguments():
    with pytest.raises(ValueError, match="Unexpected"):
        call_capability("investigation_next", {"session_json": "{}", "run_shell": True})
