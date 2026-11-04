import json

import pytest

from agentsec.assessment import (
    AssessmentError,
    compare_assessments,
    create_assessment,
    run_assessment,
)
from agentsec.knowledge import extract_knowledge
from agentsec.scenarios import (
    generate_scenarios,
    set_scenario_approval,
    validate_scenarios,
)


def _scenario_pack(tmp_path):
    source = tmp_path / "reference.md"
    source.write_text("# Prompt injection and SSRF")
    knowledge = tmp_path / "knowledge.json"
    extract_knowledge(str(source), knowledge)
    pack_path = tmp_path / "scenarios.json"
    pack = generate_scenarios(knowledge, pack_path)
    return pack_path, pack


def _scope(tmp_path):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps({
        "engagement": "unit-test",
        "authorized_by": "test owner",
        "valid_until": "2099-01-01T00:00:00Z",
        "targets": [{"origin": "https://localhost:8443"}],
    }))
    return scope_path


def test_explicit_scenario_approval_and_revocation(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    first_id = pack["scenarios"][0]["id"]
    set_scenario_approval(pack_path, [first_id], approved=True)
    assert validate_scenarios(pack_path)["executable_approved_count"] == 1
    set_scenario_approval(pack_path, [first_id], approved=False)
    assert validate_scenarios(pack_path)["executable_approved_count"] == 0


def test_approval_rejects_unknown_and_duplicate_ids(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    with pytest.raises(ValueError, match="Unknown"):
        set_scenario_approval(pack_path, ["not-a-scenario"], approved=True)
    pack["scenarios"].append(dict(pack["scenarios"][0]))
    pack_path.write_text(json.dumps(pack))
    with pytest.raises(ValueError, match="unique"):
        set_scenario_approval(pack_path, [pack["scenarios"][0]["id"]], approved=True)


def test_validation_rejects_approval_flag_mismatch(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    pack["scenarios"][0]["status"] = "approved"
    pack["scenarios"][0]["human_approval"] = False
    pack_path.write_text(json.dumps(pack))
    report = validate_scenarios(pack_path)
    assert not report["valid"]
    assert any("must agree" in error for error in report["errors"])


def test_assessment_contains_approved_snapshot_and_integrity(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    chosen = pack["scenarios"][0]["id"]
    set_scenario_approval(pack_path, [chosen], approved=True)
    assessment_path = tmp_path / "assessment.json"
    assessment = create_assessment(
        pack_path, _scope(tmp_path), "https://localhost:8443/api", assessment_path
    )
    assert assessment["approved_scenarios"] == [chosen]
    assert assessment["scenario_snapshot"][0]["id"] == chosen
    assert assessment["scenario_pack_sha256"]
    assert assessment["scope_sha256"]
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps({
        "prompt-injection": {
            "policy_preserved": True,
            "untrusted_instruction_ignored": True,
        }
    }))
    report = run_assessment(assessment_path, evidence_path, tmp_path / "result.json")
    assert report["summary"]["scenarios_run"] == 1
    assert report["scenarios"][0]["id"] == chosen


def test_assessment_detects_tampered_snapshot(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    set_scenario_approval(pack_path, [pack["scenarios"][0]["id"]], approved=True)
    assessment_path = tmp_path / "assessment.json"
    create_assessment(pack_path, _scope(tmp_path), "https://localhost:8443", assessment_path)
    doc = json.loads(assessment_path.read_text())
    doc["scenario_snapshot"][0]["objective"] = "tampered"
    assessment_path.write_text(json.dumps(doc))
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}")
    with pytest.raises(AssessmentError, match="integrity"):
        run_assessment(assessment_path, evidence, tmp_path / "result.json")


def test_regression_diff_classifies_all_status_transitions(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps({"scenarios": [
        {"id": "a", "status": "fail"},
        {"id": "b", "status": "pass"},
        {"id": "c", "status": "inconclusive"},
        {"id": "d", "status": "pass"},
        {"id": "e", "status": "fail"},
        {"id": "f", "status": "pass"},
    ]}))
    current.write_text(json.dumps({"scenarios": [
        {"id": "a", "status": "pass"},
        {"id": "b", "status": "fail"},
        {"id": "c", "status": "pass"},
        {"id": "d", "status": "inconclusive"},
        {"id": "e", "status": "inconclusive"},
        {"id": "g", "status": "pass"},
    ]}))
    report = compare_assessments(baseline, current, tmp_path / "diff.json")
    changes = {row["scenario"]: row["change"] for row in report["scenarios"]}
    assert changes == {
        "a": "improved",
        "b": "regressed",
        "c": "improved",
        "d": "degraded",
        "e": "degraded",
        "f": "removed",
        "g": "new",
    }
    assert report["summary"]["regressed"] == 1
    assert report["summary"]["removed"] == 1


def test_regression_diff_rejects_duplicate_ids(tmp_path):
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    baseline.write_text(json.dumps({"scenarios": [
        {"id": "x", "status": "pass"}, {"id": "x", "status": "fail"}
    ]}))
    current.write_text(json.dumps({"scenarios": []}))
    with pytest.raises(AssessmentError, match="Duplicate"):
        compare_assessments(baseline, current, tmp_path / "diff.json")


def test_assessment_rejects_missing_integrity_metadata(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    set_scenario_approval(pack_path, [pack["scenarios"][0]["id"]], approved=True)
    assessment_path = tmp_path / "assessment.json"
    create_assessment(pack_path, _scope(tmp_path), "https://localhost:8443", assessment_path)
    doc = json.loads(assessment_path.read_text())
    doc.pop("integrity")
    assessment_path.write_text(json.dumps(doc))
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}")
    with pytest.raises(AssessmentError, match="integrity metadata"):
        run_assessment(assessment_path, evidence, tmp_path / "result.json")


def test_cli_scenario_approve_and_revoke(tmp_path, monkeypatch, capsys):
    from agentsec.cli import main

    pack_path, pack = _scenario_pack(tmp_path)
    scenario_id = pack["scenarios"][0]["id"]
    monkeypatch.setattr(
        "sys.argv", ["agentsec", "scenario", "approve", str(pack_path), "--id", scenario_id]
    )
    assert main() == 0
    assert "Approved 1 scenario" in capsys.readouterr().out
    monkeypatch.setattr(
        "sys.argv", ["agentsec", "scenario", "revoke", str(pack_path), "--id", scenario_id]
    )
    assert main() == 0
    assert "Revoked 1 scenario" in capsys.readouterr().out


def test_approval_does_not_write_invalid_pack(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    pack["scenarios"][0]["name"] = ""
    original = json.dumps(pack)
    pack_path.write_text(original)
    with pytest.raises(ValueError, match="Scenario pack is invalid"):
        set_scenario_approval(pack_path, [pack["scenarios"][0]["id"]], approved=True)
    assert pack_path.read_text() == original


def test_approved_scenario_without_builtin_evaluator_is_inconclusive(tmp_path):
    pack_path, pack = _scenario_pack(tmp_path)
    scenario_ids = [row["id"] for row in pack["scenarios"]]
    assert "ssrf" in scenario_ids
    set_scenario_approval(pack_path, scenario_ids, approved=True)
    assessment_path = tmp_path / "assessment.json"
    create_assessment(pack_path, _scope(tmp_path), "https://localhost:8443", assessment_path)
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({
        "prompt-injection": {
            "policy_preserved": True,
            "untrusted_instruction_ignored": True,
        }
    }))
    report = run_assessment(assessment_path, evidence, tmp_path / "result.json")
    rows = {row["id"]: row for row in report["scenarios"]}
    assert rows["prompt-injection"]["status"] == "pass"
    assert rows["ssrf"]["status"] == "inconclusive"
    assert report["summary"]["scenarios_run"] == len(scenario_ids)
