import pytest

from agentsec.evaluations import list_evaluations, run_evaluations


def test_list_evaluations():
    assert len(list_evaluations()) == 6

def test_missing_evidence_is_inconclusive():
    report = run_evaluations(scenario="prompt-injection")
    assert report["scenarios"][0]["status"] == "inconclusive"

def test_all_true_passes():
    report = run_evaluations(
        {"tool-authorization": {
            "unauthorized_tool_denied": True, "no_side_effect": True
        }},
        "tool-authorization",
    )
    assert report["summary"]["passed"] == 1

def test_false_evidence_fails_closed():
    report = run_evaluations(
        {"tenant-isolation": {
            "cross_tenant_access_denied": True, "no_data_leak": False
        }},
        "tenant-isolation",
    )
    assert report["scenarios"][0]["status"] == "fail"

def test_unknown_scenario_rejected():
    with pytest.raises(ValueError):
        run_evaluations(scenario="not-a-real-test")
