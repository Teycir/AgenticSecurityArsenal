from agentsec.labs import list_scenarios, run_labs
from agentsec.sarif import to_sarif

def test_lab_catalog_has_five_scenarios():
    assert len(list_scenarios()) == 5

def test_all_labs_detect_expected_synthetic_findings():
    report = run_labs()
    assert report["summary"]["scenarios_run"] == 5
    assert report["summary"]["findings"] == 5
    assert {f["scenario"] for f in report["findings"]} == {
        "excessive-tool-permissions", "tenant-isolation", "confused-deputy",
        "tool-description-poisoning", "rag-memory-poisoning"}

def test_labs_are_local_and_use_synthetic_data_only():
    report = run_labs()
    assert report["network_access"] is False
    assert report["external_services"] is False
    assert report["synthetic_data_only"] is True

def test_single_scenario():
    report = run_labs("tenant-isolation")
    assert report["summary"]["scenarios_run"] == 1
    assert report["findings"][0]["id"] == "AGENTSEC-LAB-002"

def test_unknown_scenario_rejected():
    try: run_labs("not-a-lab")
    except ValueError as exc: assert "Unknown lab" in str(exc)
    else: raise AssertionError("unknown scenario accepted")

def test_lab_report_exports_to_sarif():
    sarif = to_sarif(run_labs())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 5
