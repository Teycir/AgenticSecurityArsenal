from agentsec.catalog import filter_catalog, load_catalog
from agentsec.planning import build_plan, render_plan_markdown


def test_catalog_entries_are_unique_and_structured():
    catalog = load_catalog()
    assert len(catalog) >= 30
    assert len({item["id"] for item in catalog}) == len(catalog)


def test_filter_by_domain_is_case_insensitive():
    catalog = load_catalog()
    domain = catalog[0]["domain"]
    filtered = filter_catalog(catalog, [domain.upper()])
    assert filtered
    assert all(item["domain"] == domain for item in filtered)


def test_plan_is_manual_and_contains_evidence_slots():
    scope = {"engagement": "lab", "authorized_by": "owner", "valid_until": "2099-01-01T00:00:00Z", "targets": [{"origin": "http://127.0.0.1:8000"}]}
    plan = build_plan(scope, load_catalog())
    assert plan["execution_mode"] == "manual-review-only"
    assert all(item["status"] == "not-tested" and item["evidence"] == [] for item in plan["techniques"])
    assert "No target" not in render_plan_markdown(plan)
