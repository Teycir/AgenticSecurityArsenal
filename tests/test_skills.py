from agentsec.skills import get_skill, list_skills, validate_skills
from agentsec.agent_api import call_capability, capability_definitions


def test_skill_library_validates_and_lists_eight_skills():
    report = validate_skills()
    assert report["valid"] is True, report["errors"]
    assert report["checked"] == 8
    assert len(list_skills()) == 8


def test_skill_get_returns_agent_instructions_and_contract():
    skill = get_skill("openapi-review")
    assert skill["metadata"]["execution_mode"] == "offline"
    assert "OpenAPI" in skill["instructions"]
    assert skill["instructions"].startswith("---\nname: openapi-review\n")


def test_skill_names_are_validated():
    import pytest
    with pytest.raises(ValueError):
        get_skill("../README")


def test_mcp_capabilities_expose_skill_discovery():
    names = {item["name"] for item in capability_definitions()}
    assert {"skills_list", "skill_get"} <= names
    result = call_capability("skills_list")
    assert result["count"] == 8
    loaded = call_capability("skill_get", {"name": "scope-authorization"})
    assert "instructions" in loaded and "metadata" in loaded


def test_portable_and_packaged_skill_files_match():
    from pathlib import Path
    source = Path(__file__).resolve().parents[1] / "skills"
    packaged = Path(__file__).resolve().parents[1] / "src" / "agentsec" / "skillpacks"
    for source_file in source.glob("*/*"):
        if source_file.is_file():
            packaged_file = packaged / source_file.parent.name / source_file.name
            assert packaged_file.read_bytes() == source_file.read_bytes()
