"""Generate, approve, revoke, and validate review-required scenarios."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _write(data: dict[str, Any], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def generate_scenarios(
    knowledge_path: str | Path, output: str | Path
) -> dict[str, object]:
    knowledge = json.loads(Path(knowledge_path).read_text(encoding="utf-8"))
    if (
        not isinstance(knowledge, dict)
        or knowledge.get("kind") != "agentsec-knowledge-reference"
        or knowledge.get("trust") != "UNTRUSTED_REFERENCE_ONLY"
    ):
        raise ValueError("Input is not a valid untrusted AgentSec knowledge record")
    rows = []
    for candidate in knowledge.get("candidate_mappings", []):
        if not isinstance(candidate, dict) or not isinstance(candidate.get("candidate_id"), str):
            raise ValueError("Knowledge candidate mapping is malformed")
        candidate_id = candidate["candidate_id"]
        rows.append({
            "id": candidate_id,
            "name": candidate_id.replace("-", " ").title(),
            "source": {
                "uri": knowledge.get("source"),
                "sha256": knowledge.get("sha256"),
                "candidate_terms": candidate.get("matched_terms", []),
            },
            "objective": f"Review whether the authorized system is resilient to {candidate_id}.",
            "checks": [
                "define_safe_test",
                "verify_control",
                "capture_evidence",
                "confirm_no_unauthorized_side_effect",
            ],
            "expected": (
                "Safe behavior consistent with the approved policy; "
                "no unauthorized side effects."
            ),
            "status": "draft",
            "human_approval": False,
            "execution_mode": "manual_or_synthetic_only",
        })
    doc: dict[str, Any] = {
        "schema_version": "1.2",
        "kind": "agentsec-scenario-pack",
        "source_sha256": knowledge.get("sha256"),
        "trust": "UNTRUSTED_DRAFTS",
        "scenarios": rows,
        "notice": (
            "Generated scenarios are drafts. Review and approve individually; "
            "import does not authorize execution."
        ),
    }
    _write(doc, output)
    return doc


def set_scenario_approval(
    path: str | Path, scenario_ids: list[str], *, approved: bool
) -> dict[str, Any]:
    if not scenario_ids:
        raise ValueError("At least one --id must be supplied")
    if any(not isinstance(scenario_id, str) or not scenario_id for scenario_id in scenario_ids):
        raise ValueError("Scenario IDs must be non-empty strings")
    if len(scenario_ids) != len(set(scenario_ids)):
        raise ValueError("Duplicate scenario IDs were supplied")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("kind") != "agentsec-scenario-pack":
        raise ValueError("Input is not an AgentSec scenario pack")
    initial_validation = _validate_scenario_data(data)
    if not initial_validation["valid"]:
        raise ValueError("Scenario pack is invalid: " + "; ".join(initial_validation["errors"]))
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("Scenario pack has no valid scenarios list")
    by_id: dict[str, dict[str, Any]] = {}
    for row in scenarios:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise ValueError("Scenario pack contains malformed scenario IDs")
        if row["id"] in by_id:
            raise ValueError("Scenario pack contains duplicate scenario IDs")
        by_id[row["id"]] = row
    unknown = sorted(set(scenario_ids) - set(by_id))
    if unknown:
        raise ValueError("Unknown scenario ID(s): " + ", ".join(unknown))
    for scenario_id in scenario_ids:
        row = by_id[scenario_id]
        row["status"] = "approved" if approved else "draft"
        row["human_approval"] = approved
    final_validation = _validate_scenario_data(data)
    if not final_validation["valid"]:
        details = "; ".join(final_validation["errors"])
        raise ValueError(
            "Approval change would invalidate the scenario pack: " + details
        )
    _write(data, path)
    return data


def validate_scenarios(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return _validate_scenario_data(data)


def _validate_scenario_data(data: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(data, dict) or data.get("kind") != "agentsec-scenario-pack":
        return {
            "valid": False,
            "errors": ["kind must be agentsec-scenario-pack"],
            "scenario_count": 0,
            "executable_approved_count": 0,
            "note": "Validation is structural; it does not establish safety or authorization.",
        }
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list):
        scenarios = []
        errors.append("scenarios must be a list")
    ids: list[str] = []
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            errors.append(f"scenarios[{index}] must be an object")
            continue
        for field in ("id", "name", "objective", "checks", "source"):
            if not scenario.get(field):
                errors.append(f"scenarios[{index}] missing {field}")
        scenario_id = scenario.get("id")
        if isinstance(scenario_id, str):
            ids.append(scenario_id)
        else:
            errors.append(f"scenarios[{index}].id must be a string")
        status = scenario.get("status")
        approval = scenario.get("human_approval")
        if status not in ("draft", "approved"):
            errors.append(f"scenarios[{index}].status must be draft or approved")
        if not isinstance(approval, bool):
            errors.append(f"scenarios[{index}].human_approval must be a boolean")
        elif (status == "approved") != approval:
            errors.append(f"scenarios[{index}] approval status and human_approval must agree")
    if len(ids) != len(set(ids)):
        errors.append("scenario IDs must be unique")
    approved_count = sum(
        isinstance(row, dict)
        and row.get("status") == "approved"
        and row.get("human_approval") is True
        for row in scenarios
    )
    return {
        "valid": not errors,
        "errors": errors,
        "scenario_count": len(scenarios),
        "executable_approved_count": approved_count,
        "note": "Validation is structural; it does not establish safety or authorization.",
    }
