"""Assessment manifests, deterministic evidence evaluation, and regression diffs."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .evaluations import run_evaluations
from .scope import load_scope, require_target_in_scope


class AssessmentError(ValueError):
    """Raised when an assessment manifest is invalid or out of scope."""

def create_assessment(
    scenarios_path: str | Path,
    scope_path: str | Path,
    target: str,
    output: str | Path,
) -> dict[str, object]:
    pack = json.loads(Path(scenarios_path).read_text(encoding="utf-8"))
    if pack.get("kind") != "agentsec-scenario-pack":
        raise AssessmentError("Invalid scenario pack")
    scope = load_scope(scope_path)
    require_target_in_scope(target, scope)
    approved = [
        scenario
        for scenario in pack.get("scenarios", [])
        if scenario.get("status") == "approved" and scenario.get("human_approval") is True
    ]
    doc: dict[str, object] = {
        "schema_version": "1.0",
        "kind": "agentsec-assessment",
        "assessment_id": hashlib.sha256(
            (target + str(datetime.now(timezone.utc))).encode()
        ).hexdigest()[:16],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scope_engagement": scope["engagement"],
        "scope_valid_until": scope["valid_until"],
        "scenario_pack": str(Path(scenarios_path).resolve()),
        "approved_scenarios": [scenario["id"] for scenario in approved],
        "draft_scenarios_excluded": len(pack.get("scenarios", [])) - len(approved),
        "execution": "evidence-fixture-only",
        "status": "ready_for_evidence",
    }
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc


def run_assessment(
    assessment_path: str | Path,
    evidence_path: str | Path,
    output: str | Path,
) -> dict[str, object]:
    assessment = json.loads(Path(assessment_path).read_text(encoding="utf-8"))
    evidence = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    if assessment.get("kind") != "agentsec-assessment":
        raise AssessmentError("Invalid assessment manifest")
    selected = assessment.get("approved_scenarios", [])
    report = run_evaluations(evidence, None)
    report["assessment_id"] = assessment["assessment_id"]
    report["target"] = assessment["target"]
    report["execution_mode"] = "offline-evidence-fixture"
    if selected:
        report["scenarios"] = [
            row for row in report["scenarios"] if row["id"] in selected
        ]
    else:
        report["scenarios"] = []
        report["summary"] = {"scenarios_run": 0, "passed": 0, "failed": 0, "inconclusive": 0}
    report["summary"] = {
        key: sum(row["status"] == status for row in report["scenarios"])
        for key, status in [
            ("passed", "pass"),
            ("failed", "fail"),
            ("inconclusive", "inconclusive"),
        ]
    }
    report["summary"]["scenarios_run"] = len(report["scenarios"])
    report.setdefault("limitations", []).append(
        "Assessment run used supplied evidence fixtures only; target was not contacted."
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def compare_assessments(
    baseline_path: str | Path,
    current_path: str | Path,
    output: str | Path,
) -> dict[str, object]:
    baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    current = json.loads(Path(current_path).read_text(encoding="utf-8"))
    baseline_map = {
        str(row["id"]): str(row["status"])
        for row in baseline.get("scenarios", [])
    }
    current_map = {
        str(row["id"]): str(row["status"])
        for row in current.get("scenarios", [])
    }
    rows: list[dict[str, object]] = []
    for sid in sorted(set(baseline_map) | set(current_map)):
        old = baseline_map.get(sid, "not-run")
        new = current_map.get(sid, "not-run")
        if old == "fail" and new == "pass":
            change = "improved"
        elif old == "pass" and new == "fail":
            change = "regressed"
        elif old == "not-run":
            change = "new"
        else:
            change = "unchanged"
        rows.append({
            "scenario": sid,
            "baseline": old,
            "current": new,
            "change": change,
        })
    doc: dict[str, object] = {
        "schema_version": "1.0",
        "kind": "agentsec-regression",
        "scenarios": rows,
        "summary": {
            "regressed": sum(row["change"] == "regressed" for row in rows),
            "improved": sum(row["change"] == "improved" for row in rows),
            "new": sum(row["change"] == "new" for row in rows),
        },
    }
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc
