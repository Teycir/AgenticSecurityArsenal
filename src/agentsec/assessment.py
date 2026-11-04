"""Assessment manifests, deterministic evidence evaluation, and regression diffs."""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evaluations import run_evaluations
from .scenarios import validate_scenarios
from .scope import load_scope, require_target_in_scope


class AssessmentError(ValueError):
    """Raised when an assessment manifest is invalid, tampered with, or out of scope."""


def _canonical_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _write_json(value: dict[str, Any], output: str | Path) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _verify_assessment(assessment: dict[str, Any]) -> None:
    if assessment.get("kind") != "agentsec-assessment":
        raise AssessmentError("Invalid assessment manifest")
    integrity = assessment.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        raise AssessmentError("Assessment integrity metadata is missing or unsupported")
    expected = integrity.get("sha256")
    payload = {key: value for key, value in assessment.items() if key != "integrity"}
    if not isinstance(expected, str) or not hmac.compare_digest(expected, _canonical_hash(payload)):
        raise AssessmentError("Assessment integrity check failed; manifest may have been modified")
    selected = assessment.get("approved_scenarios")
    snapshots = assessment.get("scenario_snapshot")
    if not isinstance(selected, list) or not isinstance(snapshots, list):
        raise AssessmentError("Assessment scenario snapshot is malformed")
    snapshot_ids = [row.get("id") for row in snapshots if isinstance(row, dict)]
    if len(snapshot_ids) != len(snapshots) or snapshot_ids != selected:
        raise AssessmentError("Assessment scenario snapshot does not match approved scenario IDs")
    if any(
        row.get("status") != "approved" or row.get("human_approval") is not True
        for row in snapshots
    ):
        raise AssessmentError("Assessment snapshot contains a scenario without explicit approval")


def create_assessment(
    scenarios_path: str | Path,
    scope_path: str | Path,
    target: str,
    output: str | Path,
) -> dict[str, Any]:
    scenario_file = Path(scenarios_path)
    raw_pack = scenario_file.read_bytes()
    pack = json.loads(raw_pack)
    if not isinstance(pack, dict) or pack.get("kind") != "agentsec-scenario-pack":
        raise AssessmentError("Invalid scenario pack")
    validation = validate_scenarios(scenario_file)
    if not validation["valid"]:
        raise AssessmentError("Invalid scenario pack: " + "; ".join(validation["errors"]))
    scope_file = Path(scope_path)
    scope = load_scope(scope_file)
    require_target_in_scope(target, scope)
    approved = [
        dict(scenario) for scenario in pack.get("scenarios", [])
        if scenario.get("status") == "approved" and scenario.get("human_approval") is True
    ]
    doc: dict[str, Any] = {
        "schema_version": "1.2",
        "kind": "agentsec-assessment",
        "assessment_id": hashlib.sha256(
            (target + datetime.now(timezone.utc).isoformat()).encode()
        ).hexdigest()[:16],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scope_engagement": scope["engagement"],
        "scope_valid_until": scope["valid_until"],
        "scope_sha256": hashlib.sha256(scope_file.read_bytes()).hexdigest(),
        "scenario_pack": str(scenario_file.resolve()),
        "scenario_pack_sha256": hashlib.sha256(raw_pack).hexdigest(),
        "approved_scenarios": [scenario["id"] for scenario in approved],
        "scenario_snapshot": approved,
        "draft_scenarios_excluded": len(pack.get("scenarios", [])) - len(approved),
        "execution": "evidence-fixture-only",
        "status": "ready_for_evidence",
    }
    doc["integrity"] = {"algorithm": "sha256", "sha256": _canonical_hash(doc)}
    _write_json(doc, output)
    return doc


def run_assessment(
    assessment_path: str | Path,
    evidence_path: str | Path,
    output: str | Path,
) -> dict[str, Any]:
    assessment = json.loads(Path(assessment_path).read_text(encoding="utf-8"))
    evidence = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    if not isinstance(assessment, dict) or not isinstance(evidence, dict):
        raise AssessmentError("Assessment and evidence files must contain JSON objects")
    _verify_assessment(assessment)
    all_results = run_evaluations(evidence, None)
    known_results = {
        row["id"]: row for row in all_results["scenarios"]
    }
    report = dict(all_results)
    report["scenarios"] = []
    for snapshot in assessment["scenario_snapshot"]:
        scenario_id = snapshot["id"]
        if scenario_id in known_results:
            report["scenarios"].append(known_results[scenario_id])
        else:
            report["scenarios"].append({
                "id": scenario_id,
                "title": snapshot.get("name", scenario_id),
                "status": "inconclusive",
                "checks": [{
                    "check": "deterministic_evaluator_available",
                    "status": "inconclusive",
                }],
                "passed": 0,
                "failed": 0,
                "inconclusive": 1,
                "note": (
                    "No built-in deterministic evaluator is mapped to this scenario; "
                    "review manually and provide an appropriate evidence adapter."
                ),
            })
    report["assessment_id"] = assessment["assessment_id"]
    report["target"] = assessment["target"]
    report["execution_mode"] = "offline-evidence-fixture"
    report["assessment_integrity"] = assessment["integrity"]
    report["summary"] = {
        "scenarios_run": len(report["scenarios"]),
        "passed": sum(row["status"] == "pass" for row in report["scenarios"]),
        "failed": sum(row["status"] == "fail" for row in report["scenarios"]),
        "inconclusive": sum(row["status"] == "inconclusive" for row in report["scenarios"]),
    }
    report.setdefault("limitations", []).append(
        "Assessment run used supplied evidence fixtures only; target was not contacted."
    )
    _write_json(report, output)
    return report


def _load_status_map(path: str | Path) -> dict[str, str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("scenarios", []), list):
        raise AssessmentError(f"Invalid assessment result file: {path}")
    result: dict[str, str] = {}
    allowed = {"pass", "fail", "inconclusive"}
    for row in data.get("scenarios", []):
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise AssessmentError(f"Malformed scenario row in {path}")
        sid, status = row["id"], row.get("status")
        if sid in result:
            raise AssessmentError(f"Duplicate scenario ID {sid!r} in {path}")
        if status not in allowed:
            raise AssessmentError(f"Invalid status for scenario {sid!r} in {path}: {status!r}")
        result[sid] = status
    return result


def compare_assessments(
    baseline_path: str | Path,
    current_path: str | Path,
    output: str | Path,
) -> dict[str, Any]:
    baseline_map = _load_status_map(baseline_path)
    current_map = _load_status_map(current_path)
    rows: list[dict[str, str]] = []
    for sid in sorted(set(baseline_map) | set(current_map)):
        old = baseline_map.get(sid)
        new = current_map.get(sid)
        if old is None:
            change = "new"
        elif new is None:
            change = "removed"
        elif old == new:
            change = "unchanged"
        elif old == "fail" and new == "pass" or old == "inconclusive" and new == "pass":
            change = "improved"
        elif old == "pass" and new == "inconclusive":
            change = "degraded"
        elif new == "fail":
            change = "regressed"
        elif old == "fail" and new == "inconclusive":
            change = "degraded"
        else:
            change = "changed"
        rows.append({
            "scenario": sid,
            "baseline": old or "not-run",
            "current": new or "not-run",
            "change": change,
        })
    doc: dict[str, Any] = {
        "schema_version": "1.2",
        "kind": "agentsec-regression",
        "scenarios": rows,
        "summary": {
            key: sum(row["change"] == key for row in rows)
            for key in (
                "regressed", "improved", "degraded", "new",
                "removed", "changed", "unchanged",
            )
        },
    }
    _write_json(doc, output)
    return doc
