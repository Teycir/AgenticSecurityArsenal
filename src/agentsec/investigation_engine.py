"""Stateful, evidence-led investigation sessions for agent orchestration.

This module plans and tracks benign validation work. It does not exploit targets,
run arbitrary commands, or perform network access.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from agentsec.investigation import generate_hypotheses
from agentsec.scope import require_target_in_scope

OUTCOMES = {"observed", "not_observed", "inconclusive"}


def _canonical_id(value: Any, prefix: str) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return prefix + "-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _make_steps(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps = []
    for index, hypothesis in enumerate(hypotheses, 1):
        hid = hypothesis["hypothesis_id"]
        steps.append({
            "step_id": _canonical_id({"hypothesis": hid, "index": index}, "step"),
            "hypothesis_id": hid,
            "objective": "Review the cited observation and define a benign validation check.",
            "method": "manual_review_then_benign_check",
            "instructions": [
                "Verify the evidence belongs to the declared target and engagement.",
                "Inspect the original request, response, or scanner record.",
                "Choose a read-only validation check appropriate to the suspected issue.",
                "Do not attempt exploitation, access control bypass, data extraction, or state changes.",
                "Record the exact observation and limitations; otherwise mark inconclusive.",
            ],
            "status": "queued",
            "priority": "normal",
        })
    return steps


def _candidate_attack_paths(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Correlate observations sharing an explicit host/target; never infer exploitability."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for report in reports:
        source = str(report.get("source", "unknown"))
        for row in report.get("observations", []) if isinstance(report.get("observations"), list) else []:
            if not isinstance(row, dict):
                continue
            host = row.get("host") or row.get("target") or row.get("matched_at") or row.get("host_ip")
            if host:
                groups.setdefault(str(host).rstrip("/"), []).append({"source": source, "observation": row})
    paths = []
    for host, nodes in sorted(groups.items()):
        if len(nodes) < 2:
            continue
        paths.append({
            "path_id": _canonical_id({"host": host, "nodes": nodes}, "path"),
            "target_context": host,
            "nodes": nodes,
            "relationship": "shared_target_context_only",
            "confidence": "low",
            "status": "candidate_only",
            "limitation": "Shared target context is not proof of a causal attack path or chained exploitability.",
        })
    return paths


def create_investigation(scope: dict[str, Any], target: str, reports: list[dict[str, Any]], title: str = "Security investigation") -> dict[str, Any]:
    if not isinstance(reports, list) or not all(isinstance(item, dict) for item in reports):
        raise ValueError("reports must be an array of report objects")
    require_target_in_scope(target, scope)
    hypotheses_doc = generate_hypotheses(*reports)
    hypotheses = hypotheses_doc["hypotheses"]
    now = datetime.now(timezone.utc).isoformat()
    session = {
        "schema_version": "1.0",
        "engine_version": "1.5.0",
        "session_id": _canonical_id({"target": target, "title": title, "created_at": now}, "inv"),
        "title": title,
        "target": target,
        "engagement": scope.get("engagement"),
        "scope_checked": True,
        "created_at": now,
        "status": "in_progress" if hypotheses else "needs_input",
        "hypotheses": hypotheses,
        "steps": _make_steps(hypotheses),
        "candidate_attack_paths": _candidate_attack_paths(reports),
        "evidence_log": [],
        "decision_log": [],
        "safety": {
            "network_access_during_session_creation": False,
            "automatic_exploitation": False,
            "arbitrary_command_execution": False,
            "high_impact_actions": "not_supported; require separate human-controlled tooling and authorization",
        },
        "limitations": [
            "Hypotheses are unverified and generated from supplied evidence only.",
            "Candidate paths correlate shared target context; they do not establish causality.",
            "The engine plans and records checks; it does not execute validation steps.",
        ],
    }
    return session


def next_action(session: dict[str, Any]) -> dict[str, Any]:
    _validate_session(session)
    for step in session["steps"]:
        if step["status"] == "queued":
            return {"status": "action_available", "session_id": session["session_id"],
                    "next_action": step, "network_access": False}
    return {"status": "no_queued_actions", "session_id": session["session_id"],
            "next_action": None, "network_access": False,
            "hint": "Add further evidence or close the investigation; no checks are executed automatically."}


def record_result(session: dict[str, Any], step_id: str, outcome: str, note: str, evidence: Any = None) -> dict[str, Any]:
    _validate_session(session)
    if outcome not in OUTCOMES:
        raise ValueError("outcome must be observed, not_observed, or inconclusive")
    if not isinstance(note, str) or not note.strip():
        raise ValueError("note must be a non-empty string")
    step = next((item for item in session["steps"] if item["step_id"] == step_id), None)
    if step is None:
        raise ValueError(f"Unknown step_id: {step_id}")
    if step["status"] != "queued":
        raise ValueError("This step already has a recorded result; duplicate recording is refused")
    entry = {"step_id": step_id, "hypothesis_id": step["hypothesis_id"],
             "outcome": outcome, "note": note.strip(), "evidence": evidence,
             "recorded_at": datetime.now(timezone.utc).isoformat(),
             "source": "agent_or_operator_supplied"}
    step["status"] = "recorded"
    step["outcome"] = outcome
    session["evidence_log"].append(entry)
    session["decision_log"].append({"step_id": step_id, "decision": {
        "observed": "retain_as_observation_not_confirmation",
        "not_observed": "hypothesis_not_reproduced_in_this_check",
        "inconclusive": "collect_better_evidence_or_refine_check",
    }[outcome]})
    if all(item["status"] != "queued" for item in session["steps"]):
        session["status"] = "review_required"
    return session


def investigation_report(session: dict[str, Any]) -> dict[str, Any]:
    _validate_session(session)
    counts = {outcome: sum(1 for item in session["evidence_log"] if item["outcome"] == outcome)
              for outcome in sorted(OUTCOMES)}
    return {
        "schema_version": "1.0", "session_id": session["session_id"],
        "title": session["title"], "target": session["target"],
        "status": session["status"],
        "summary": {"hypotheses": len(session["hypotheses"]), "steps": len(session["steps"]),
                    "steps_remaining": sum(1 for step in session["steps"] if step["status"] == "queued"),
                    "candidate_attack_paths": len(session["candidate_attack_paths"]),
                    "recorded_outcomes": counts},
        "hypotheses": session["hypotheses"],
        "candidate_attack_paths": session["candidate_attack_paths"],
        "steps": session["steps"], "evidence_log": session["evidence_log"],
        "decision_log": session["decision_log"],
        "conclusion": "No vulnerability is marked confirmed by this workflow. Human review and independent reproduction are required.",
        "safety": session["safety"], "limitations": session["limitations"],
    }


def _validate_session(session: dict[str, Any]) -> None:
    if not isinstance(session, dict) or session.get("schema_version") != "1.0":
        raise ValueError("Invalid investigation session")
    for key in ("session_id", "target", "hypotheses", "steps", "evidence_log", "decision_log"):
        if key not in session:
            raise ValueError(f"Investigation session missing {key}")
    if not isinstance(session["steps"], list) or not isinstance(session["evidence_log"], list):
        raise ValueError("Investigation session collections are malformed")
