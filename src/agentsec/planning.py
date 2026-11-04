from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def build_plan(scope: dict, catalog: list[dict], domains: list[str] | None = None) -> dict:
    selected_domains = {value.casefold() for value in (domains or [])}
    techniques = [
        {
            "technique_id": item["id"],
            "name": item["name"],
            "domain": item["domain"],
            "objective": item["description"],
            "safe_validation": item["safe_validation"],
            "mitigation_reference": item["mitigation"],
            "status": "not-tested",
            "evidence": [],
            "notes": "",
        }
        for item in catalog
        if not selected_domains or item["domain"].casefold() in selected_domains
    ]
    return {
        "schema_version": "1.0",
        "engagement": scope["engagement"],
        "authorized_by": scope["authorized_by"],
        "valid_until": scope["valid_until"],
        "targets": scope["targets"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "execution_mode": "manual-review-only",
        "techniques": techniques,
        "summary": {"total": len(techniques), "not_tested": len(techniques), "passed": 0, "failed": 0, "inconclusive": 0, "not_applicable": 0},
    }


def write_plan(plan: dict, output: str | Path) -> None:
    Path(output).write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def render_plan_markdown(plan: dict) -> str:
    lines = [
        f"# Assessment plan: {plan['engagement']}",
        "",
        f"- Authorized by: {plan['authorized_by']}",
        f"- Authorization valid until: {plan['valid_until']}",
        f"- Generated: {plan['generated_at']}",
        "- Execution mode: manual review only; this file does not send network traffic.",
        "",
        "## Authorized origins",
    ]
    lines.extend(f"- `{item['origin']}` — {item.get('description', '')}" for item in plan["targets"])
    lines.extend(["", "## Test cases", "", "| ID | Domain | Technique | Status |", "|---|---|---|---|"])
    lines.extend(f"| {item['technique_id']} | {item['domain']} | {item['name']} | {item['status']} |" for item in plan["techniques"])
    lines.extend(["", "## Execution notes", "", "Use synthetic data and benign canaries. Record evidence and impact for each test. Stop if scope is ambiguous, unexpected real data is exposed, or service stability is affected.", ""])
    return "\n".join(lines)
