from __future__ import annotations

import json
from pathlib import Path

DEFAULT_CATALOG = Path(__file__).resolve().parents[2] / "catalog" / "techniques.json"
REQUIRED_FIELDS = {"id", "name", "domain", "class", "description", "safe_validation", "mitigation"}


def load_catalog(path: str | Path | None = None) -> list[dict]:
    catalog_path = Path(path) if path else DEFAULT_CATALOG
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Technique catalog must be a JSON array")
    seen: set[str] = set()
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Catalog entry {index} must be an object")
        missing = REQUIRED_FIELDS - item.keys()
        if missing:
            raise ValueError(f"Catalog entry {index} is missing: {', '.join(sorted(missing))}")
        technique_id = item["id"]
        if not isinstance(technique_id, str) or not technique_id.strip():
            raise ValueError(f"Catalog entry {index} has an invalid id")
        if technique_id in seen:
            raise ValueError(f"Duplicate technique id: {technique_id}")
        seen.add(technique_id)
    return data


def filter_catalog(items: list[dict], domains: list[str] | None = None, ids: list[str] | None = None) -> list[dict]:
    domain_set = {value.casefold() for value in (domains or [])}
    id_set = set(ids or [])
    return [item for item in items if (not domain_set or item["domain"].casefold() in domain_set) and (not id_set or item["id"] in id_set)]


def render_catalog(items: list[dict]) -> str:
    lines = ["ID       DOMAIN             TECHNIQUE", "-" * 78]
    for item in items:
        lines.append(f"{item['id']:<8} {item['domain'][:18]:<18} {item['name']}")
    return "\n".join(lines)
