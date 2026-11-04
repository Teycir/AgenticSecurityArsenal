from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def skills_root() -> Path:
    # Skill resources are packaged for installed CLI and MCP use.
    return Path(__file__).resolve().parent / "skillpacks"


def list_skills() -> list[dict[str, Any]]:
    root = skills_root()
    items = []
    if not root.exists():
        return items
    for metadata_path in sorted(root.glob("*/asa-skill.json")):
        item = json.loads(metadata_path.read_text(encoding="utf-8"))
        item["path"] = f"skills/{item['name']}"
        items.append(item)
    return items


def get_skill(name: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        raise ValueError("Skill name must be a lowercase kebab-case identifier")
    directory = skills_root() / name
    metadata_path, instruction_path = directory / "asa-skill.json", directory / "SKILL.md"
    if not metadata_path.is_file() or not instruction_path.is_file():
        raise ValueError(f"Unknown or incomplete skill: {name}")
    return {"metadata": json.loads(metadata_path.read_text(encoding="utf-8")),
            "instructions": instruction_path.read_text(encoding="utf-8")}


def validate_skills() -> dict[str, Any]:
    root = skills_root()
    errors: list[str] = []
    names: set[str] = set()
    checked = 0
    if not root.exists():
        return {"valid": False, "checked": 0, "errors": ["skills directory is missing"]}
    for meta_path in sorted(root.glob("*/asa-skill.json")):
        checked += 1
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            name = meta.get("name")
            if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
                errors.append(f"{meta_path}: invalid name")
                continue
            if name in names:
                errors.append(f"duplicate skill name: {name}")
            names.add(name)
            if meta_path.parent.name != name:
                errors.append(f"{meta_path}: directory/name mismatch")
            required = ("description", "version", "execution_mode", "permission_profile", "inputs", "outputs", "interfaces", "parallel_safety")
            for key in required:
                if key not in meta or meta[key] in (None, "", []):
                    errors.append(f"{meta_path}: missing {key}")
            skill_md = meta_path.parent / "SKILL.md"
            if not skill_md.is_file():
                errors.append(f"{meta_path}: SKILL.md missing")
            else:
                text = skill_md.read_text(encoding="utf-8")
                if not text.startswith("---\n") or "\nname: " + str(name) + "\n" not in text[:500]:
                    errors.append(f"{skill_md}: missing or mismatched Agent Skills frontmatter")
                if len(text) > 16000:
                    errors.append(f"{skill_md}: exceeds 16000 character guidance budget")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{meta_path}: {exc}")
    return {"valid": not errors, "checked": checked, "errors": errors, "names": sorted(names)}
