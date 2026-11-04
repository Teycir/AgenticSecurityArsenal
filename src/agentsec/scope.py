from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when an authorization manifest is invalid or insufficient."""


class MCPHTTPError(RuntimeError):
    """Raised when a remote MCP endpoint is not authorized for inspection."""


def _origin(value: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.query or parsed.fragment:
            return None
        scheme = parsed.scheme.lower()
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port
    except (ValueError, UnicodeError):
        return None


def load_scope(path: str | Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScopeError(f"Invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeError("Scope manifest must be a JSON object")
    required = {"engagement", "authorized_by", "valid_until", "targets"}
    missing = required - data.keys()
    if missing:
        raise ScopeError(f"Missing required scope fields: {', '.join(sorted(missing))}")
    for field in ("engagement", "authorized_by", "valid_until"):
        if not isinstance(data[field], str) or not data[field].strip():
            raise ScopeError(f"{field} must be a non-empty string")
    try:
        expiry = datetime.fromisoformat(data["valid_until"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ScopeError("valid_until must be an ISO-8601 timestamp") from exc
    if expiry.tzinfo is None:
        raise ScopeError("valid_until must include a timezone")
    if expiry <= datetime.now(timezone.utc):
        raise ScopeError("Authorization has expired")
    if not isinstance(data["targets"], list) or not data["targets"]:
        raise ScopeError("targets must be a non-empty array")
    for index, target in enumerate(data["targets"]):
        if not isinstance(target, dict) or not isinstance(target.get("origin"), str):
            raise ScopeError(f"targets[{index}].origin must be a URL origin")
        parsed = urlsplit(target["origin"])
        normalized = _origin(target["origin"])
        if normalized is None or parsed.path not in {"", "/"}:
            raise ScopeError(f"targets[{index}].origin must be an exact HTTP(S) origin")
        if "*" in target["origin"]:
            raise ScopeError("Wildcard origins are not supported; declare each origin explicitly")
    return data


def target_is_allowed(target: str, scope: dict) -> bool:
    requested = _origin(target)
    if requested is None:
        return False
    return any(
        isinstance(entry, dict) and _origin(entry.get("origin", "")) == requested
        for entry in scope.get("targets", [])
    )


def require_target_in_scope(target: str, scope: dict) -> None:
    if not target_is_allowed(target, scope):
        raise ScopeError(f"Target origin is not explicitly authorized: {target}")
