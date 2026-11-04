import json
from datetime import datetime, timedelta, timezone

import pytest

from agentsec.scope import ScopeError, load_scope, require_target_in_scope, target_is_allowed


def write_scope(tmp_path, origin="http://127.0.0.1:8000", expiry=None):
    expiry = expiry or (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"engagement": "test", "authorized_by": "test owner", "valid_until": expiry, "targets": [{"origin": origin}]}))
    return p


def test_allows_exact_declared_origin_and_paths(tmp_path):
    scope = load_scope(write_scope(tmp_path))
    require_target_in_scope("http://127.0.0.1:8000/api/v1", scope)


def test_origin_matching_normalizes_host_case_and_default_port(tmp_path):
    scope = load_scope(write_scope(tmp_path, "HTTPS://Example.COM:443"))
    assert target_is_allowed("https://example.com/health", scope)


def test_rejects_undeclared_port(tmp_path):
    scope = load_scope(write_scope(tmp_path))
    with pytest.raises(ScopeError):
        require_target_in_scope("http://127.0.0.1:9000/", scope)


def test_rejects_expired_scope(tmp_path):
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with pytest.raises(ScopeError):
        load_scope(write_scope(tmp_path, expiry=expired))


@pytest.mark.parametrize("target", ["file:///etc/passwd", "http://user:pass@example.com", "http://example.com:bad", "https://example.com/?x=1#frag"])
def test_rejects_invalid_target_forms(tmp_path, target):
    scope = load_scope(write_scope(tmp_path, "https://example.com"))
    assert not target_is_allowed(target, scope)


def test_rejects_wildcard_scope(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(write_scope(tmp_path, "https://*.example.com"))


def test_rejects_scope_target_with_path(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(write_scope(tmp_path, "https://example.com/api"))
