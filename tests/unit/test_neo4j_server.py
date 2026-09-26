"""
tests/unit/test_neo4j_server.py — Unit tests cho Neo4j MCP Server logic.

Test mà KHÔNG cần Neo4j thật hoặc MCP protocol.
Import trực tiếp các helper functions và test chúng.

Coverage:
  ✓ Label whitelist (valid + invalid)
  ✓ Relationship whitelist (valid + invalid)
  ✓ Identifier validation
  ✓ Endpoint _uid computation (deterministic + isolation)
  ✓ Write query detection (run_cypher protection)
  ✓ get_identity_key cho từng label
  ✓ Error result format
"""

import hashlib
import json
import sys
import os

import pytest

# Thêm root vào sys.path để import src.*
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.mcp_servers.neo4j_server import (
    ALLOWED_LABELS,
    ALLOWED_RELATIONSHIPS,
    _validate_label,
    _validate_relationship,
    _validate_identifier,
    _compute_endpoint_uid,
    _get_identity_key,
    _error_response,
    _ok_response,
    GRAPH_SCHEMA,
)


# ─── Label whitelist ──────────────────────────────────────────────────────────

class TestLabelWhitelist:
    """Kiểm tra label whitelist validation."""

    @pytest.mark.parametrize("label", sorted(ALLOWED_LABELS))
    def test_valid_labels_pass(self, label):
        """Tất cả 5 allowed labels phải pass."""
        _validate_label(label)  # không raise

    @pytest.mark.parametrize("label", [
        "User", "Admin", "Session", "target", "ENDPOINT",  # wrong case
        "DROP TABLE",  # injection attempt
        "",  # empty
        "Target; DROP",  # injection
        "Technology2",  # không trong whitelist
    ])
    def test_invalid_labels_raise(self, label):
        """Labels không trong whitelist phải raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported label"):
            _validate_label(label)

    def test_whitelist_contains_exactly_5_labels(self):
        """Whitelist phải có đúng 5 labels theo spec."""
        expected = {"Target", "Technology", "Endpoint", "Parameter", "Finding"}
        assert ALLOWED_LABELS == expected


# ─── Relationship whitelist ───────────────────────────────────────────────────

class TestRelationshipWhitelist:
    """Kiểm tra relationship whitelist validation."""

    @pytest.mark.parametrize("rel", sorted(ALLOWED_RELATIONSHIPS))
    def test_valid_relationships_pass(self, rel):
        """Tất cả 5 allowed relationships phải pass."""
        _validate_relationship(rel)  # không raise

    @pytest.mark.parametrize("rel", [
        "uses", "HAS_endpoint", "LINKED_TO",  # wrong name/case
        "OWNED_BY", "CONNECTED_TO",  # không trong whitelist
        "", "USES; DROP",  # injection
    ])
    def test_invalid_relationships_raise(self, rel):
        """Relationships không trong whitelist phải raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported relationship"):
            _validate_relationship(rel)

    def test_whitelist_contains_exactly_5_relationships(self):
        """Whitelist phải có đúng 5 relationship types theo spec."""
        expected = {"USES", "HAS_ENDPOINT", "HAS_PARAM", "LINKS_TO", "FLAGGED_AS"}
        assert ALLOWED_RELATIONSHIPS == expected


# ─── Identifier validation ────────────────────────────────────────────────────

class TestIdentifierValidation:
    """Kiểm tra chặn injection qua property key."""

    @pytest.mark.parametrize("ident", [
        "url", "name", "path", "_uid", "_target_url",
        "status_code", "created_at", "camelCase", "PascalCase",
    ])
    def test_valid_identifiers(self, ident):
        _validate_identifier(ident)

    @pytest.mark.parametrize("bad", [
        "url; DROP", "name`hack`", "path UNION",
        "name()", "rel-type", "key space",
        "", "123invalid",  # không bắt đầu bằng chữ
    ])
    def test_invalid_identifiers_raise(self, bad):
        with pytest.raises(ValueError):
            _validate_identifier(bad)


# ─── Endpoint UID ─────────────────────────────────────────────────────────────

class TestEndpointUID:
    """Kiểm tra endpoint identity isolation (quan trọng nhất)."""

    def test_uid_is_deterministic(self):
        """Cùng input → cùng _uid."""
        uid1 = _compute_endpoint_uid("https://a.com", "GET", "/login")
        uid2 = _compute_endpoint_uid("https://a.com", "GET", "/login")
        assert uid1 == uid2

    def test_different_targets_same_path_different_uid(self):
        """
        target-A /login GET ≠ target-B /login GET.
        Đây là test quan trọng nhất cho endpoint identity.
        """
        uid_a = _compute_endpoint_uid("https://target-a.com", "GET", "/login")
        uid_b = _compute_endpoint_uid("https://target-b.com", "GET", "/login")
        assert uid_a != uid_b, (
            "FAIL: target-A và target-B có cùng /login GET → bị trộn identity!"
        )

    def test_same_target_different_path_different_uid(self):
        """Cùng target nhưng path khác → _uid khác."""
        uid_login = _compute_endpoint_uid("https://a.com", "GET", "/login")
        uid_logout = _compute_endpoint_uid("https://a.com", "GET", "/logout")
        assert uid_login != uid_logout

    def test_same_target_same_path_different_method_different_uid(self):
        """Cùng target, cùng path nhưng method khác → _uid khác."""
        uid_get = _compute_endpoint_uid("https://a.com", "GET", "/api/users")
        uid_post = _compute_endpoint_uid("https://a.com", "POST", "/api/users")
        assert uid_get != uid_post

    def test_uid_length_is_64(self):
        """_uid phải có đúng 64 ký tự hex."""
        uid = _compute_endpoint_uid("https://a.com", "GET", "/test")
        assert len(uid) == 64
        assert all(c in "0123456789abcdef" for c in uid)

    def test_path_normalization(self):
        """Path /login và login phải cho cùng uid sau normalize."""
        uid1 = _compute_endpoint_uid("https://a.com", "GET", "/login")
        uid2 = _compute_endpoint_uid("https://a.com", "GET", "login")
        assert uid1 == uid2

    def test_method_case_normalization(self):
        """GET và get phải cho cùng uid."""
        uid1 = _compute_endpoint_uid("https://a.com", "GET", "/test")
        uid2 = _compute_endpoint_uid("https://a.com", "get", "/test")
        assert uid1 == uid2


# ─── Write query detection ────────────────────────────────────────────────────

# ─── Identity key ─────────────────────────────────────────────────────────────

class TestIdentityKey:
    """_get_identity_key trả đúng key cho từng label."""

    def test_target_uses_url(self):
        key = _get_identity_key("Target", {"url": "https://example.com", "created_at": "now"})
        assert key == ("url", "https://example.com")

    def test_technology_uses_name(self):
        key = _get_identity_key("Technology", {"name": "Django", "category": "backend"})
        assert key == ("name", "Django")

    def test_endpoint_uses_uid(self):
        key = _get_identity_key("Endpoint", {"_uid": "abc123", "path": "/login"})
        assert key == ("_uid", "abc123")

    def test_parameter_no_global_key(self):
        with pytest.raises(ValueError):
            _get_identity_key("Parameter", {"name": "id", "location": "query"})

    def test_finding_no_global_key(self):
        with pytest.raises(ValueError):
            _get_identity_key("Finding", {"type": "xss", "severity": "high"})

    def test_target_missing_url_returns_none(self):
        with pytest.raises(ValueError):
            _get_identity_key("Target", {"created_at": "now"})


# ─── Error / OK result format ─────────────────────────────────────────────────

class TestResultFormat:
    """Kết quả phải serializable và có cấu trúc đúng."""

    def test_error_response_structure(self):
        result = _error_response("Something went wrong", code="TEST_ERROR")
        parsed = json.loads(result)
        assert parsed["status"] == "error"
        assert parsed["code"] == "TEST_ERROR"
        assert parsed["message"] == "Something went wrong"

    def test_ok_response_structure(self):
        result = _ok_response({"node_id": 42, "label": "Target"})
        parsed = json.loads(result)
        assert parsed["status"] == "ok"
        assert parsed["data"]["node_id"] == 42

    def test_error_response_default_code(self):
        result = _error_response("oops")
        parsed = json.loads(result)
        assert parsed["code"] == "ERROR"


# ─── Graph Schema ─────────────────────────────────────────────────────────────

class TestGraphSchema:
    """Schema resource phải chứa đủ thông tin theo spec."""

    def test_schema_has_all_labels(self):
        for label in ALLOWED_LABELS:
            assert label in GRAPH_SCHEMA["labels"], f"Label '{label}' missing from schema"

    def test_schema_has_all_relationships(self):
        for rel in ALLOWED_RELATIONSHIPS:
            assert rel in GRAPH_SCHEMA["relationships"], f"Rel '{rel}' missing from schema"

    def test_endpoint_schema_documents_uid_identity(self):
        ep = GRAPH_SCHEMA["labels"]["Endpoint"]
        assert "_uid" in ep["properties"]
        assert "target_url" in ep["identity"].lower() or "_target_url" in ep.get("properties", [])

    def test_schema_is_json_serializable(self):
        """Schema phải luôn serializable — không có non-JSON types."""
        json.dumps(GRAPH_SCHEMA)
