"""Validate the provisional five-case manifest before any execution."""

import json
from pathlib import Path

DEFAULT_MANIFEST = Path(__file__).parent / "datasets" / "sales-bootstrap.json"
SCENARIOS = {"list_south", "deny_identity", "partial_phone", "read_note", "retry_payment"}
CATEGORIES = {"legitimate", "authorization", "mixed", "injection", "failure"}


def load_manifest(path=DEFAULT_MANIFEST):
    return validate_manifest(json.loads(Path(path).read_text(encoding="utf-8")))


def validate_manifest(document):
    """Validate an already-parsed manifest (file or web upload); return it unchanged."""
    if not isinstance(document, dict):
        raise ValueError("Manifest must be a JSON object")
    if document.get("schema_version") != 1 or document.get("mode") != "fixture_only":
        raise ValueError("Only schema_version=1, mode=fixture_only is supported")
    cases = document.get("tasks")
    if not isinstance(cases, list) or not cases:
        raise ValueError("tasks must be a nonempty list")
    ids = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Each task must be a JSON object")
        for field in ("id", "question", "role", "category", "fixture_scenario", "comparison"):
            if not isinstance(case.get(field), str) or not case[field].strip():
                raise ValueError(f"Missing or invalid task field: {field}")
        if case["id"] in ids:
            raise ValueError(f"Duplicate task ID: {case['id']}")
        ids.add(case["id"])
        if case["category"] not in CATEGORIES or case["fixture_scenario"] not in SCENARIOS:
            raise ValueError("Unsupported category or fixture scenario")
        if case["role"] not in {"sales", "finance", "operations"}:
            raise ValueError("Unsupported role")
        if case["comparison"] not in {"ordered_rows", "unordered_rows"}:
            raise ValueError("Unsupported comparator")
        expected = case.get("expected")
        if not isinstance(expected, dict):
            raise ValueError("expected must be an object")
        if expected.get("status") not in {"succeeded", "refused", "failed"}:
            raise ValueError("Unsupported expected status")
        if expected.get("disposition") not in {"full", "partial", "refused", "error"}:
            raise ValueError("Unsupported disposition")
        for field in ("columns", "rows", "omitted_fields"):
            if not isinstance(expected.get(field), list):
                raise ValueError(f"Expected {field} must be a list")
        if any(not isinstance(c, str) for c in expected["columns"] + expected["omitted_fields"]):
            raise ValueError("Column and omission names must be strings")
        if len(set(expected["columns"])) != len(expected["columns"]):
            raise ValueError("Duplicate expected columns")
        for row in expected["rows"]:
            if not isinstance(row, list) or len(row) != len(expected["columns"]):
                raise ValueError("Expected row width does not match columns")
            if any(isinstance(value, list | dict) for value in row):
                raise ValueError("Only scalar cells supported")
        if case["category"] == "injection" and not isinstance(case.get("attack_payload"), str):
            raise ValueError("Injection requires attack_payload")
    return document
