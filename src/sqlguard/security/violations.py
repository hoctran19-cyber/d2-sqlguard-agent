"""Fixed catalogue of gate violation codes shared with the agent loop and evaluation.

``repairable`` violations may be returned to the LLM as an observation for one more SQL attempt.
Policy violations are terminal so a model cannot probe the policy by retrying. ``error_class``
maps each code onto the proposal's error taxonomy; whether a denial is a *False Rejection* or a
correct block is decided by the evaluation label of the task, not by the gate.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ViolationInfo:
    reason: str
    repairable: bool
    error_class: str  # ast_parse_failure | unsupported_syntax | schema_error | policy_denial


_PARSE = "ast_parse_failure"
_UNSUPPORTED = "unsupported_syntax"
_SCHEMA = "schema_error"
_POLICY = "policy_denial"

VIOLATIONS: dict[str, ViolationInfo] = {
    # Input and parsing
    "empty_sql": ViolationInfo("SQL is empty", True, _PARSE),
    "sql_too_long": ViolationInfo("SQL exceeds the maximum length", False, _POLICY),
    "invalid_characters": ViolationInfo("SQL contains control characters", False, _POLICY),
    "parse_error": ViolationInfo("SQL could not be parsed", True, _PARSE),
    "multiple_statements": ViolationInfo("Exactly one SQL statement is required", False, _POLICY),
    "query_too_complex": ViolationInfo("Query is too complex", True, _UNSUPPORTED),
    "normalization_mismatch": ViolationInfo("Query could not be normalized", True, _PARSE),
    # Statement structure
    "not_select": ViolationInfo("Only read-only SELECT statements are permitted", False, _POLICY),
    "write_operation": ViolationInfo("Write or DDL operations are not permitted", False, _POLICY),
    "select_into": ViolationInfo("SELECT INTO is not permitted", False, _POLICY),
    "locking_clause": ViolationInfo("Locking clauses are not permitted", False, _POLICY),
    "set_operation": ViolationInfo("UNION/INTERSECT/EXCEPT are not supported", True, _UNSUPPORTED),
    "cte_not_supported": ViolationInfo("WITH/CTE is not supported", True, _UNSUPPORTED),
    "subquery_not_supported": ViolationInfo("Subqueries are not supported", True, _UNSUPPORTED),
    "window_not_supported": ViolationInfo("Window functions are not supported", True, _UNSUPPORTED),
    "unsupported_syntax": ViolationInfo("Query uses unsupported SQL syntax", True, _UNSUPPORTED),
    "function_not_allowed": ViolationInfo(
        "Query uses a function that is not allowed", False, _POLICY
    ),
    "cast_not_allowed": ViolationInfo(
        "Query casts to a type that is not allowed", True, _UNSUPPORTED
    ),
    "limit_invalid": ViolationInfo("LIMIT/OFFSET must be integer literals", True, _UNSUPPORTED),
    # Tables and joins
    "system_catalog": ViolationInfo("System catalogs are not permitted", False, _POLICY),
    "schema_not_allowed": ViolationInfo("Only the business schema is permitted", False, _POLICY),
    "table_unknown": ViolationInfo("Query references an unknown table", True, _SCHEMA),
    "table_not_allowed": ViolationInfo(
        "Query references a table this role may not read", False, _POLICY
    ),
    "join_not_allowed": ViolationInfo(
        "Only INNER/LEFT joins on declared foreign keys are permitted", True, _UNSUPPORTED
    ),
    # Columns
    "star_not_allowed": ViolationInfo("List columns explicitly instead of *", True, _UNSUPPORTED),
    "column_unknown": ViolationInfo("Query references an unknown column", True, _SCHEMA),
    "column_ambiguous": ViolationInfo("Query references an ambiguous column", True, _SCHEMA),
    "column_forbidden": ViolationInfo("Query uses a column this role may not read", False, _POLICY),
    "positional_reference": ViolationInfo(
        "Positional GROUP BY/ORDER BY cannot be combined with removed columns", False, _POLICY
    ),
    # Context
    "unknown_role": ViolationInfo("The caller role is not recognized", False, _POLICY),
    "gate_error": ViolationInfo("The security gate failed", False, _POLICY),
}

# Most severe first; the first matching code decides the reported reason.
SEVERITY_ORDER: tuple[str, ...] = tuple(VIOLATIONS)
_SEVERITY_INDEX = {code: index for index, code in enumerate(SEVERITY_ORDER)}


def by_severity(codes: set[str] | tuple[str, ...]) -> tuple[str, ...]:
    policy_first = sorted(
        set(codes),
        key=lambda code: (VIOLATIONS[code].repairable, _SEVERITY_INDEX[code]),
    )
    return tuple(policy_first)


def is_repairable(codes: tuple[str, ...]) -> bool:
    return bool(codes) and all(VIOLATIONS[code].repairable for code in codes)
