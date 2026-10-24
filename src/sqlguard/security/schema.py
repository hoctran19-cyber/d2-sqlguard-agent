"""Role-filtered schema for the ``get_schema`` tool.

The schema comes from the reviewed policy file, never from free-form database comments, and
lists only tables and columns the caller's role may read: withheld columns are absent, not
marked, so the model cannot be steered toward them. Relevance narrowing is a simple keyword
match; the agent owner may replace the ranking as long as the role filter is applied first.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from sqlguard.mcp.tools import ToolError
from sqlguard.security.gate import SecurityContext
from sqlguard.security.policy import DIMENSION, KEY, MEASURE, RolePolicy, load_default_policy

SQL_SUBSET_RULES = (
    "One read-only SELECT statement only; no INSERT/UPDATE/DELETE/DDL, no SELECT INTO.",
    "List columns explicitly; * is only allowed inside COUNT(*).",
    "JOIN only with INNER JOIN or LEFT JOIN ... ON a listed join condition; ON holds only the "
    "join condition, every other condition goes in WHERE.",
    "No WITH/CTE, subqueries, UNION/INTERSECT/EXCEPT or window functions.",
    "Use only the listed tables, columns and functions.",
    "LIMIT and OFFSET must be integer literals; at most {max_rows} rows are returned.",
)
_DATE_RULES = {
    "postgres": (
        "Use half-open date ranges: <date column> >= DATE '2026-09-01' AND "
        "<date column> < DATE '2026-10-01'."
    ),
    "sqlite": (
        "Dates are TEXT 'YYYY-MM-DD'. Use half-open ranges such as <date column> >= "
        "'1997-01-01' AND <date column> < '1998-01-01'; group by month or year with "
        "strftime('%Y-%m', <date column>) or strftime('%Y', <date column>)."
    ),
}
_DIALECT_NAMES = {"postgresql": "PostgreSQL", "sqlite": "SQLite"}
AGGREGATE_ONLY_RULES = (
    "This role receives aggregate results only: every selected value is an aggregate "
    "(COUNT, SUM, AVG, MIN, MAX) or a dimension that is also in GROUP BY.",
    "[key] columns may only appear in JOIN conditions and as COUNT(<key>) or "
    "COUNT(DISTINCT <key>); never select, group, filter or order by them.",
    "[measure] columns may only appear inside an aggregate function, also in WHERE/HAVING.",
    "[dimension] columns may be selected when grouped, and used to filter and order.",
)
_KIND_LABELS = {KEY: "key", DIMENSION: "dimension", MEASURE: "measure"}
_MIN_TOKEN = 3
# Frequent question words that would otherwise match almost every description.
_STOPWORDS = frozenset(
    "cua cac cho nao bao nhieu hang nhung trong theo voi danh sach liet nhat moi "
    "the and for with what how many which from all".split()
)


def schema_for_role(policy: RolePolicy, role: str, query: str | None = None) -> dict[str, Any]:
    role = role.casefold()
    if not policy.has_role(role):
        raise ValueError("Unknown role")
    permitted = sorted(policy.allowed_tables(role))
    selected = _relevant_tables(policy, role, permitted, query) if query else permitted
    tables = []
    for table in selected:
        notes = policy.descriptions.get(table, {})
        columns = []
        for column in sorted(policy.allowed_columns(role, table)):
            entry = {"name": column, "description": notes.get(column, "")}
            kind = policy.column_kind(role, table, column)
            if kind is not None:
                entry["kind"] = _KIND_LABELS[kind]
            columns.append(entry)
        tables.append({"name": table, "description": notes.get("_table", ""), "columns": columns})
    joins = sorted(
        " = ".join(f"{t}.{c}" for t, c in sorted(pair))
        for pair in policy.foreign_keys
        if all(t in selected and policy.can_read(role, t, c) for t, c in pair)
    )
    rules = [rule.format(max_rows=policy.limits.max_rows) for rule in SQL_SUBSET_RULES]
    rules.append(_DATE_RULES[policy.dialect])
    if policy.is_aggregate_only(role):
        rules.extend(AGGREGATE_ONLY_RULES)
        if policy.limits.min_group_size > 0:
            rules.append(
                f"Groups covering fewer than {policy.limits.min_group_size} clients or accounts "
                "are withheld from results. If the question asks for individual rows, say that "
                "this role only receives aggregates instead of splitting groups until they "
                "describe one client or account."
            )
    return {
        "policy_version": policy.version,
        "role": role,
        "dialect": "postgresql" if policy.dialect == "postgres" else policy.dialect,
        "tables": tables,
        "joins": joins,
        "functions": sorted(policy.functions),
        "max_rows": policy.limits.max_rows,
        "rules": rules,
    }


def dialect_name(schema: dict[str, Any]) -> str:
    return _DIALECT_NAMES[schema["dialect"]]


def render_schema(schema: dict[str, Any]) -> str:
    """Compact text form for the system/context prompt."""
    lines = [
        f"Schema for role {schema['role']} ({dialect_name(schema)}, "
        f"policy {schema['policy_version']}):"
    ]
    for table in schema["tables"]:
        lines.append(f"- {table['name']}: {table['description']}".rstrip(": "))
        for column in table["columns"]:
            kind = f" [{column['kind']}]" if column.get("kind") else ""
            suffix = f" -- {column['description']}" if column["description"] else ""
            lines.append(f"    {column['name']}{kind}{suffix}")
    if schema["joins"]:
        lines.append("Join conditions: " + "; ".join(schema["joins"]))
    lines.append("Functions: " + ", ".join(schema["functions"]))
    lines.append("Rules:")
    lines.extend(f"  - {rule}" for rule in schema["rules"])
    return "\n".join(lines)


class SchemaTool:
    """``get_schema`` tool bound to the run's trusted context; the model only sends ``query``."""

    name = "get_schema"

    def __init__(self, context: SecurityContext, policy: RolePolicy | None = None) -> None:
        self._context = context
        self._policy = policy or load_default_policy()

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {"query": {"type": "string", "maxLength": 1000}},
        }

    @property
    def output_schema(self) -> dict[str, Any]:
        return {"type": "object", "required": ["tables", "joins", "rules"]}

    async def call(self, arguments: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
        del timeout_seconds
        query = arguments.get("query") if isinstance(arguments, dict) else None
        if (
            not isinstance(arguments, dict)
            or not set(arguments) <= {"query"}
            or (query is not None and not isinstance(query, str))
        ):
            raise ToolError(
                "Only an optional 'query' string is accepted",
                category="invalid_tool_input",
                retryable=False,
            )
        try:
            return schema_for_role(self._policy, self._context.role, query)
        except ValueError:
            raise ToolError("Unknown role", category="unknown_role", retryable=False) from None


def _relevant_tables(policy: RolePolicy, role: str, permitted: list[str], query: str) -> list[str]:
    wanted = _tokens(query)
    matched = set()
    for table in permitted:
        notes = policy.descriptions.get(table, {})
        words = _tokens(table) | _tokens(notes.get("_table", ""))
        for column in policy.allowed_columns(role, table):
            words |= _tokens(column) | _tokens(notes.get(column, ""))
        if wanted & words:
            matched.add(table)
    if not matched:
        return permitted
    # Add direct foreign-key neighbours so the model can still write the join.
    neighbours = {
        other
        for pair in policy.foreign_keys
        for (table, _), (other, _) in (tuple(pair), tuple(pair)[::-1])
        if table in matched and other in permitted
    }
    return sorted(matched | neighbours)


def _tokens(text: str) -> set[str]:
    stripped = "".join(
        char
        for char in unicodedata.normalize("NFD", text.casefold())
        if unicodedata.category(char) != "Mn"
    ).replace("đ", "d")
    return {
        token
        for token in re.split(r"[^a-z0-9]+", stripped)
        if len(token) >= _MIN_TOKEN and token not in _STOPWORDS
    }
