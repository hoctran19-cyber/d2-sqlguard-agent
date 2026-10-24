from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, SqlglotError

from sqlguard.security.audit import AuditRecord, AuditSink
from sqlguard.security.policy import KEY, MEASURE, RolePolicy, load_default_policy
from sqlguard.security.question_coverage import check_question_coverage
from sqlguard.security.violations import VIOLATIONS, by_severity, is_repairable


class DecisionKind(StrEnum):
    ALLOW = "allow"
    ALLOW_PARTIAL = "allow_partial"
    DENY = "deny"
    UNSUPPORTED = "unsupported"


class GateMode(StrEnum):
    COLUMN_LEVEL = "column_level"  # Ours: AST column gate
    TABLE_LEVEL = "table_level"  # B1/B2: a table is all-or-nothing for a role
    OFF = "off"  # B0: evaluation sandbox only; DB grants are the only control


@dataclass(frozen=True)
class SecurityDecision:
    allowed: bool
    reason: str
    violations: tuple[str, ...] = ()
    kind: DecisionKind | None = None
    normalized_sql: str | None = None  # the only SQL an executor may run
    query_hash: str | None = None
    input_hash: str | None = None
    removed_columns: tuple[str, ...] = ()
    repairable: bool = False
    policy_version: str | None = None
    referenced_tables: tuple[str, ...] = ()
    referenced_columns: tuple[str, ...] = ()
    notices: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind is None:
            object.__setattr__(
                self, "kind", DecisionKind.ALLOW if self.allowed else DecisionKind.DENY
            )


class SecurityGate(Protocol):
    def check(self, sql: str) -> SecurityDecision: ...


@dataclass(frozen=True)
class SecurityContext:
    """Trusted launch context; built by the backend from the authenticated session, never by
    the LLM or from a request body."""

    role: str
    user_id: str = "anonymous"
    run_id: str | None = None
    request_mode: str = "nl"  # "nl" or "manual_sql"
    # The user's own question (never evidence or model text), for the question coverage check.
    # Never written to audit records.
    question: str | None = field(default=None, repr=False)


class ReadOnlySQLGate:
    """Fail-closed, single-SELECT gate; not a complete data authorization policy."""

    def __init__(self, allowed_tables: set[str] | None = None) -> None:
        self._allowed_tables = (
            {table.casefold() for table in allowed_tables} if allowed_tables is not None else None
        )

    def check(self, sql: str) -> SecurityDecision:
        if not sql.strip():
            return _deny("SQL is empty", "empty_sql")
        try:
            statements = sqlglot.parse(sql, read="sqlite")
        except ParseError:
            return _deny("SQL could not be parsed", "parse_error")
        if len(statements) != 1 or statements[0] is None:
            return _deny("Exactly one SQL statement is required", "multiple_statements")
        statement = statements[0]
        if not isinstance(statement, exp.Select):
            return _deny("Only read-only SELECT statements are permitted", "not_select")
        if self._allowed_tables is not None:
            referenced = {
                table.name.casefold() for table in statement.find_all(exp.Table) if table.name
            }
            disallowed = sorted(referenced - self._allowed_tables)
            if disallowed:
                return _deny("Query references a table outside the allowlist", "table_not_allowed")
        return SecurityDecision(allowed=True, reason="Read-only SELECT accepted")


def _deny(reason: str, violation: str) -> SecurityDecision:
    return SecurityDecision(allowed=False, reason=reason, violations=(violation,))


_WRITE_TYPES: tuple[type[exp.Expression], ...] = tuple(
    getattr(exp, name)
    for name in (
        "Insert",
        "Update",
        "Delete",
        "Merge",
        "Create",
        "Drop",
        "Alter",
        "AlterTable",
        "TruncateTable",
        "Copy",
        "Grant",
        "Set",
        "Transaction",
        "Commit",
        "Rollback",
        "Use",
        "Pragma",
        "LoadData",
        "Returning",
    )
    if hasattr(exp, name)
)
_SET_OPERATION_TYPES = (exp.Union, exp.Intersect, exp.Except)
_SUBQUERY_TYPES = (exp.Subquery, exp.Select, exp.Exists)
_STRUCTURAL_FUNCTIONS = (exp.Case, exp.If, exp.Cast)
_STRUCTURAL_TYPES = (
    exp.From,
    exp.Join,
    exp.Where,
    exp.Group,
    exp.Having,
    exp.Order,
    exp.Ordered,
    exp.Limit,
    exp.Offset,
    exp.Table,
    exp.TableAlias,
    exp.Alias,
    exp.Column,
    exp.Identifier,
    exp.Literal,
    exp.Boolean,
    exp.Null,
    exp.EQ,
    exp.NEQ,
    exp.GT,
    exp.GTE,
    exp.LT,
    exp.LTE,
    exp.And,
    exp.Or,
    exp.Not,
    exp.Paren,
    exp.Add,
    exp.Sub,
    exp.Mul,
    exp.Div,
    exp.Mod,
    exp.Neg,
    exp.Between,
    exp.In,
    exp.Like,
    exp.ILike,
    exp.Is,
    exp.DPipe,
    exp.DataTypeParam,
    exp.Interval,
)
_VAR_PARENTS = (exp.TimestampTrunc, exp.DateTrunc, exp.Extract, exp.Interval)
_SELECT_ARGS = {
    "expressions",
    "from",
    "joins",
    "where",
    "group",
    "having",
    "order",
    "limit",
    "offset",
    "distinct",
}
_TABLE_ARGS = {"this", "db", "catalog", "alias", "only"}
_JOIN_ARGS = {"this", "side", "kind", "on"}
_SYSTEM_SCHEMAS = {"pg_catalog", "information_schema", "pg_toast"}
# Output columns the gate adds itself; queries may not use identifiers with this prefix, so a
# model cannot forge the group counts SecureSqlTool trusts.
RESERVED_PREFIX = "__sqlguard"
GROUP_COUNT_PREFIX = f"{RESERVED_PREFIX}_group_"


class PolicySQLGate:
    """Role-aware SQLGlot gate for the D2 SELECT subset (Postgres dialect), fail-closed.

    Checks every column reference (projection, predicates, joins, grouping, ordering and
    function arguments), not only the SELECT list. Allowed queries are regenerated from the AST;
    callers must execute ``decision.normalized_sql`` and never the original string.
    """

    def __init__(
        self,
        context: SecurityContext,
        policy: RolePolicy | None = None,
        *,
        mode: GateMode = GateMode.COLUMN_LEVEL,
        auto_partial: bool = True,
        audit: AuditSink | None = None,
    ) -> None:
        self._context = context
        self._policy = policy or load_default_policy()
        self._mode = GateMode(mode)
        self._auto_partial = auto_partial
        self._audit = audit
        self._checks = 0

    @property
    def policy(self) -> RolePolicy:
        return self._policy

    @property
    def mode(self) -> GateMode:
        return self._mode

    @property
    def context(self) -> SecurityContext:
        return self._context

    def check(self, sql: str) -> SecurityDecision:
        self._checks += 1
        try:
            decision = _Evaluation(self, sql).run()
        except Exception:
            decision = self._denied(("gate_error",), input_hash=_hash_text(sql))
        if self._audit is not None:
            try:
                self._audit.record(self.audit_record(decision, phase="gate", attempt=self._checks))
            except Exception:
                return self._denied(("gate_error",), input_hash=decision.input_hash)
        return decision

    def audit_record(self, decision: SecurityDecision, *, phase: str, attempt: int, **extra):
        fields = {
            "phase": phase,
            "outcome": "allowed" if decision.allowed else "denied",
            "role": self._context.role,
            "policy_version": self._policy.version,
            "gate_mode": self._mode.value,
            "decision_kind": str(decision.kind),
            "run_id": self._context.run_id,
            "attempt": attempt,
            "user_id": self._context.user_id,
            "request_mode": self._context.request_mode,
            "violations": decision.violations,
            "removed_columns": decision.removed_columns,
            "notices": decision.notices,
            "input_hash": decision.input_hash,
            "query_hash": decision.query_hash,
        }
        fields.update(extra)
        return AuditRecord(**fields)

    def _denied(self, codes, *, input_hash: str | None) -> SecurityDecision:
        ordered = by_severity(tuple(codes))
        repairable = is_repairable(ordered)
        unsupported = repairable and any(
            VIOLATIONS[c].error_class == "unsupported_syntax" for c in ordered
        )
        return SecurityDecision(
            allowed=False,
            reason=VIOLATIONS[ordered[0]].reason,
            violations=ordered,
            kind=DecisionKind.UNSUPPORTED if unsupported else DecisionKind.DENY,
            input_hash=input_hash,
            repairable=repairable,
            policy_version=self._policy.version,
        )


@dataclass
class _Evaluation:
    gate: PolicySQLGate
    sql: str
    violations: set[str] = field(default_factory=set)

    def run(self) -> SecurityDecision:
        gate, policy, sql = self.gate, self.gate.policy, self.sql
        if not isinstance(sql, str):
            return gate._denied(("empty_sql",), input_hash=None)
        input_hash = _hash_text(sql)
        role = gate.context.role.casefold()
        limits = policy.limits

        if not sql.strip():
            return gate._denied(("empty_sql",), input_hash=input_hash)
        if len(sql.encode("utf-8")) > limits.max_sql_bytes:
            return gate._denied(("sql_too_long",), input_hash=input_hash)
        if any(_is_control(char) for char in sql):
            return gate._denied(("invalid_characters",), input_hash=input_hash)
        if not policy.has_role(role):
            return gate._denied(("unknown_role",), input_hash=input_hash)
        if gate.mode is GateMode.OFF:
            return SecurityDecision(
                allowed=True,
                reason="Gate disabled (evaluation baseline)",
                normalized_sql=sql.strip(),
                query_hash=_hash_text(sql.strip()),
                input_hash=input_hash,
                policy_version=policy.version,
                notices=("gate_off",),
            )

        dialect = policy.dialect
        try:
            statements = sqlglot.parse(sql, read=dialect)
        except (SqlglotError, RecursionError, ValueError):
            return gate._denied(("parse_error",), input_hash=input_hash)
        if len(statements) != 1 or statements[0] is None:
            return gate._denied(("multiple_statements",), input_hash=input_hash)
        root = statements[0]
        if not isinstance(root, exp.Select):
            if isinstance(root, _WRITE_TYPES):
                code = "write_operation"
            elif isinstance(root, _SET_OPERATION_TYPES):
                code = "set_operation"
            else:
                code = "not_select"
            # Still report nested writes such as INSERT ... SELECT.
            codes = {code} | ({"write_operation"} if root.find(*_WRITE_TYPES) else set())
            return gate._denied(codes, input_hash=input_hash)
        if sum(1 for _ in root.walk()) > limits.max_ast_nodes:
            return gate._denied(("query_too_complex",), input_hash=input_hash)

        # Collect structure, table and join findings together so a terminal finding (for example
        # a system catalog) is never hidden behind a repairable one (for example ``*``).
        self._check_structure(root)
        if not limits.allow_constant_projections and _constant_projection(root):
            self.violations.add("constant_projection")
        alias_map = self._check_tables(root, role)
        self._check_joins(root, alias_map)
        question = gate.context.question
        check_question = (
            gate.mode is GateMode.COLUMN_LEVEL and bool(question) and bool(policy.question_terms)
        )
        if check_question:
            # A forbidden table the question names, missing from the SQL, means the model answered
            # something else; no repair can answer it, so it is terminal next to repairable
            # findings. A named table the SQL does read is already denied as table_not_allowed.
            named = check_question_coverage(question, policy, role).forbidden_tables
            if set(named) - set(alias_map.values()):
                self.violations.add("question_needs_forbidden_data")
        if self.violations:
            return gate._denied(self.violations, input_hash=input_hash)

        tree = root
        removed: tuple[str, ...] = ()
        referenced_columns: tuple[str, ...] = ()
        if gate.mode is GateMode.COLUMN_LEVEL:
            tree, removed, referenced_columns = self._check_columns(root, alias_map, role)
            if not self.violations and policy.is_aggregate_only(role):
                self._check_aggregate(tree, alias_map, role)
            if self.violations:
                return gate._denied(self.violations, input_hash=input_hash)

        notices: tuple[str, ...] = ()
        if check_question:
            # A forbidden column the question names but the SQL dropped is withheld like a display
            # column the gate removed (named forbidden tables were refused above).
            coverage = check_question_coverage(question, policy, role, removed=removed)
            if coverage.withheld_columns:
                removed += coverage.withheld_columns
                notices += ("question_columns_withheld",)
        if (
            gate.mode is GateMode.COLUMN_LEVEL
            and policy.is_aggregate_only(role)
            and limits.min_group_size > 0
        ):
            tree, notices = _add_group_counts(tree, alias_map, policy)
        tree, limit_notices = _enforce_limit(tree, limits.max_rows)
        notices += limit_notices
        normalized = tree.sql(dialect=dialect, comments=False)
        try:
            reparsed = sqlglot.parse_one(normalized, read=dialect)
        except (SqlglotError, RecursionError, ValueError):
            reparsed = None
        if reparsed is None or reparsed.sql(dialect=dialect, comments=False) != normalized:
            return gate._denied(("normalization_mismatch",), input_hash=input_hash)

        partial = bool(removed)
        return SecurityDecision(
            allowed=True,
            reason=(
                "Query narrowed: forbidden display columns were removed"
                if partial
                else "Query accepted"
            ),
            kind=DecisionKind.ALLOW_PARTIAL if partial else DecisionKind.ALLOW,
            normalized_sql=normalized,
            query_hash=_hash_text(normalized),
            input_hash=input_hash,
            removed_columns=removed,
            policy_version=policy.version,
            referenced_tables=tuple(sorted(set(alias_map.values()))),
            referenced_columns=referenced_columns,
            notices=notices,
        )

    # -- structure ---------------------------------------------------------------------------

    def _check_structure(self, root: exp.Select) -> None:
        policy, column_mode = self.gate.policy, self.gate.mode is GateMode.COLUMN_LEVEL
        for key, value in root.args.items():
            if value and key not in _SELECT_ARGS:
                self.violations.add(_select_arg_violation(key))
        for node in root.walk():
            if node is root:
                continue
            if isinstance(node, exp.Identifier) and node.name.casefold().startswith(
                RESERVED_PREFIX
            ):
                self.violations.add("unsupported_syntax")
            if isinstance(node, _WRITE_TYPES):
                self.violations.add("write_operation")
            elif isinstance(node, exp.Into):
                self.violations.add("select_into")
            elif isinstance(node, exp.Lock):
                self.violations.add("locking_clause")
            elif isinstance(node, exp.With | exp.CTE):
                self.violations.add("cte_not_supported")
            elif isinstance(node, _SET_OPERATION_TYPES):
                self.violations.add("set_operation")
            elif isinstance(node, _SUBQUERY_TYPES):
                self.violations.add("subquery_not_supported")
            elif isinstance(node, exp.Window):
                self.violations.add("window_not_supported")
            elif isinstance(node, exp.Star):
                if column_mode and not isinstance(node.parent, exp.Count):
                    self.violations.add("star_not_allowed")
            elif isinstance(node, exp.Distinct):
                if node.args.get("on"):
                    self.violations.add("unsupported_syntax")
            elif isinstance(node, exp.DataType):
                type_name = node.this.name if isinstance(node.this, exp.DataType.Type) else None
                if type_name not in policy.cast_types or node.expressions:
                    self.violations.add("cast_not_allowed")
            elif isinstance(node, exp.Var):
                if not isinstance(node.parent, _VAR_PARENTS):
                    self.violations.add("unsupported_syntax")
            elif isinstance(node, exp.Func):
                # Connectors such as AND/OR are Func subclasses in SQLGlot.
                if not isinstance(node, _STRUCTURAL_FUNCTIONS + _STRUCTURAL_TYPES) and (
                    type(node).__name__ not in policy.functions
                ):
                    self.violations.add("function_not_allowed")
            elif isinstance(node, exp.Table):
                if any(v for k, v in node.args.items() if k not in _TABLE_ARGS):
                    self.violations.add("unsupported_syntax")
            elif isinstance(node, exp.Group):
                if any(v for k, v in node.args.items() if k != "expressions"):
                    self.violations.add("unsupported_syntax")
            elif isinstance(node, exp.Limit):
                if not _is_int_literal(node.expression) or any(
                    v for k, v in node.args.items() if k != "expression"
                ):
                    self.violations.add("limit_invalid")
            elif isinstance(node, exp.Offset):
                if not _is_int_literal(node.expression) or (
                    int(node.expression.this) > policy.limits.max_offset
                ):
                    self.violations.add("limit_invalid")
            elif not isinstance(node, _STRUCTURAL_TYPES):
                self.violations.add("unsupported_syntax")

    # -- tables and joins --------------------------------------------------------------------

    def _check_tables(self, root: exp.Select, role: str) -> dict[str, str]:
        policy, gate = self.gate.policy, self.gate
        if gate.mode is GateMode.TABLE_LEVEL:
            permitted = {
                table
                for table in policy.allowed_tables(role)
                if policy.allowed_columns(role, table) == policy.tables[table]
            }
        else:
            permitted = set(policy.allowed_tables(role))
        alias_map: dict[str, str] = {}
        for table in root.find_all(exp.Table):
            if not isinstance(table.this, exp.Identifier):
                self.violations.add("function_not_allowed")
                continue
            name, schema = table.name.casefold(), table.db.casefold()
            if table.catalog:
                self.violations.add("schema_not_allowed")
            elif (
                schema in _SYSTEM_SCHEMAS
                or schema.startswith("pg_")
                or name.startswith(("pg_", "sqlite_"))
            ):
                self.violations.add("system_catalog")
            elif schema and schema != policy.schema:
                self.violations.add("schema_not_allowed")
            elif name not in policy.tables:
                self.violations.add("table_unknown")
            elif name not in permitted:
                self.violations.add("table_not_allowed")
            key = table.alias_or_name.casefold()
            if key in alias_map:
                self.violations.add("unsupported_syntax")
            alias_map[key] = name
        return alias_map

    def _check_joins(self, root: exp.Select, alias_map: dict[str, str]) -> None:
        policy = self.gate.policy
        joins = root.args.get("joins") or []
        if len(joins) > policy.limits.max_joins:
            self.violations.add("query_too_complex")
        for join in joins:
            side = (join.args.get("side") or "").upper()
            kind = (join.args.get("kind") or "").upper()
            extra = any(v for k, v in join.args.items() if k not in _JOIN_ARGS)
            allowed_shape = (side, kind) in {
                ("", ""),
                ("", "INNER"),
                ("LEFT", ""),
                ("LEFT", "OUTER"),
            }
            # ON is one foreign-key equality, or an AND of them (a bridge table such as disp
            # joined on both of its keys).
            terms = list(_conjuncts(join.args.get("on")))
            if extra or not allowed_shape or not terms:
                self.violations.add("join_not_allowed")
                continue
            for term in terms:
                left = right = None
                if isinstance(term, exp.EQ):
                    left = _resolve_join_column(term.this, alias_map, policy)
                    right = _resolve_join_column(term.expression, alias_map, policy)
                if left is None or right is None or not policy.is_foreign_key(left, right):
                    self.violations.add("join_not_allowed")

    # -- columns -----------------------------------------------------------------------------

    def _check_columns(self, root: exp.Select, alias_map: dict[str, str], role: str):
        policy, gate = self.gate.policy, self.gate
        projections = list(root.expressions)
        direct: dict[int, int] = {}  # id(column) -> projection index
        output_aliases: dict[str, int] = {}
        for index, projection in enumerate(projections):
            target = projection.this if isinstance(projection, exp.Alias) else projection
            if isinstance(target, exp.Column):
                direct[id(target)] = index
            if isinstance(projection, exp.Alias):
                output_aliases[projection.alias.casefold()] = index

        readable: set[str] = set()
        forbidden_direct: dict[int, str] = {}  # projection index -> table.column
        tainted: set[int] = set()  # projections that read a forbidden column inside an expression
        in_filter = in_group = False
        alias_references: list[exp.Column] = []
        for column in root.find_all(exp.Column):
            resolved = self._resolve_column(column, alias_map, output_aliases)
            if resolved is None:
                if not column.table and column.name.casefold() in output_aliases:
                    alias_references.append(column)
                continue
            table, name = resolved
            if policy.can_read(role, table, name):
                readable.add(f"{table}.{name}")
                continue
            clause = _clause_of(column, root)
            if clause == "filter":
                in_filter = True
            elif clause == "group":
                in_group = True
            elif id(column) in direct:
                forbidden_direct[direct[id(column)]] = f"{table}.{name}"
            else:
                tainted.add(_projection_index(column, root))
        if not (forbidden_direct or tainted or in_filter or in_group):
            return root, (), tuple(sorted(readable))

        # An output alias of a forbidden projection used elsewhere carries the forbidden value.
        dropped = set(forbidden_direct) | tainted
        for column in alias_references:
            if output_aliases[column.name.casefold()] in dropped:
                clause = _clause_of(column, root)
                in_filter = in_filter or clause == "filter"
                in_group = in_group or clause == "group"

        # Filtering/ranking on a forbidden column, or asking only for forbidden data, has no
        # narrower equivalent: terminal. Dropping a display/grouping column does (D1 Axis 4).
        clean = [index for index in range(len(projections)) if index not in dropped]
        if in_filter or not clean:
            self.violations.add("column_forbidden")
        elif (
            not gate._auto_partial
            or tainted
            or in_group
            or root.args.get("distinct")
            or _has_positional_reference(root)
        ):
            self.violations.add("column_forbidden_narrowable")
        if self.violations:
            return root, (), ()

        # Partial answer: only direct display columns are dropped, so the filtered, grouped and
        # ranked row set is unchanged (D2-02 §2: no silent WHERE/ranking change).
        tree = root.copy()
        tree.set(
            "expressions",
            [p for index, p in enumerate(tree.expressions) if index not in forbidden_direct],
        )
        removed = tuple(sorted(set(forbidden_direct.values())))
        return tree, removed, tuple(sorted(readable))

    # -- aggregate-only roles ----------------------------------------------------------------

    def _check_aggregate(self, root: exp.Select, alias_map: dict[str, str], role: str) -> None:
        """Aggregate-only roles get grouped/aggregated results, never individual rows.

        Keys may appear only in JOIN conditions and as what COUNT counts: its direct argument, or
        the value of a CASE branch that COUNT counts directly (``COUNT(DISTINCT CASE WHEN
        gender = 'F' THEN client_id END)``; the WHEN conditions are checked as any other
        expression, so a key there is still exposed); measures only inside an aggregate
        function; dimensions anywhere. Every projection is an aggregate
        or a grouped expression, so SQLite's bare columns cannot return a row's value. Small
        groups are not suppressed here (the cohort threshold is not approved yet).
        """
        policy = self.gate.policy
        projections = list(root.expressions)
        output_aliases = {
            p.alias.casefold(): index
            for index, p in enumerate(projections)
            if isinstance(p, exp.Alias)
        }
        for column in root.find_all(exp.Column):
            resolved = self._resolve_column(column, alias_map, output_aliases)
            if resolved is None:
                continue
            kind = policy.column_kind(role, *resolved)
            aggregate = _enclosing(column, root, exp.AggFunc)
            if kind == KEY:
                parent = column.parent
                if isinstance(parent, exp.Distinct):
                    parent = parent.parent
                counted = isinstance(aggregate, exp.Count) and (
                    parent is aggregate or _counted_case_value(column, aggregate)
                )
                if not (counted or _enclosing(column, root, exp.Join) is not None):
                    self.violations.add("aggregate_key_exposed")
            elif kind == MEASURE and aggregate is None:
                self.violations.add("aggregate_measure_exposed")

        group = root.args.get("group")
        keys = list(group.expressions) if group else []
        grouped_sql = {key.sql() for key in keys}
        grouped_columns = set()
        grouped_indexes = {int(key.this) - 1 for key in keys if _is_int_literal(key)}
        for key in keys:
            if not isinstance(key, exp.Column):
                continue
            if not key.table and key.name.casefold() in output_aliases:
                grouped_indexes.add(output_aliases[key.name.casefold()])
            else:
                grouped_columns.add(self._resolve_column(key, alias_map, output_aliases))
        has_aggregate = False
        for index, projection in enumerate(projections):
            target = projection.this if isinstance(projection, exp.Alias) else projection
            has_aggregate = has_aggregate or target.find(exp.AggFunc) is not None
            bare = [
                self._resolve_column(c, alias_map, output_aliases)
                for c in target.find_all(exp.Column)
                if _enclosing(c, root, exp.AggFunc) is None
            ]
            if bare and index not in grouped_indexes and target.sql() not in grouped_sql:
                if not all(c is not None and c in grouped_columns for c in bare):
                    self.violations.add("aggregate_required")
        if not has_aggregate:
            self.violations.add("aggregate_required")

    def _resolve_column(
        self, column: exp.Column, alias_map: dict[str, str], output_aliases: dict[str, int]
    ) -> tuple[str, str] | None:
        policy = self.gate.policy
        name = column.name.casefold()
        qualifier, schema = column.table.casefold(), column.db.casefold()
        if column.args.get("catalog"):
            self.violations.add("schema_not_allowed")
            return None
        if schema:
            if schema in _SYSTEM_SCHEMAS or schema.startswith("pg_"):
                self.violations.add("system_catalog")
                return None
            if schema != policy.schema or alias_map.get(qualifier) != qualifier:
                self.violations.add("column_unknown")
                return None
        if qualifier:
            table = alias_map.get(qualifier)
            if table is None or name not in policy.tables.get(table, ()):
                self.violations.add("column_unknown")
                return None
            return table, name
        matches = {
            (key, table) for key, table in alias_map.items() if name in policy.tables.get(table, ())
        }
        if len(matches) > 1:
            self.violations.add("column_ambiguous")
            return None
        if matches:
            return next(iter(matches))[1], name
        if name not in output_aliases:
            self.violations.add("column_unknown")
        return None


def _counted_case_value(column: exp.Column, count: exp.Count) -> bool:
    """True when the key is a THEN/ELSE value of a CASE that ``count`` counts directly."""
    parent = column.parent
    if isinstance(parent, exp.If) and parent.args.get("true") is column:
        case = parent.parent
    elif isinstance(parent, exp.Case) and parent.args.get("default") is column:
        case = parent
    else:
        return False
    if not isinstance(case, exp.Case):
        return False
    holder = case.parent
    if isinstance(holder, exp.Distinct):
        holder = holder.parent
    return holder is count


def _constant_projection(root: exp.Select) -> bool:
    """A query that reads no table, or outputs a column that is only a literal (``SELECT 1``,
    ``SELECT NULL AS card_id ...``): what it returns did not come from the database."""
    if root.find(exp.Table) is None:
        return True
    for projection in root.expressions:
        target = projection.this if isinstance(projection, exp.Alias) else projection
        # ``*`` reads the table; it is reported (and repairable) as star_not_allowed instead.
        if target.find(exp.Column, exp.AggFunc, exp.Star) is None:
            return True
    return False


def _select_arg_violation(key: str) -> str:
    return {
        "with": "cte_not_supported",
        "into": "select_into",
        "locks": "locking_clause",
        "windows": "window_not_supported",
    }.get(key, "unsupported_syntax")


def _conjuncts(node):
    """Flatten ``a AND (b AND c)`` into its terms; parentheses are transparent."""
    while isinstance(node, exp.Paren):
        node = node.this
    if isinstance(node, exp.And):
        yield from _conjuncts(node.this)
        yield from _conjuncts(node.expression)
    elif node is not None:
        yield node


def _resolve_join_column(node, alias_map, policy) -> tuple[str, str] | None:
    if not isinstance(node, exp.Column) or node.db or not node.table:
        return None
    table = alias_map.get(node.table.casefold())
    name = node.name.casefold()
    if table is None or name not in policy.tables.get(table, ()):
        return None
    return table, name


def _clause_of(node: exp.Expression, root: exp.Select) -> str:
    """Which top-level clause of ``root`` contains ``node``: filter, group or select."""
    while node.parent is not None and node.parent is not root:
        node = node.parent
        if isinstance(node, exp.Where | exp.Having | exp.Order | exp.Join):
            return "filter"
        if isinstance(node, exp.Group):
            return "group"
    return "select"


def _enclosing(node: exp.Expression, root: exp.Select, kind) -> exp.Expression | None:
    """Nearest ancestor of ``node`` below ``root`` that is an instance of ``kind``."""
    node = node.parent
    while node is not None and node is not root:
        if isinstance(node, kind):
            return node
        node = node.parent
    return None


def _projection_index(node: exp.Expression, root: exp.Select) -> int:
    while node.parent is not root:
        node = node.parent
    return next(index for index, item in enumerate(root.expressions) if item is node)


def _has_positional_reference(root: exp.Select) -> bool:
    group = root.args.get("group")
    order = root.args.get("order")
    keys = list(group.expressions) if group else []
    keys += [ordered.this for ordered in order.expressions] if order else []
    return any(_is_int_literal(key) for key in keys)


def _add_group_counts(
    tree: exp.Select, alias_map: dict[str, str], policy: RolePolicy
) -> tuple[exp.Select, tuple[str, ...]]:
    """Append ``COUNT(DISTINCT <cohort key>)`` per table holding individuals, so SecureSqlTool can
    withhold groups below ``min_group_size``. Appended last, so positional references hold."""
    counts = [
        exp.alias_(
            exp.Count(this=exp.Distinct(expressions=[exp.column(policy.cohort_keys[table], key)])),
            f"{GROUP_COUNT_PREFIX}{index}",
        )
        for index, (key, table) in enumerate(sorted(alias_map.items()))
        if table in policy.cohort_keys
    ]
    if not counts:
        return tree, ()
    tree = tree.copy()
    tree.set("expressions", [*tree.expressions, *counts])
    return tree, ("group_counts_added",)


def _enforce_limit(tree: exp.Select, max_rows: int) -> tuple[exp.Select, tuple[str, ...]]:
    # The gate's own LIMIT asks for one extra row: SecureSqlTool returns at most max_rows rows
    # and flags the result truncated when that extra row arrives. With LIMIT max_rows the
    # database never returns more, so a cut result would look complete.
    limit = tree.args.get("limit")
    if limit is None:
        return tree.limit(max_rows + 1, copy=True), ("limit_added",)
    if int(limit.expression.this) > max_rows:
        tree = tree.copy()
        tree.args["limit"].set("expression", exp.Literal.number(max_rows + 1))
        return tree, ("limit_capped",)
    return tree, ()


def _is_int_literal(node) -> bool:
    return isinstance(node, exp.Literal) and not node.is_string and str(node.this).isdigit()


def _is_control(char: str) -> bool:
    return char not in "\t\n\r" and unicodedata.category(char) in {"Cc", "Cf", "Cs", "Co", "Cn"}


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
