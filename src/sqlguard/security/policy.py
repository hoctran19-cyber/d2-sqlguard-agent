from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

DEFAULT_POLICY = "d2_synthetic_v1"
POLICY_ENV = "SQLGUARD_POLICY"
_DEFAULT_DOMAIN = "an internal business database"
_DIALECTS = frozenset({"postgres", "sqlite"})

# How an aggregate-only role may use a column. A role grant is either a list of columns (plain
# reads) or a {column: kind} map using only these kinds.
KEY = "key"  # JOIN conditions and COUNT/COUNT(DISTINCT) only; never output, grouped or filtered
DIMENSION = "dimension"  # grouping, filtering, ordering and labels of an aggregate query
MEASURE = "measure"  # only inside an aggregate function
AGGREGATE_KINDS = frozenset({KEY, DIMENSION, MEASURE})


class PolicyError(ValueError):
    """The policy file is malformed or internally inconsistent."""


@dataclass(frozen=True)
class Canary:
    value: str
    table: str
    column: str


@dataclass(frozen=True)
class PolicyLimits:
    max_sql_bytes: int = 4096
    max_ast_nodes: int = 400
    max_joins: int = 4
    max_rows: int = 100
    max_offset: int = 10_000
    max_result_bytes: int = 65_536
    max_text_length: int = 500
    query_timeout_seconds: float = 3.0


@dataclass(frozen=True)
class RolePolicy:
    """Versioned role -> table -> column permissions for the business schema.

    Every identifier is stored case-folded. ``tables`` is the full schema, so the gate can tell
    a column that does not exist (repairable) from one the role may not read (terminal).
    """

    version: str
    schema: str
    tables: dict[str, frozenset[str]]
    roles: dict[str, dict[str, frozenset[str]]]
    foreign_keys: frozenset[frozenset[tuple[str, str]]]
    functions: frozenset[str]
    cast_types: frozenset[str]
    limits: PolicyLimits
    canaries: tuple[Canary, ...] = ()
    # Reviewed descriptions for get_schema; key "_table" describes the table itself.
    descriptions: dict[str, dict[str, str]] = field(default_factory=dict)
    # Free-text columns the Attack Lab may rewrite: table -> primary key column.
    note_targets: dict[str, str] = field(default_factory=dict)
    # Name of the rewritable column per note target; tables not listed use "note".
    note_columns: dict[str, str] = field(default_factory=dict)
    domain_description: str = _DEFAULT_DOMAIN
    # SQL dialect of the target database; the gate parses and regenerates SQL in it.
    dialect: str = "postgres"
    # Aggregate-only roles: role -> table -> column -> kind (KEY, DIMENSION or MEASURE).
    column_kinds: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)

    def note_column(self, table: str) -> str:
        return self.note_columns.get(table.casefold(), "note")

    def is_aggregate_only(self, role: str) -> bool:
        return role.casefold() in self.column_kinds

    def column_kind(self, role: str, table: str, column: str) -> str | None:
        """KEY, DIMENSION or MEASURE for an aggregate-only role; None for plain reads."""
        return (
            self.column_kinds.get(role.casefold(), {})
            .get(table.casefold(), {})
            .get(column.casefold())
        )

    def has_role(self, role: str) -> bool:
        return role.casefold() in self.roles

    def allowed_tables(self, role: str) -> frozenset[str]:
        return frozenset(self.roles.get(role.casefold(), {}))

    def allowed_columns(self, role: str, table: str) -> frozenset[str]:
        return self.roles.get(role.casefold(), {}).get(table.casefold(), frozenset())

    def can_read(self, role: str, table: str, column: str) -> bool:
        return column.casefold() in self.allowed_columns(role, table)

    def is_foreign_key(self, left: tuple[str, str], right: tuple[str, str]) -> bool:
        return frozenset((left, right)) in self.foreign_keys

    def canaries_for(self, role: str) -> tuple[Canary, ...]:
        """Canary values the role must never see; values from readable columns are excluded."""
        return tuple(c for c in self.canaries if not self.can_read(role, c.table, c.column))

    def forbidden_column_names(self, role: str) -> frozenset[str]:
        names = set()
        for table, columns in self.tables.items():
            names.update(columns - self.allowed_columns(role, table))
        return frozenset(names)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RolePolicy:
        try:
            version = str(data["policy_version"])
            schema = str(data.get("schema", "public")).casefold()
            tables = {
                _fold(table): frozenset(_fold(column) for column in columns)
                for table, columns in data["tables"].items()
            }
            roles: dict[str, dict[str, frozenset[str]]] = {}
            column_kinds: dict[str, dict[str, dict[str, str]]] = {}
            for role, grants in data["roles"].items():
                roles[_fold(role)] = {}
                for table, columns in grants.items():
                    roles[_fold(role)][_fold(table)] = frozenset(_fold(c) for c in columns)
                    if isinstance(columns, dict):
                        column_kinds.setdefault(_fold(role), {})[_fold(table)] = {
                            _fold(column): str(kind) for column, kind in columns.items()
                        }
            dialect = str(data.get("dialect", "postgres")).casefold()
            foreign_keys = frozenset(
                frozenset((_split_column(left), _split_column(right)))
                for left, right in data.get("foreign_keys", ())
            )
            functions = frozenset(str(name) for name in data.get("functions", ()))
            cast_types = frozenset(str(name).upper() for name in data.get("cast_types", ()))
            limits = PolicyLimits(**data.get("limits", {}))
            canaries = tuple(
                Canary(str(item["value"]), _fold(item["table"]), _fold(item["column"]))
                for item in data.get("canaries", ())
            )
            descriptions = {
                _fold(table): {_fold(key): str(text) for key, text in entries.items()}
                for table, entries in data.get("descriptions", {}).items()
            }
            # A target is either the key column (note column "note") or {"key": ..., "column": ...}.
            note_targets, note_columns = {}, {}
            for table, target in data.get("note_targets", {}).items():
                if isinstance(target, dict):
                    note_targets[_fold(table)] = _fold(target["key"])
                    note_columns[_fold(table)] = _fold(target.get("column", "note"))
                else:
                    note_targets[_fold(table)] = _fold(target)
            domain_description = str(data.get("domain_description", _DEFAULT_DOMAIN))
        except (KeyError, TypeError, AttributeError) as error:
            raise PolicyError("Policy file is missing a required field") from error

        if dialect not in _DIALECTS:
            raise PolicyError(f"Unsupported dialect {dialect!r}")
        for role, grants in roles.items():
            for table, columns in grants.items():
                if table not in tables:
                    raise PolicyError(f"Role {role!r} references unknown table {table!r}")
                if not columns <= tables[table]:
                    raise PolicyError(f"Role {role!r} grants unknown columns on {table!r}")
        for role, by_table in column_kinds.items():
            # A role is either plain-read or aggregate-only on every table, never a mix.
            if set(by_table) != set(roles[role]):
                raise PolicyError(f"Role {role!r} mixes plain and aggregate-only grants")
            for kinds in by_table.values():
                if not set(kinds.values()) <= AGGREGATE_KINDS:
                    raise PolicyError(f"Role {role!r} uses an unknown column kind")
        for pair in foreign_keys:
            for table, column in pair:
                if column not in tables.get(table, ()):
                    raise PolicyError(f"Foreign key references unknown column {table}.{column}")
        for canary in canaries:
            if canary.column not in tables.get(canary.table, ()):
                raise PolicyError("Canary references an unknown column")
        for table, entries in descriptions.items():
            if table not in tables or not set(entries) - {"_table"} <= tables[table]:
                raise PolicyError(f"Description references an unknown table or column: {table}")
        for table, key in note_targets.items():
            column = note_columns.get(table, "note")
            if not {key, column} <= tables.get(table, frozenset()):
                raise PolicyError(f"Note target {table!r} needs columns {key!r} and {column!r}")
        return cls(
            version=version,
            schema=schema,
            tables=tables,
            roles=roles,
            foreign_keys=foreign_keys,
            functions=functions,
            cast_types=cast_types,
            limits=limits,
            canaries=canaries,
            descriptions=descriptions,
            note_targets=note_targets,
            note_columns=note_columns,
            domain_description=domain_description,
            dialect=dialect,
            column_kinds=column_kinds,
        )

    @classmethod
    def from_file(cls, path: str | Path) -> RolePolicy:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def load_policy(name: str) -> RolePolicy:
    """Load a packaged policy by name, e.g. ``bird_financial_v1``."""
    if not name.replace("_", "").isalnum():
        raise PolicyError(f"Invalid policy name {name!r}")
    text = (
        resources.files("sqlguard.security")
        .joinpath("policies", f"{name}.json")
        .read_text(encoding="utf-8")
    )
    return RolePolicy.from_dict(json.loads(text))


def load_default_policy() -> RolePolicy:
    """The policy named by ``SQLGUARD_POLICY``, else ``DEFAULT_POLICY``."""
    return load_policy(os.environ.get(POLICY_ENV) or DEFAULT_POLICY)


def _fold(name: str) -> str:
    return str(name).casefold()


def _split_column(qualified: str) -> tuple[str, str]:
    table, _, column = str(qualified).casefold().partition(".")
    if not table or not column:
        raise PolicyError(f"Foreign key column must be table.column, got {qualified!r}")
    return table, column
