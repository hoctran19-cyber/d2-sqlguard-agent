from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

DEFAULT_POLICY_RESOURCE = "d2_synthetic_v1.json"


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
            roles = {
                _fold(role): {
                    _fold(table): frozenset(_fold(column) for column in columns)
                    for table, columns in grants.items()
                }
                for role, grants in data["roles"].items()
            }
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
        except (KeyError, TypeError, AttributeError) as error:
            raise PolicyError("Policy file is missing a required field") from error

        for role, grants in roles.items():
            for table, columns in grants.items():
                if table not in tables:
                    raise PolicyError(f"Role {role!r} references unknown table {table!r}")
                if not columns <= tables[table]:
                    raise PolicyError(f"Role {role!r} grants unknown columns on {table!r}")
        for pair in foreign_keys:
            for table, column in pair:
                if column not in tables.get(table, ()):
                    raise PolicyError(f"Foreign key references unknown column {table}.{column}")
        for canary in canaries:
            if canary.column not in tables.get(canary.table, ()):
                raise PolicyError("Canary references an unknown column")
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
        )

    @classmethod
    def from_file(cls, path: str | Path) -> RolePolicy:
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def load_default_policy() -> RolePolicy:
    text = (
        resources.files("sqlguard.security")
        .joinpath("policies", DEFAULT_POLICY_RESOURCE)
        .read_text(encoding="utf-8")
    )
    return RolePolicy.from_dict(json.loads(text))


def _fold(name: str) -> str:
    return str(name).casefold()


def _split_column(qualified: str) -> tuple[str, str]:
    table, _, column = str(qualified).casefold().partition(".")
    if not table or not column:
        raise PolicyError(f"Foreign key column must be table.column, got {qualified!r}")
    return table, column
