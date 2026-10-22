from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SchemaColumn:
    """A column's database metadata; contains no query results or user-provided SQL."""

    name: str
    data_type: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Schema column name must not be empty")
        if not self.data_type.strip():
            raise ValueError("Schema column data type must not be empty")


@dataclass(frozen=True)
class SchemaTable:
    """A table and its ordered column metadata."""

    name: str
    columns: tuple[SchemaColumn, ...]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Schema table name must not be empty")
        if not self.columns:
            raise ValueError("Schema table must contain at least one column")
        names = [column.name.casefold() for column in self.columns]
        if len(names) != len(set(names)):
            raise ValueError(f"Schema table {self.name!r} contains duplicate columns")


@dataclass(frozen=True)
class SchemaContext:
    """Explicit, deterministic schema metadata passed separately from conversation memory."""

    tables: tuple[SchemaTable, ...]
    dialect: str = "postgres"

    def __post_init__(self) -> None:
        if not self.dialect.strip():
            raise ValueError("Schema dialect must not be empty")
        if not self.tables:
            raise ValueError("Schema context must contain at least one table")
        names = [table.name.casefold() for table in self.tables]
        if len(names) != len(set(names)):
            raise ValueError("Schema context contains duplicate table names")

    def to_prompt_text(self) -> str:
        """Render schema metadata deterministically for the planner's structured prompt."""
        lines = [f"Database dialect: {self.dialect}"]
        for table in self.tables:
            lines.append(f"Table: {table.name}")
            lines.extend(f"  - {column.name}: {column.data_type}" for column in table.columns)
        return "\n".join(lines)
