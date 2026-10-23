"""Fail-closed schema validation for the reviewed financial SQLite schema.

This contract checks user table names, column names, and declared foreign-key relationships.
It does not establish database provenance, license, revision, column meaning, or runtime use.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType

FINANCIAL_SCHEMA_CONTRACT: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "district": frozenset(
            {
                "district_id",
                "A2",
                "A3",
                "A4",
                "A5",
                "A6",
                "A7",
                "A8",
                "A9",
                "A10",
                "A11",
                "A12",
                "A13",
                "A14",
                "A15",
                "A16",
            }
        ),
        "client": frozenset(
            {
                "client_id",
                "gender",
                "birth_date",
                "district_id",
                "id_number",
                "full_name",
                "address",
            }
        ),
        "account": frozenset({"account_id", "district_id", "frequency", "date", "service_note"}),
        "disp": frozenset({"disp_id", "client_id", "account_id", "type"}),
        "card": frozenset({"card_id", "disp_id", "type", "issued", "placeholder"}),
        "loan": frozenset(
            {"loan_id", "account_id", "date", "amount", "duration", "payments", "status"}
        ),
        "order": frozenset(
            {"order_id", "account_id", "bank_to", "account_to", "amount", "k_symbol", "note"}
        ),
        "trans": frozenset(
            {
                "trans_id",
                "account_id",
                "date",
                "type",
                "operation",
                "amount",
                "balance",
                "k_symbol",
                "bank",
                "account",
            }
        ),
    }
)

# Each tuple is (source table, source column, referenced table, referenced column).
FINANCIAL_FOREIGN_KEYS = frozenset(
    {
        ("disp", "client_id", "client", "client_id"),
        ("disp", "account_id", "account", "account_id"),
        ("card", "disp_id", "disp", "disp_id"),
        ("account", "district_id", "district", "district_id"),
        ("client", "district_id", "district", "district_id"),
        ("trans", "account_id", "account", "account_id"),
        ("loan", "account_id", "account", "account_id"),
        ("order", "account_id", "account", "account_id"),
    }
)


class SchemaIssueCode(str, Enum):
    FILE_NOT_FOUND = "file_not_found"
    NOT_A_FILE = "not_a_file"
    OPEN_FAILED = "open_failed"
    INVALID_DATABASE = "invalid_database"
    MISSING_TABLES = "missing_tables"
    UNEXPECTED_TABLES = "unexpected_tables"
    MISSING_COLUMNS = "missing_columns"
    UNEXPECTED_COLUMNS = "unexpected_columns"
    FOREIGN_KEY_MISMATCH = "foreign_key_mismatch"


@dataclass(frozen=True)
class SchemaPreflightIssue:
    code: SchemaIssueCode
    message: str
    mismatch_count: int = 0


@dataclass(frozen=True)
class SchemaPreflightResult:
    valid: bool
    issues: tuple[SchemaPreflightIssue, ...]
    table_count: int | None = None
    column_count: int | None = None


def preflight_financial_sqlite(path: str | Path) -> SchemaPreflightResult:
    """Validate a SQLite file against the reviewed schema contract without reading row data.

    Issue messages are deliberately generic: they do not include filesystem paths, database
    values, or table/column identifiers. A result is valid only when every contract check passes.
    """
    database_path = Path(path).expanduser()
    try:
        if not database_path.exists():
            return _failure(SchemaIssueCode.FILE_NOT_FOUND)
        if not database_path.is_file():
            return _failure(SchemaIssueCode.NOT_A_FILE)
        uri = f"{database_path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True)
    except OSError:
        return _failure(SchemaIssueCode.OPEN_FAILED)
    except sqlite3.Error as error:
        return _failure(_database_open_error_code(error))

    try:
        # Query only SQLite's schema catalog. No customer rows are selected or exposed.
        tables = {
            name
            for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            if not name.startswith("sqlite_")
        }
        columns_by_table: dict[str, set[str]] = {}
        for table in tables & FINANCIAL_SCHEMA_CONTRACT.keys():
            quoted_table = table.replace('"', '""')
            columns_by_table[table] = {
                row[1] for row in connection.execute(f'PRAGMA table_xinfo("{quoted_table}")')
            }

        actual_foreign_keys: list[tuple[str, str, str, str]] = []
        for table in tables & FINANCIAL_SCHEMA_CONTRACT.keys():
            quoted_table = table.replace('"', '""')
            actual_foreign_keys.extend(
                (table, row[3], row[2], row[4])
                for row in connection.execute(f'PRAGMA foreign_key_list("{quoted_table}")')
            )
    except sqlite3.DatabaseError:
        return _failure(SchemaIssueCode.INVALID_DATABASE)
    finally:
        connection.close()

    issues: list[SchemaPreflightIssue] = []
    missing_tables = FINANCIAL_SCHEMA_CONTRACT.keys() - tables
    unexpected_tables = tables - FINANCIAL_SCHEMA_CONTRACT.keys()
    if missing_tables:
        issues.append(_issue(SchemaIssueCode.MISSING_TABLES, len(missing_tables)))
    if unexpected_tables:
        issues.append(_issue(SchemaIssueCode.UNEXPECTED_TABLES, len(unexpected_tables)))

    missing_column_count = 0
    unexpected_column_count = 0
    for table, expected_columns in FINANCIAL_SCHEMA_CONTRACT.items():
        actual_columns = columns_by_table.get(table)
        if actual_columns is None:
            continue
        missing_column_count += len(expected_columns - actual_columns)
        unexpected_column_count += len(actual_columns - expected_columns)
    if missing_column_count:
        issues.append(_issue(SchemaIssueCode.MISSING_COLUMNS, missing_column_count))
    if unexpected_column_count:
        issues.append(_issue(SchemaIssueCode.UNEXPECTED_COLUMNS, unexpected_column_count))

    foreign_key_mismatch_count = sum(
        (Counter(actual_foreign_keys) - Counter(FINANCIAL_FOREIGN_KEYS)).values()
    ) + sum((Counter(FINANCIAL_FOREIGN_KEYS) - Counter(actual_foreign_keys)).values())
    if foreign_key_mismatch_count:
        issues.append(_issue(SchemaIssueCode.FOREIGN_KEY_MISMATCH, foreign_key_mismatch_count))

    return SchemaPreflightResult(
        valid=not issues,
        issues=tuple(issues),
        table_count=len(tables),
        column_count=sum(map(len, columns_by_table.values())),
    )


def _failure(code: SchemaIssueCode) -> SchemaPreflightResult:
    return SchemaPreflightResult(valid=False, issues=(_issue(code),))


def _issue(code: SchemaIssueCode, mismatch_count: int = 0) -> SchemaPreflightIssue:
    messages = {
        SchemaIssueCode.FILE_NOT_FOUND: "Database file was not found.",
        SchemaIssueCode.NOT_A_FILE: "Database path is not a regular file.",
        SchemaIssueCode.OPEN_FAILED: "Database file could not be opened read-only.",
        SchemaIssueCode.INVALID_DATABASE: "File is not a valid readable SQLite database.",
        SchemaIssueCode.MISSING_TABLES: "Database schema is missing required tables.",
        SchemaIssueCode.UNEXPECTED_TABLES: "Database schema contains unexpected tables.",
        SchemaIssueCode.MISSING_COLUMNS: "Database schema is missing required columns.",
        SchemaIssueCode.UNEXPECTED_COLUMNS: "Database schema contains unexpected columns.",
        SchemaIssueCode.FOREIGN_KEY_MISMATCH: "Database foreign-key relationships do not match.",
    }
    return SchemaPreflightIssue(code=code, message=messages[code], mismatch_count=mismatch_count)


def _database_open_error_code(error: sqlite3.Error) -> SchemaIssueCode:
    if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_CANTOPEN:
        return SchemaIssueCode.OPEN_FAILED
    return SchemaIssueCode.INVALID_DATABASE
