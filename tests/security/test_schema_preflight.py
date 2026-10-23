from __future__ import annotations

import hashlib
import sqlite3

import pytest

from sqlguard.security.schema_preflight import (
    FINANCIAL_FOREIGN_KEYS,
    FINANCIAL_SCHEMA_CONTRACT,
    SchemaIssueCode,
    preflight_financial_sqlite,
)


@pytest.fixture
def financial_schema_path(tmp_path):
    path = tmp_path / "financial-fixture.sqlite"
    create_financial_schema(path)
    return path


def create_financial_schema(
    path,
    *,
    omit_table=None,
    omit_column=None,
    add_table=None,
    add_column=None,
    rename_column=None,
    foreign_keys=FINANCIAL_FOREIGN_KEYS,
):
    with sqlite3.connect(path) as connection:
        for table, expected_columns in FINANCIAL_SCHEMA_CONTRACT.items():
            if table == omit_table:
                continue
            columns = sorted(expected_columns)
            if omit_column and omit_column[0] == table:
                columns.remove(omit_column[1])
            if add_column and add_column[0] == table:
                columns.append(add_column[1])
            if rename_column and rename_column[0] == table:
                columns[columns.index(rename_column[1])] = rename_column[2]
            column_sql = ", ".join(f'"{column}" TEXT' for column in columns)
            table_foreign_keys = [
                (
                    source_column,
                    target_table,
                    target_column,
                )
                for source_table, source_column, target_table, target_column in foreign_keys
                if source_table == table
            ]
            foreign_key_sql = ", ".join(
                f'FOREIGN KEY ("{source}") REFERENCES "{target_table}" ("{target}")'
                for source, target_table, target in table_foreign_keys
            )
            definitions = ", ".join(part for part in (column_sql, foreign_key_sql) if part)
            connection.execute(f'CREATE TABLE "{table}" ({definitions})')

        if add_table:
            connection.execute(f'CREATE TABLE "{add_table}" ("unexpected" TEXT)')


def issue_codes(result):
    return {issue.code for issue in result.issues}


def test_contract_describes_the_reviewed_schema_and_foreign_keys():
    assert FINANCIAL_SCHEMA_CONTRACT == {
        "district": frozenset(
            {
                "district_id",
                *(f"A{number}" for number in range(2, 17)),
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
    assert sum(map(len, FINANCIAL_SCHEMA_CONTRACT.values())) == 61
    assert FINANCIAL_FOREIGN_KEYS == frozenset(
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


def test_valid_reviewed_schema_is_accepted(financial_schema_path):
    result = preflight_financial_sqlite(financial_schema_path)

    assert result.valid
    assert result.issues == ()
    assert result.table_count == 8
    assert result.column_count == 61


def test_missing_file_is_rejected_without_exposing_path(tmp_path):
    path = tmp_path / "private-location" / "missing.sqlite"

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert issue_codes(result) == {SchemaIssueCode.FILE_NOT_FOUND}
    assert str(path) not in repr(result)


def test_non_sqlite_file_is_rejected_without_exposing_contents(tmp_path):
    path = tmp_path / "not-sqlite.sqlite"
    path.write_bytes(b"private-row-value-not-a-database")

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert issue_codes(result) == {SchemaIssueCode.INVALID_DATABASE}
    assert "private-row-value" not in repr(result)
    assert str(path) not in repr(result)


def test_directory_is_rejected_as_not_a_database_file(tmp_path):
    result = preflight_financial_sqlite(tmp_path)

    assert not result.valid
    assert issue_codes(result) == {SchemaIssueCode.NOT_A_FILE}


def test_missing_table_is_rejected(tmp_path):
    path = tmp_path / "missing-table.sqlite"
    create_financial_schema(path, omit_table="card")

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert SchemaIssueCode.MISSING_TABLES in issue_codes(result)


def test_missing_column_is_rejected(tmp_path):
    path = tmp_path / "missing-column.sqlite"
    create_financial_schema(path, omit_column=("client", "full_name"))

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert SchemaIssueCode.MISSING_COLUMNS in issue_codes(result)


def test_unexpected_table_and_column_are_rejected(tmp_path):
    path = tmp_path / "unexpected-schema.sqlite"
    create_financial_schema(
        path,
        add_table="sqliteX_shadow",
        add_column=("account", "unexpected_column"),
    )

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert {
        SchemaIssueCode.UNEXPECTED_TABLES,
        SchemaIssueCode.UNEXPECTED_COLUMNS,
    } <= issue_codes(result)


def test_foreign_key_mismatch_is_rejected(tmp_path):
    path = tmp_path / "wrong-foreign-key.sqlite"
    changed_foreign_keys = set(FINANCIAL_FOREIGN_KEYS)
    changed_foreign_keys.remove(("loan", "account_id", "account", "account_id"))
    changed_foreign_keys.add(("loan", "account_id", "district", "district_id"))
    create_financial_schema(path, foreign_keys=frozenset(changed_foreign_keys))

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert SchemaIssueCode.FOREIGN_KEY_MISMATCH in issue_codes(result)


def test_trans_note_is_not_part_of_the_contract(tmp_path):
    path = tmp_path / "trans-note.sqlite"
    create_financial_schema(path, add_column=("trans", "note"))

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert SchemaIssueCode.UNEXPECTED_COLUMNS in issue_codes(result)


def test_equal_table_and_column_counts_do_not_hide_renamed_columns(tmp_path):
    path = tmp_path / "renamed-column.sqlite"
    create_financial_schema(path, rename_column=("client", "full_name", "renamed_name"))

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert result.table_count == 8
    assert result.column_count == 61
    assert {
        SchemaIssueCode.MISSING_COLUMNS,
        SchemaIssueCode.UNEXPECTED_COLUMNS,
    } <= issue_codes(result)


def test_preflight_is_read_only_and_does_not_expose_row_values(tmp_path):
    path = tmp_path / "read-only-check.sqlite"
    create_financial_schema(path, add_column=("account", "unexpected_column"))
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO account VALUES ('sensitive-fixture-value', NULL, NULL, NULL, NULL, NULL)"
        )
    before = hashlib.sha256(path.read_bytes()).digest()

    result = preflight_financial_sqlite(path)

    assert not result.valid
    assert hashlib.sha256(path.read_bytes()).digest() == before
    assert "sensitive-fixture-value" not in repr(result)
    assert str(path) not in repr(result)
    assert "service_note" not in repr(result)
