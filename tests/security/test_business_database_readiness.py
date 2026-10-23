from __future__ import annotations

import sqlite3

import pytest

from sqlguard.security.business_database import (
    BUSINESS_DATABASE_ENV,
    BusinessDatabaseNotReady,
    BusinessDatabaseReadinessCode,
    check_business_database_readiness,
    require_business_database_ready,
)
from sqlguard.security.schema_preflight import FINANCIAL_FOREIGN_KEYS, FINANCIAL_SCHEMA_CONTRACT
from sqlguard.web.database import DB_ENV, DEFAULT_DB_PATH, resolve_db_path


@pytest.fixture
def business_database_path(tmp_path):
    path = tmp_path / "business-financial.sqlite"
    create_contract_database(path)
    return path


def create_contract_database(path, *, extra_column=None, changed_foreign_key=False):
    foreign_keys = set(FINANCIAL_FOREIGN_KEYS)
    if changed_foreign_key:
        foreign_keys.remove(("loan", "account_id", "account", "account_id"))
        foreign_keys.add(("loan", "account_id", "district", "district_id"))

    with sqlite3.connect(path) as connection:
        for table, columns in FINANCIAL_SCHEMA_CONTRACT.items():
            definitions = [f'"{column}" TEXT' for column in sorted(columns)]
            if extra_column and extra_column[0] == table:
                definitions.append(f'"{extra_column[1]}" TEXT')
            definitions.extend(
                f'FOREIGN KEY ("{source_column}") REFERENCES "{target_table}" ("{target_column}")'
                for source_table, source_column, target_table, target_column in foreign_keys
                if source_table == table
            )
            connection.execute(f'CREATE TABLE "{table}" ({", ".join(definitions)})')


def test_valid_schema_is_ready_and_require_returns_preflight(business_database_path):
    readiness = require_business_database_ready(business_database_path)

    assert readiness.ready
    assert readiness.code is BusinessDatabaseReadinessCode.READY
    assert readiness.preflight is not None and readiness.preflight.valid


def test_missing_configuration_is_not_ready_even_if_legacy_path_is_configured(
    business_database_path, monkeypatch
):
    monkeypatch.delenv(BUSINESS_DATABASE_ENV, raising=False)
    monkeypatch.setenv(DB_ENV, str(business_database_path))

    readiness = check_business_database_readiness()

    assert not readiness.ready
    assert readiness.code is BusinessDatabaseReadinessCode.NOT_CONFIGURED
    assert readiness.preflight is None
    with pytest.raises(BusinessDatabaseNotReady) as raised:
        require_business_database_ready()
    assert raised.value.code is BusinessDatabaseReadinessCode.NOT_CONFIGURED
    assert str(business_database_path) not in str(raised.value)


@pytest.mark.parametrize("configured_path", ["", "   "])
def test_empty_business_database_configuration_is_not_ready(configured_path, monkeypatch):
    monkeypatch.setenv(BUSINESS_DATABASE_ENV, configured_path)

    readiness = check_business_database_readiness()

    assert not readiness.ready
    assert readiness.code is BusinessDatabaseReadinessCode.NOT_CONFIGURED


def test_missing_configured_file_is_not_ready_without_legacy_fallback(
    business_database_path, monkeypatch, tmp_path
):
    missing_path = tmp_path / "missing-business.sqlite"
    monkeypatch.setenv(BUSINESS_DATABASE_ENV, str(missing_path))
    monkeypatch.setenv(DB_ENV, str(business_database_path))

    readiness = check_business_database_readiness()

    assert not readiness.ready
    assert readiness.code is BusinessDatabaseReadinessCode.SCHEMA_INVALID
    assert readiness.preflight is not None and not readiness.preflight.valid
    assert str(missing_path) not in repr(readiness)
    assert str(business_database_path) not in repr(readiness)


def test_require_rejects_invalid_schema_with_safe_error(tmp_path):
    path = tmp_path / "private-business-db.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE client (private_column TEXT)")
        connection.execute("INSERT INTO client VALUES ('private-row-value')")

    with pytest.raises(BusinessDatabaseNotReady) as raised:
        require_business_database_ready(path)

    assert raised.value.code is BusinessDatabaseReadinessCode.SCHEMA_INVALID
    assert str(path) not in str(raised.value)
    assert "private_column" not in str(raised.value)
    assert "private-row-value" not in str(raised.value)


@pytest.mark.parametrize(
    ("extra_column", "changed_foreign_key"),
    [(("account", "unapproved_column"), False), (None, True)],
)
def test_schema_or_foreign_key_mismatch_fails_closed(tmp_path, extra_column, changed_foreign_key):
    path = tmp_path / "invalid-business.sqlite"
    create_contract_database(
        path,
        extra_column=extra_column,
        changed_foreign_key=changed_foreign_key,
    )

    readiness = check_business_database_readiness(path)

    assert not readiness.ready
    assert readiness.code is BusinessDatabaseReadinessCode.SCHEMA_INVALID


def test_readiness_is_recomputed_after_database_file_changes(business_database_path, tmp_path):
    assert check_business_database_readiness(business_database_path).ready

    replacement_path = tmp_path / "replacement.sqlite"
    with sqlite3.connect(replacement_path) as connection:
        connection.execute("CREATE TABLE changed_schema (value TEXT)")
    replacement_path.replace(business_database_path)

    readiness = check_business_database_readiness(business_database_path)

    assert not readiness.ready
    assert readiness.code is BusinessDatabaseReadinessCode.SCHEMA_INVALID


def test_legacy_database_path_resolution_is_unchanged(monkeypatch, tmp_path):
    legacy_path = tmp_path / "legacy.sqlite"
    business_path = tmp_path / "business.sqlite"
    monkeypatch.setenv(DB_ENV, str(legacy_path))
    monkeypatch.setenv(BUSINESS_DATABASE_ENV, str(business_path))

    assert resolve_db_path() == legacy_path
    monkeypatch.delenv(DB_ENV)
    assert resolve_db_path() == DEFAULT_DB_PATH


def test_valid_schema_readiness_does_not_enable_business_sql(
    business_database_path,
):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    from sqlguard.web.app import create_app

    assert check_business_database_readiness(business_database_path).ready
    client = TestClient(create_app(business_database_path))
    login = client.post(
        "/api/login",
        json={"username": "operator", "password": "123456"},
    )
    assert login.status_code == 200
    response = client.post("/api/sql", json={"sql": "SELECT 1"})
    assert response.status_code == 403
