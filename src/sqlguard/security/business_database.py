"""Explicit readiness checks for the reviewed business-role SQLite database.

This module does not enable SQL access or configure legacy web/database paths. Call the guard
before every future business-role database initialization or query; it deliberately does not
cache readiness because the configured file may change.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sqlguard.security.schema_preflight import (
    SchemaPreflightResult,
    preflight_financial_sqlite,
)

BUSINESS_DATABASE_ENV = "SQLGUARD_BUSINESS_FINANCIAL_DB"


class BusinessDatabaseReadinessCode(StrEnum):
    READY = "ready"
    NOT_CONFIGURED = "not_configured"
    SCHEMA_INVALID = "schema_invalid"


@dataclass(frozen=True)
class BusinessDatabaseReadiness:
    ready: bool
    code: BusinessDatabaseReadinessCode
    preflight: SchemaPreflightResult | None = None


class BusinessDatabaseNotReady(RuntimeError):
    """Safe error for callers that must stop when business DB readiness fails."""

    def __init__(self, code: BusinessDatabaseReadinessCode) -> None:
        self.code = code
        super().__init__("Business-role database is not ready.")


def check_business_database_readiness(
    path: str | Path | None = None,
) -> BusinessDatabaseReadiness:
    """Check an explicit business database path or its dedicated environment setting.

    ``SQLGUARD_FINANCIAL_DB`` and the legacy default path are intentionally not consulted. The
    schema preflight runs on every call and its result contains no database path or row values.
    """
    configured_path = path
    if configured_path is None:
        configured_path = os.environ.get(BUSINESS_DATABASE_ENV)
    if configured_path is None or not str(configured_path).strip():
        return BusinessDatabaseReadiness(
            ready=False,
            code=BusinessDatabaseReadinessCode.NOT_CONFIGURED,
        )

    preflight = preflight_financial_sqlite(configured_path)
    if not preflight.valid:
        return BusinessDatabaseReadiness(
            ready=False,
            code=BusinessDatabaseReadinessCode.SCHEMA_INVALID,
            preflight=preflight,
        )
    return BusinessDatabaseReadiness(
        ready=True,
        code=BusinessDatabaseReadinessCode.READY,
        preflight=preflight,
    )


def require_business_database_ready(
    path: str | Path | None = None,
) -> BusinessDatabaseReadiness:
    """Fail closed with a safe error when the explicit business DB is not ready."""
    readiness = check_business_database_readiness(path)
    if not readiness.ready:
        raise BusinessDatabaseNotReady(readiness.code)
    return readiness
