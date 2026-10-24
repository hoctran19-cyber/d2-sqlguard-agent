"""Pre-demo checklist for the business-role web demo (Gemini planner + financial.sqlite).

It only inspects configuration and the database file; it never calls the planner, so it costs
nothing and sends nothing off the machine. Secret values are never printed.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from sqlguard.agent.planning import GEMINI_API_KEY_ENV
from sqlguard.security.business_database import BUSINESS_DATABASE_ENV
from sqlguard.security.policy import POLICY_ENV, load_policy
from sqlguard.security.schema_preflight import preflight_financial_sqlite

# SHA-256 of the financial.sqlite snapshot pinned by the evaluation suite.
PINNED_SNAPSHOT_SHA256 = "ec45f11d8568fa4dcc2ce60594a37fd9db643d6b0fc01b4a61090faeea21eba0"
EXPECTED_POLICY = "business_financial_v1"


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_checks(env: Mapping[str, str], *, expected_sha256: str | None = None) -> list[Check]:
    checks: list[Check] = []

    planner = (env.get("SQLGUARD_PLANNER") or "").strip().casefold()
    checks.append(
        Check(
            "SQLGUARD_PLANNER",
            planner == "gemini",
            f"{planner or 'unset'} (demo expects gemini; local qwen 3B is too weak, workplan F3)",
        )
    )
    checks.append(
        Check(
            GEMINI_API_KEY_ENV,
            bool((env.get(GEMINI_API_KEY_ENV) or "").strip()),
            "set (value not shown)" if env.get(GEMINI_API_KEY_ENV) else "missing",
        )
    )
    checks.append(
        Check(
            "SQLGUARD_PLANNER_FALLBACK",
            not env.get("SQLGUARD_PLANNER_FALLBACK"),
            "unset (no silent switch to local)"
            if not env.get("SQLGUARD_PLANNER_FALLBACK")
            else "set, but workplan Q1 says no fallback in the demo",
        )
    )

    policy_name = env.get(POLICY_ENV) or ""
    checks.append(
        Check(
            POLICY_ENV,
            policy_name == EXPECTED_POLICY,
            f"{policy_name or 'unset'} (demo expects {EXPECTED_POLICY})",
        )
    )
    try:
        policy = load_policy(EXPECTED_POLICY)
        checks.append(
            Check("policy loads", True, f"{EXPECTED_POLICY} roles: {', '.join(policy.roles)}")
        )
    except Exception as error:  # noqa: BLE001 - report any load failure as a failed check
        checks.append(Check("policy loads", False, type(error).__name__))

    configured = (env.get(BUSINESS_DATABASE_ENV) or "").strip()
    if not configured:
        checks.append(Check(BUSINESS_DATABASE_ENV, False, "unset"))
        return checks
    path = Path(configured).expanduser()
    result = preflight_financial_sqlite(path)
    checks.append(
        Check(
            "schema preflight",
            result.valid,
            f"{result.table_count} tables / {result.column_count} columns"
            if result.valid
            else "failed: " + ", ".join(issue.code.value for issue in result.issues),
        )
    )
    if path.is_file():
        actual = _sha256(path)
        pinned = expected_sha256 or PINNED_SNAPSHOT_SHA256
        checks.append(
            Check(
                "snapshot sha256",
                actual == pinned,
                "matches the snapshot pinned by the evaluation suite"
                if actual == pinned
                else f"differs from pinned ec45f11d…eba0 (actual {actual[:8]}…{actual[-4:]})",
            )
        )
    return checks


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the environment before the web demo.")
    parser.add_argument("--expected-sha256", help="override the pinned financial.sqlite hash")
    args = parser.parse_args(argv)
    checks = run_checks(os.environ if env is None else env, expected_sha256=args.expected_sha256)
    for check in checks:
        print(f"[{'OK' if check.ok else 'FAIL'}] {check.name}: {check.detail}")
    failed = [check for check in checks if not check.ok]
    print(f"{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
