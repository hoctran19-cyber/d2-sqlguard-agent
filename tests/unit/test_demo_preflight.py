import hashlib

from tests.security.test_business_database_readiness import create_contract_database

from sqlguard.demo_preflight import main, run_checks

KEY = "test-secret-value"


def good_env(path):
    return {
        "SQLGUARD_PLANNER": "gemini",
        "GEMINI_API_KEY": KEY,
        "SQLGUARD_POLICY": "business_financial_v1",
        "SQLGUARD_BUSINESS_FINANCIAL_DB": str(path),
    }


def test_ready_environment_passes_and_never_prints_the_key(tmp_path, capsys):
    path = tmp_path / "financial.sqlite"
    create_contract_database(path)
    pinned = hashlib.sha256(path.read_bytes()).hexdigest()

    code = main(["--expected-sha256", pinned], env=good_env(path))

    output = capsys.readouterr().out
    assert code == 0
    assert "FAIL" not in output
    assert KEY not in output


def test_unpinned_snapshot_is_reported(tmp_path):
    path = tmp_path / "financial.sqlite"
    create_contract_database(path)

    checks = {c.name: c for c in run_checks(good_env(path))}

    assert not checks["snapshot sha256"].ok
    assert checks["schema preflight"].ok


def test_missing_configuration_fails_each_item(tmp_path):
    checks = {c.name: c for c in run_checks({"SQLGUARD_PLANNER": "ollama"})}

    assert not checks["SQLGUARD_PLANNER"].ok
    assert not checks["GEMINI_API_KEY"].ok
    assert not checks["SQLGUARD_POLICY"].ok
    assert not checks["SQLGUARD_BUSINESS_FINANCIAL_DB"].ok


def test_fallback_flag_and_bad_schema_fail(tmp_path):
    path = tmp_path / "financial.sqlite"
    create_contract_database(path, extra_column=("client", "surprise"))
    env = good_env(path) | {"SQLGUARD_PLANNER_FALLBACK": "ollama"}

    checks = {c.name: c for c in run_checks(env)}

    assert not checks["SQLGUARD_PLANNER_FALLBACK"].ok
    assert not checks["schema preflight"].ok
