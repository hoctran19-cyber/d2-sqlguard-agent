from sqlguard.security.gate import ReadOnlySQLGate


def test_gate_allows_single_select():
    decision = ReadOnlySQLGate().check("SELECT id FROM users")

    assert decision.allowed
    assert decision.violations == ()


def test_gate_denies_dml_malformed_and_multiple_statements():
    gate = ReadOnlySQLGate()

    for sql in ("DELETE FROM users", "SELECT FROM", "SELECT 1; DROP TABLE users"):
        decision = gate.check(sql)
        assert not decision.allowed
        assert decision.violations


def test_gate_enforces_optional_table_allowlist():
    decision = ReadOnlySQLGate(allowed_tables={"public_users"}).check(
        "SELECT id FROM private_users"
    )

    assert not decision.allowed
    assert decision.violations == ("table_not_allowed",)
