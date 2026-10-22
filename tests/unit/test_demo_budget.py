import pytest

from sqlguard.demo import budget_from_env


def test_default_budget_when_unset():
    assert budget_from_env({}).run_timeout_seconds == 60.0


def test_run_timeout_override():
    assert budget_from_env({"SQLGUARD_RUN_TIMEOUT_SECONDS": "600"}).run_timeout_seconds == 600.0


@pytest.mark.parametrize("value", ["abc", "0", "-5"])
def test_invalid_run_timeout_rejected(value):
    with pytest.raises(ValueError, match="SQLGUARD_RUN_TIMEOUT_SECONDS|positive"):
        budget_from_env({"SQLGUARD_RUN_TIMEOUT_SECONDS": value})
