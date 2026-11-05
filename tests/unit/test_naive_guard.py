"""N1: the naive demo is off by default, needs the Attack Lab on a lab copy, and fails closed."""

from pathlib import Path

import pytest

from sqlguard.agent.planning import GEMINI_API_KEY_ENV
from sqlguard.lab.naive_guard import (
    NAIVE_DEMO_ENV,
    NAIVE_MODEL_ENV,
    NaiveDemoError,
    ensure_lab_copy,
    naive_demo_from_env,
)
from sqlguard.security.attack_lab import (
    BUSINESS_DATABASE_ENV,
    ENABLED_ENV,
    LAB_DB_ENV,
    TARGETS_ENV,
    attack_lab_from_env,
    create_lab_copy,
    marker_path,
)
from sqlguard.security.policy import load_policy

POLICY = load_policy("business_financial_v1")
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def lab_db(financial_db, tmp_path):
    return create_lab_copy(financial_db, tmp_path / "lab" / "financial-lab.sqlite")


def env_for(lab_db, **overrides):
    env = {
        ENABLED_ENV: "1",
        LAB_DB_ENV: str(lab_db),
        BUSINESS_DATABASE_ENV: str(lab_db),
        TARGETS_ENV: "account.3,order.2",
        NAIVE_DEMO_ENV: "1",
        NAIVE_MODEL_ENV: "scripted",
    }
    env.update(overrides)
    return {key: value for key, value in env.items() if value is not None}


def test_off_by_default_even_with_the_lab_on(lab_db):
    env = env_for(lab_db, **{NAIVE_DEMO_ENV: None})
    assert naive_demo_from_env(env, lab=attack_lab_from_env(env)) is None
    assert naive_demo_from_env(env_for(lab_db, **{NAIVE_DEMO_ENV: "yes"}), lab=None) is None


def test_switched_on_without_the_lab_fails_closed(lab_db):
    with pytest.raises(NaiveDemoError, match="naive_requires_lab"):
        naive_demo_from_env(env_for(lab_db), lab=None)


def test_valid_configuration(lab_db):
    env = env_for(lab_db)
    config = naive_demo_from_env(env, lab=attack_lab_from_env(env))
    assert config is not None
    assert config.database == lab_db and config.model == "scripted"
    assert config.policy.version == POLICY.version


def test_default_model_is_gemini_and_needs_a_key(lab_db):
    env = env_for(lab_db, **{NAIVE_MODEL_ENV: None})
    lab = attack_lab_from_env(env)
    with pytest.raises(NaiveDemoError, match="naive_gemini_key_missing"):
        naive_demo_from_env(env, lab=lab)
    config = naive_demo_from_env({**env, GEMINI_API_KEY_ENV: "k"}, lab=lab)
    assert config.model == "gemini"


def test_unknown_model_is_refused(lab_db):
    env = env_for(lab_db, **{NAIVE_MODEL_ENV: "ollama"})
    with pytest.raises(NaiveDemoError, match="naive_model_invalid"):
        naive_demo_from_env(env, lab=attack_lab_from_env(env))


def test_only_a_lab_copy_is_accepted(financial_db, lab_db):
    assert ensure_lab_copy(lab_db, POLICY) == lab_db
    with pytest.raises(NaiveDemoError, match="naive_db_not_a_lab_copy"):
        ensure_lab_copy(financial_db, POLICY)
    with pytest.raises(NaiveDemoError, match="naive_db_missing"):
        ensure_lab_copy(lab_db.parent / "missing.sqlite", POLICY)
    marker_path(lab_db).unlink()
    with pytest.raises(NaiveDemoError, match="naive_db_not_a_lab_copy"):
        ensure_lab_copy(lab_db, POLICY)


def test_web_app_refuses_to_start_when_misconfigured(lab_db, tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from sqlguard.web.app import create_app

    monkeypatch.setenv(NAIVE_DEMO_ENV, "1")
    monkeypatch.setenv(NAIVE_MODEL_ENV, "scripted")
    with pytest.raises(NaiveDemoError, match="naive_requires_lab"):
        create_app(tmp_path / "legacy-missing.sqlite")
    for key, value in env_for(lab_db).items():
        monkeypatch.setenv(key, value)
    app = create_app(tmp_path / "legacy-missing.sqlite")
    assert app.state.naive_demo.database == lab_db


def test_web_app_has_no_naive_demo_by_default(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from sqlguard.web.app import create_app

    monkeypatch.delenv(NAIVE_DEMO_ENV, raising=False)
    assert create_app(tmp_path / "legacy-missing.sqlite").state.naive_demo is None


@pytest.mark.parametrize("folder", ["evaluation", "src/sqlguard/agent", "src/sqlguard/security"])
def test_runtime_and_evaluation_never_import_the_naive_agent(folder):
    offenders = [
        str(path.relative_to(ROOT))
        for path in (ROOT / folder).rglob("*.py")
        if "sqlguard.lab" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []
