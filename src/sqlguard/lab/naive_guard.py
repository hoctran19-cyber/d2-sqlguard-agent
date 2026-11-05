"""Fail-closed switch for the naive demo (N1).

The naive agent reads the database with no role authorizer, so it may only ever touch an Attack
Lab copy. ``naive_demo_from_env`` returns ``None`` unless ``SQLGUARD_NAIVE_DEMO=1``; switched on
but misconfigured, it raises ``NaiveDemoError`` so the web app refuses to start, exactly like the
lab itself.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from sqlguard.agent.planning import GEMINI_API_KEY_ENV
from sqlguard.security.attack_lab import LAB_DB_ENV, LAB_POLICY, AttackLab, LabError
from sqlguard.security.attack_lab import _check_marker as _check_lab_marker
from sqlguard.security.policy import RolePolicy, load_policy

NAIVE_DEMO_ENV = "SQLGUARD_NAIVE_DEMO"
NAIVE_MODEL_ENV = "SQLGUARD_NAIVE_MODEL"
NAIVE_MODELS = frozenset({"gemini", "scripted"})


class NaiveDemoError(Exception):
    """Naive demo switched on but unsafe or incomplete; carries a category only."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class NaiveDemoConfig:
    """What the naive agent may use: the lab copy, the lab policy and a model kind."""

    database: Path
    policy: RolePolicy
    model: str  # "gemini" or "scripted"


def ensure_lab_copy(database: str | Path, policy: RolePolicy) -> Path:
    """Raise ``NaiveDemoError`` unless ``database`` is an Attack Lab copy made for ``policy``.

    Checked at start-up and again before every naive query, so a file swapped after start-up
    is refused too.
    """
    path = Path(database).expanduser()
    if not path.is_file():
        raise NaiveDemoError("naive_db_missing")
    try:
        _check_lab_marker(path, policy)
    except LabError:
        raise NaiveDemoError("naive_db_not_a_lab_copy") from None
    return path


def naive_demo_from_env(
    env: Mapping[str, str] | None = None,
    *,
    lab: AttackLab | None,
    policy: RolePolicy | None = None,
) -> NaiveDemoConfig | None:
    """The naive demo configuration, or ``None`` unless ``SQLGUARD_NAIVE_DEMO=1``.

    ``lab`` is the running Attack Lab (``attack_lab_from_env``). It has already checked that the
    business database is the lab copy; the naive demo refuses to run without it.
    """
    env = os.environ if env is None else env
    if env.get(NAIVE_DEMO_ENV, "").strip() != "1":
        return None
    if lab is None:
        raise NaiveDemoError("naive_requires_lab")
    policy = policy or load_policy(LAB_POLICY)
    database = ensure_lab_copy(env.get(LAB_DB_ENV, "").strip() or "", policy)
    model = (env.get(NAIVE_MODEL_ENV) or "gemini").strip().casefold()
    if model not in NAIVE_MODELS:
        raise NaiveDemoError("naive_model_invalid")
    if model == "gemini" and not (env.get(GEMINI_API_KEY_ENV) or "").strip():
        raise NaiveDemoError("naive_gemini_key_missing")
    return NaiveDemoConfig(database=database, policy=policy, model=model)
