"""Web side of the naive-agent demo (N6): run the naive agent and build the compare payload.

The route in ``app.py`` runs SQLGuard and the naive agent on the same question, role and lab
copy, then this module puts both results side by side with the same deterministic symptom checks.
Nothing here is written to query history or the audit log: the naive answer is attacker-shaped
text and stays in the HTTP response (``docs/threat-model/NAIVE_AGENT_DEMO.md`` section 3.3).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlguard.lab.gemini_tools import GeminiToolModel
from sqlguard.lab.model import ToolCallingModel, scripted_model_for
from sqlguard.lab.naive_agent import NaiveAgent, NaiveResult, NaiveSqliteExecutor
from sqlguard.lab.naive_guard import NaiveDemoConfig
from sqlguard.lab.naive_prompt import PROMPT_FINGERPRINTS
from sqlguard.lab.symptoms import detect_symptoms, observation_from_naive, observation_from_sqlguard

NAIVE_MODEL_LABELS = {
    "gemini": "Gemini (model thật)",
    "scripted": "Model giả lập bị chiếm (scripted), không phải Gemini",
}


def naive_model(config: NaiveDemoConfig, question: str) -> ToolCallingModel:
    if config.model == "scripted":
        return scripted_model_for(question)
    return GeminiToolModel.from_env()


async def run_naive(
    config: NaiveDemoConfig,
    question: str,
    role: str,
    *,
    model: ToolCallingModel | None = None,
) -> NaiveResult:
    """One naive run on the lab copy. A fresh executor re-checks the lab marker first, so a file
    swapped since start-up raises ``NaiveDemoError`` instead of being queried."""
    executor = NaiveSqliteExecutor(config.database, config.policy)
    agent = NaiveAgent(model or naive_model(config, question), executor, config.policy)
    return await agent.run(question, role)


def compare_payload(
    config: NaiveDemoConfig,
    role: str,
    sqlguard: Mapping[str, Any],
    naive: NaiveResult,
    lab_revisions: Mapping[str, Any] | None,
) -> dict[str, Any]:
    naive_payload = naive.to_payload()
    sqlguard_symptoms = detect_symptoms(
        observation_from_sqlguard(dict(sqlguard)), config.policy, role
    )
    naive_symptoms = detect_symptoms(
        observation_from_naive(naive_payload),
        config.policy,
        role,
        prompt_fingerprints=PROMPT_FINGERPRINTS,
    )
    return {
        "role": role,
        "naive_model": config.model,
        "naive_model_label": NAIVE_MODEL_LABELS.get(config.model, config.model),
        "sqlguard": dict(sqlguard),
        "naive": naive_payload,
        "symptoms": {
            "sqlguard": [symptom.to_payload() for symptom in sqlguard_symptoms],
            "naive": [symptom.to_payload() for symptom in naive_symptoms],
        },
        "lab_revisions": lab_revisions,
    }
