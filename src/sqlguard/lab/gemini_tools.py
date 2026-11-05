"""Gemini with function calling, for the naive agent only (N3).

Unlike ``GeminiPlanner``, this client lets the model call ``execute_sql`` over several turns and
feeds it the rows **verbatim**: that is the weakness the demo shows. It keeps the planner's
transport rules: the key travels only in the ``x-goog-api-key`` header over https, and errors
carry a category, never the URL, the key or provider text.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from sqlguard.agent.planning import DEFAULT_GEMINI_MODEL, DEFAULT_GEMINI_URL, GEMINI_API_KEY_ENV
from sqlguard.lab.model import (
    TOOL_NAME,
    ModelReply,
    NaiveModelError,
    ToolCall,
    ToolResults,
    Turn,
    UserTurn,
)

DEFAULT_TIMEOUT_SECONDS = 30.0
_MODEL_NAME = re.compile(r"[A-Za-z0-9._-]+")
_BLOCKED = frozenset({"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII"})

TOOL_DECLARATIONS: list[dict[str, Any]] = [
    {
        "functionDeclarations": [
            {
                "name": TOOL_NAME,
                "description": (
                    "Run one read-only SQLite SELECT statement on the bank database and return "
                    "the columns and rows."
                ),
                "parameters": {
                    "type": "OBJECT",
                    "properties": {
                        "sql": {"type": "STRING", "description": "One SQLite SELECT statement."}
                    },
                    "required": ["sql"],
                },
            }
        ]
    }
]

# (url, body, headers, timeout) -> response body; swapped in tests.
Transport = Callable[[str, bytes, dict[str, str], float], bytes]


def _urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read()
    except urllib.error.HTTPError as error:
        raise NaiveModelError(f"http_{error.code}") from None
    except TimeoutError:
        raise NaiveModelError("timeout") from None
    except urllib.error.URLError as error:
        if isinstance(error.reason, TimeoutError):
            raise NaiveModelError("timeout") from None
        raise NaiveModelError("connection") from None
    except OSError:
        raise NaiveModelError("connection") from None


class GeminiToolModel:
    """``ToolCallingModel`` backed by Gemini ``generateContent`` with one function declared."""

    def __init__(
        self,
        *,
        api_key: str,
        url: str = DEFAULT_GEMINI_URL,
        model: str = DEFAULT_GEMINI_MODEL,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: Transport | None = None,
    ) -> None:
        if not url.startswith("https://"):
            raise ValueError("Gemini URL must start with https://")
        if not api_key or not api_key.strip():
            raise ValueError(f"Gemini API key is missing (set {GEMINI_API_KEY_ENV})")
        if not _MODEL_NAME.fullmatch(model):
            raise ValueError("Gemini model name is invalid")
        if not timeout_seconds > 0:
            raise ValueError("Gemini timeout must be a positive number")
        self.name = f"gemini:{model}"
        self._url = f"{url.rstrip('/')}/models/{model}:generateContent"
        self._api_key = api_key.strip()
        self._timeout = timeout_seconds
        self._transport = transport or _urllib_transport

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, transport: Transport | None = None
    ) -> GeminiToolModel:
        env = os.environ if env is None else env
        raw_timeout = env.get("SQLGUARD_GEMINI_TIMEOUT_SECONDS")
        try:
            timeout = float(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT_SECONDS
        except ValueError:
            raise ValueError("SQLGUARD_GEMINI_TIMEOUT_SECONDS must be a number") from None
        return cls(
            api_key=env.get(GEMINI_API_KEY_ENV) or "",
            url=env.get("SQLGUARD_GEMINI_URL") or DEFAULT_GEMINI_URL,
            model=env.get("SQLGUARD_GEMINI_MODEL") or DEFAULT_GEMINI_MODEL,
            timeout_seconds=timeout,
            transport=transport,
        )

    async def generate(
        self, system: str, turns: Sequence[Turn], *, allow_tools: bool
    ) -> ModelReply:
        payload = build_payload(system, turns, allow_tools=allow_tools)
        headers = {"Content-Type": "application/json", "x-goog-api-key": self._api_key}
        body = await asyncio.to_thread(
            self._transport, self._url, json.dumps(payload).encode("utf-8"), headers, self._timeout
        )
        return parse_reply(body)


def build_payload(system: str, turns: Sequence[Turn], *, allow_tools: bool) -> dict[str, Any]:
    """Gemini request for the whole conversation so far. Rows go in as plain JSON: no fence."""
    contents = []
    for turn in turns:
        if isinstance(turn, UserTurn):
            contents.append({"role": "user", "parts": [{"text": turn.text}]})
        elif isinstance(turn, ModelReply):
            contents.append(turn.raw if turn.raw is not None else _model_content(turn))
        elif isinstance(turn, ToolResults):
            contents.append(
                {
                    "role": "user",
                    "parts": [
                        {"functionResponse": {"name": r.call.name, "response": r.payload}}
                        for r in turn.results
                    ],
                }
            )
    mode = "AUTO" if allow_tools else "NONE"
    return {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": contents,
        "tools": TOOL_DECLARATIONS,
        "toolConfig": {"functionCallingConfig": {"mode": mode}},
        "generationConfig": {"temperature": 0},
    }


def _model_content(reply: ModelReply) -> dict[str, Any]:
    parts: list[dict[str, Any]] = [{"text": reply.text}] if reply.text else []
    parts += [{"functionCall": {"name": c.name, "args": {"sql": c.sql}}} for c in reply.tool_calls]
    return {"role": "model", "parts": parts}


def parse_reply(body: bytes) -> ModelReply:
    """Text and ``execute_sql`` calls of the first candidate; thought parts are dropped."""
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise NaiveModelError("invalid_response") from None
    if not isinstance(data, dict):
        raise NaiveModelError("invalid_response")
    feedback = data.get("promptFeedback")
    if isinstance(feedback, dict) and feedback.get("blockReason"):
        raise NaiveModelError("blocked")
    candidates = data.get("candidates")
    candidate = candidates[0] if isinstance(candidates, list) and candidates else None
    if not isinstance(candidate, dict):
        raise NaiveModelError("invalid_response")
    if candidate.get("finishReason") in _BLOCKED:
        raise NaiveModelError("blocked")
    content = candidate.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        raise NaiveModelError("invalid_response")
    text, calls = [], []
    for part in parts:
        if not isinstance(part, dict) or part.get("thought"):
            continue
        if isinstance(part.get("text"), str):
            text.append(part["text"])
        call = part.get("functionCall")
        if isinstance(call, dict):
            args = call.get("args")
            sql = args.get("sql") if isinstance(args, dict) else None
            if call.get("name") != TOOL_NAME or not isinstance(sql, str) or not sql.strip():
                raise NaiveModelError("invalid_tool_call")
            calls.append(ToolCall(sql=sql.strip()))
    if not calls and not "".join(text).strip():
        raise NaiveModelError("empty_reply")
    raw = {"role": "model", "parts": parts}
    return ModelReply(text="".join(text).strip(), tool_calls=tuple(calls), raw=raw)
