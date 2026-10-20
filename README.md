# SQLGuard — Security-Aware Text-to-SQL Agent

SQLGuard is a CO5151 project starter for a natural-language-to-SQL agent with an explicit security check before query execution. This repository contains a runnable, deterministic demo and replaceable interfaces; it is not a production Text-to-SQL system.

## Goals and scope

The intended system will retrieve database context, plan and generate SQL, enforce security policy, call approved tools, process results, and answer users. This starter demonstrates only the orchestration skeleton. The current planner and query tool are local mocks; there is no LLM, MCP server, database, authentication, production authorization policy, or benchmark result.

## Team

| Member | Ownership |
| --- | --- |
| Trần Thái Học | Agent controller/loop, planning and state, MCP/tool integration, short-term memory, retries, recovery, runtime events |
| Nguyễn Văn Hoàng Khang | Threat model, SQL parsing, security gate/policies, data protection, prompt-injection defenses, security tests/auditing |
| Tiêu Trí Kiệt | Benchmark and ground truth, evaluation harness, baselines/ablations, metrics, error analysis and reports |

See [team responsibilities](docs/TEAM_RESPONSIBILITIES.md) for collaboration and module boundaries.

## Architecture and implementation status

- **Implemented starter:** asynchronous controller, run state and configurable budgets, short-term in-memory store, structured in-memory events, tool contract/registry, SQLGlot-based single-`SELECT` gate, deterministic mock planner/tool, and a small evaluation runner.
- **Not implemented:** real LLM, MCP transport/client, database connection, query authorization tied to identities, durable memory, production observability, recovery based on model-generated repair, or official research benchmark.
- **Security boundary:** the gate denies parse errors, non-`SELECT` statements, multiple statements, and optionally tables outside a configured allowlist. It is not a complete authorization system. A real database adapter must use least privilege, parameterization, timeouts, and independently enforced database permissions.

The architecture and interfaces are described in [`docs/architecture/`](docs/architecture/), [`docs/interfaces/`](docs/interfaces/), and [`docs/threat-model/`](docs/threat-model/).

## Requirements and installation

- Python 3.11 or newer
- pip

```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
which python               # must point to .../d2-sqlguard-agent/.venv/bin/python
python -m pip install -e ".[dev]"
```

macOS/Homebrew notes:

- If `pip install` fails with `externally-managed-environment`, `python` is not the venv interpreter (e.g. conda `(base)` is active). Run `conda deactivate`, recreate the venv (`rm -rf .venv && python3 -m venv .venv`), activate it, and check `which python`. Do not use `--break-system-packages`.
- If `pytest: command not found`, the `[dev]` extra is not installed. Run `python -m pip install -e ".[dev]"` and use `python -m pytest`.

The SQL parser is pinned in `pyproject.toml`. Development dependencies provide pytest and Ruff.

## Run the demo

```bash
sqlguard-demo
# demo_value=1
```

Equivalent invocation: `python -m sqlguard.demo`. The demo uses a deterministic planner and local mock tool; it does not execute SQL against a database.

### Optional: local LLM planner (Ollama + Qwen3)

The default planner is the deterministic `DemoPlanner` (offline, used by all tests). `OllamaPlanner` calls a local Ollama server; no hosted provider or API key is used.

```bash
brew install ollama            # or download the app from https://ollama.com
ollama serve                   # skip if the Ollama app is already running
ollama pull qwen3:8b
curl http://localhost:11434/api/tags   # check the local API lists qwen3:8b
SQLGUARD_PLANNER=ollama python -m sqlguard.demo
```

Optional settings: `SQLGUARD_RUN_TIMEOUT_SECONDS` (demo run budget, default `60`), `SQLGUARD_OLLAMA_URL` (default `http://localhost:11434/api/chat`), `SQLGUARD_OLLAMA_MODEL` (default `qwen3:8b`), `SQLGUARD_OLLAMA_TIMEOUT_SECONDS` (default `60`). The planner uses non-streaming structured JSON output (`sql`, `summary`) and fails the run with `planner_error` on any Ollama or output-validation error; it never falls back to `DemoPlanner`. Generated SQL is only a proposal: it still goes through the security gate before any tool call.

Performance note: `ollama ps` shows whether the model runs on GPU or `100% CPU`. On CPU-only machines `qwen3:8b` can take minutes per request; raise `SQLGUARD_OLLAMA_TIMEOUT_SECONDS`, and note the controller's own 60-second run budget (`ExecutionBudget`) will end the run with `run_timeout` first, so also set `SQLGUARD_RUN_TIMEOUT_SECONDS` (e.g. `600`) for the demo, or use a smaller model (`SQLGUARD_OLLAMA_MODEL`).

Limitations: the planner `context` is currently memory notes, not a database schema, so the model is not given tables/columns until schema retrieval exists; `MockQueryTool` still does not query a real database (no PostgreSQL/MCP yet); there is no LLM-driven SQL repair. Cancelling a run does not abort an in-flight HTTP request; it ends at the timeout.

## Tests, lint, and evaluation

```bash
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

Run the offline sample evaluation case with:

```bash
python -m pytest -q tests/unit/test_evaluation.py
```

Add approved benchmark inputs and expected behaviors under `evaluation/datasets/`, without private or sensitive data. The current evaluation code reports per-case status/latency only; it does not calculate accuracy or claim benchmark performance.

## Configuration

`ExecutionBudget` centralizes defaults: up to 3 tool retries, 6 planner calls, 8 tool calls, 3 seconds per query, and 60 seconds per run. `llm_call_count` and `max_llm_calls` retain their API names for compatibility, but currently count calls to the planner; the deterministic demo does not call an LLM. SQL validation/execution attempts are bounded by `max_sql_attempts`, which defaults to the configured tool-call limit. These values are defaults from the project brief, **not confirmed D2 requirements**; no D2 documents were present in the workspace. Tune them through `ExecutionBudget` when constructing the controller. `.env.example` contains illustrative names only and is not loaded by this demo.

The controller reports security rejection as `RunStatus.REFUSED`. It records only coarse error/retry/status metadata in memory, not the request, generated SQL, or raw tool result. Event sink failures fail the run with `event_sink_error` and prevent further execution; a failed terminal event cannot be guaranteed to have reached the sink. The memory and event implementations remain process-local.

## Development status and next integration steps

See [architecture decisions](docs/decisions/README.md) and the module-specific plans. Replace `DemoPlanner` with an explicitly configured provider, implement a concrete tool/MCP adapter, agree on data authorization and threat-model policy, and add verified benchmark cases before reporting system performance. Do not place API keys, credentials, or private datasets in the repository.
