# SQLGuard — Security-Aware Text-to-SQL Agent

SQLGuard is a CO5151 project starter for a natural-language-to-SQL agent with an explicit security check before query execution. The default demo is deterministic and uses mocks; optional local Ollama, SQLite, PostgreSQL, and MCP paths are also implemented. This is a controlled technical demo, not a production Text-to-SQL system.

## Goals and scope

The intended system will retrieve database context, plan and generate SQL, enforce security policy, call approved tools, process results, and answer users. The default planner and query tool are local mocks, while the opt-in Ollama, SQLite, PostgreSQL, and MCP paths exercise real local or configured services. There is no production authentication or authorization system, durable memory, or benchmark result.

## Team

| Member | Ownership |
| --- | --- |
| Trần Thái Học | Agent controller/loop, planning and state, MCP/tool integration, short-term memory, retries, recovery, runtime events |
| Nguyễn Văn Hoàng Khang | Threat model, SQL parsing, security gate/policies, data protection, prompt-injection defenses, security tests/auditing |
| Tiêu Trí Kiệt | Benchmark and ground truth, evaluation harness, baselines/ablations, metrics, error analysis and reports |

See [team responsibilities](docs/TEAM_RESPONSIBILITIES.md) for collaboration and module boundaries.

## Architecture and implementation status

- **Implemented starter:** asynchronous controller, run state and configurable budgets, short-term in-memory store, structured in-memory events, tool contract/registry, SQLGlot-based single-`SELECT` gate, deterministic mock planner/tool, optional Ollama planner, read-only SQLite and PostgreSQL executors, optional MCP transport, and a small evaluation runner.
- **Not implemented:** query authorization tied to real authenticated identities, durable memory, production observability, or an official research benchmark.
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
# planner: demo
# tool: MockQueryTool (mock; no database is queried)
# proposed_sql[1]: SELECT 1 AS demo_value
# security_gate[1]: allowed (Read-only SELECT accepted)
# mock_tool_sql[1]: SELECT 1 AS demo_value
# mock_result: demo_value=1
```

Equivalent invocation: `python -m sqlguard.demo`. Add `--question "..."` to choose the natural-language question. The demo prints the selected planner (and model for Ollama), the exact SQL the planner proposed, the security gate verdict, the SQL that reached the tool, and the result or failure status (exit code `1` on failure, `2` on invalid configuration). `mock_result` is the hardcoded `MockQueryTool` value, not a database result; SQL rejected by the gate is never passed to the tool.

### Optional: local LLM planner (Ollama + Qwen3)

The default planner is the deterministic `DemoPlanner` (offline, used by all tests). `OllamaPlanner` calls a local Ollama server; no hosted provider or API key is used.

```bash
brew install ollama            # or download the app from https://ollama.com
ollama serve                   # skip if the Ollama app is already running
ollama pull qwen3:8b
curl http://localhost:11434/api/tags   # check the local API lists qwen3:8b
SQLGUARD_PLANNER=ollama python -m sqlguard.demo --question "Show the demo value"
```

Optional settings: `SQLGUARD_RUN_TIMEOUT_SECONDS` (demo run budget, default `60`), `SQLGUARD_OLLAMA_URL` (default `http://localhost:11434/api/chat`), `SQLGUARD_OLLAMA_MODEL` (default `qwen3:8b`), `SQLGUARD_OLLAMA_TIMEOUT_SECONDS` (default `60`). The planner uses non-streaming structured JSON output (`sql`, `summary`) and fails the run with `planner_error` on any Ollama or output-validation error; it never falls back to `DemoPlanner`. Generated SQL is only a proposal: it still goes through the security gate before any tool call.

Performance note: `ollama ps` shows whether the model runs on GPU or `100% CPU`. On CPU-only machines `qwen3:8b` can take minutes per request; raise `SQLGUARD_OLLAMA_TIMEOUT_SECONDS`, and note the controller's own 60-second run budget (`ExecutionBudget`) will end the run with `run_timeout` first, so also set `SQLGUARD_RUN_TIMEOUT_SECONDS` (e.g. `600`) for the demo, or use a smaller model (`SQLGUARD_OLLAMA_MODEL`).

Limitations: the planner's conversational `context` remains memory notes; schema metadata is supplied separately only when `SQLGUARD_SCHEMA_SOURCE` is explicitly configured. `MockQueryTool` remains a no-database demo backend. SQL repair is bounded and opt-in per planner: when the gate (or the secure tool's independent gate) denies SQL with `repairable=True` and the planner implements `repair_plan` (`OllamaPlanner` does, `DemoPlanner` does not), the planner receives the previous SQL plus a safe denial summary and may propose one corrected query per attempt. Every corrected query goes through the gate again, and repairs consume the existing planner-call, SQL-attempt, tool-call and run-timeout budgets; non-repairable denials stay terminal. Cancelling a run does not abort an in-flight HTTP request; it ends at the timeout.

### Query source: mock (default), PostgreSQL, or local SQLite

`SQLGUARD_QUERY_SOURCE` selects what executes the planner's SQL; it is independent of `SQLGUARD_SCHEMA_SOURCE` (which only controls planner schema context).

- `mock` (default, or unset): `MockQueryTool`; fully offline, no database.
- `postgres` (explicit opt-in): the per-run `PolicySQLGate` pre-check, then `SecureSqlTool` (which re-checks the policy itself) and `PostgresExecutor`, which runs only the gate's normalized SQL in a read-only transaction with a statement timeout and bounded fetch. Results are sanitized, canary-checked, size-capped, and audited (hashes/counts only).
- `sqlite` (explicit opt-in): uses the same per-run `PolicySQLGate` and `SecureSqlTool` with `SQLiteExecutor`. The executor opens an existing local database in SQLite read-only mode, enables `query_only`, applies a progress-handler timeout, and bounds fetched rows. The existing role policy filters the schema context and gates table/column access; SQL must also be compatible with SQLite because the gate's accepted SQL subset is not a SQLite-specific policy. SQLite has no PostgreSQL-style roles or grants: local file permissions remain a separate security boundary, and a user who can access the file outside SQLGuard is not constrained by these application checks.

```bash
export SQLGUARD_QUERY_SOURCE=postgres
export SQLGUARD_ROLE=sales                       # operator-configured trusted role, never from the prompt
export SQLGUARD_DB_DSN_SALES='<postgres DSN for the sales role>'   # one DSN variable per role
SQLGUARD_PLANNER=ollama SQLGUARD_SCHEMA_SOURCE=postgres python -m sqlguard.demo
```

Per-role DSN variables are `SQLGUARD_DB_DSN_<ROLE>` (`SALES`, `FINANCE`, `OPERATIONS`); only the selected role's DSN is used, and there is no fallback credential. Optional `SQLGUARD_AUDIT_PATH` writes audit records as JSONL (otherwise they stay in memory). An invalid or missing role, an unknown `SQLGUARD_QUERY_SOURCE`, a missing DSN or driver, or any later database failure fails the run with a safe category (for example `query_config_error: query_role_unconfigured`, exit code `2`) and never falls back to the mock. The fixed `DemoPlanner` SQL (`SELECT 1`) is rejected by the policy in this mode because it references no permitted table; use the Ollama planner with schema loading. The `psycopg` driver must be installed (`python -m pip install -e ".[postgres]"`).

For a local SQLite file, set both sources explicitly and provide an existing database path:

```bash
export SQLGUARD_QUERY_SOURCE=sqlite
export SQLGUARD_SCHEMA_SOURCE=sqlite
export SQLGUARD_SQLITE_PATH='/absolute/path/to/local.db'
export SQLGUARD_ROLE=sales
SQLGUARD_PLANNER=ollama python -m sqlguard.demo --question "List order IDs and total amounts"
```

The SQLite schema adapter exposes only tables and columns allowed to the selected trusted role. Query and schema sources are independent; `SQLGUARD_SCHEMA_SOURCE` may also be `none` or `postgres`, and `SQLGUARD_QUERY_SOURCE` may be `mock`, `postgres`, or `sqlite`. SQLite mode never creates a missing database or falls back to mock. Use only local data you are authorized to access; database files and SQLite journal/WAL sidecars are ignored by Git. `.env.example` contains placeholders and is not automatically loaded.

### End-to-end local Ollama + SQLite demo

The packaged `d2_synthetic_v1` policy describes a synthetic sales schema. The checked-in `data/financial.sqlite` has a different schema and is not a compatible database for this policy; schema compatibility also does not establish data provenance or license. Create a disposable fixture with synthetic rows instead. The generator refuses to overwrite an existing file and does not add a database binary to Git:

```bash
python -m sqlguard.demo_fixture --output /tmp/sqlguard-demo.sqlite
```

Install the project and start Ollama with a local Qwen model:

```bash
python -m pip install -e ".[dev]"
ollama serve                         # skip if Ollama is already running
ollama pull qwen3:8b
curl http://localhost:11434/api/tags # verify the model is listed
```

Configure the planner, schema source, query source, database, and trusted policy role explicitly. `sales` is a role in the synthetic reference policy; it is not one of the business roles (`operator`, `analyst`, or `credit_officer`).

```bash
export SQLGUARD_PLANNER=ollama
export SQLGUARD_OLLAMA_MODEL=qwen3:8b
export SQLGUARD_SQLITE_PATH=/tmp/sqlguard-demo.sqlite
export SQLGUARD_SCHEMA_SOURCE=sqlite
export SQLGUARD_QUERY_SOURCE=sqlite
export SQLGUARD_ROLE=sales
export SQLGUARD_POLICY=d2_synthetic_v1
python -m sqlguard.demo --question "List order IDs and total amounts"
```

The schema adapter reads `SQLGUARD_SQLITE_PATH` and filters it through the selected policy role. The query runtime opens that same path read-only; SQL passes the policy-aware gate, `SecureSqlTool`, and SQLite authorizer before execution. A successful output identifies the Ollama model, SQLite schema/table count, proposed SQL, gate verdict, and rows returned by SQLite. For the sample question, the synthetic rows should include order IDs `101` and `102` with totals `120000` and `230000` (exact generated SQL can vary by model). `mock_result` means no database was queried; a SQLite result is labeled `result`. Missing configuration, invalid database/schema, unavailable Ollama, or a gate rejection fails visibly and never switches to mock.

Common checks: `query_config_error: query_sqlite_path_missing` means set `SQLGUARD_SQLITE_PATH`; `query_config_error: query_role_missing` means set a supported role; `schema_error: schema_sqlite_source_required` means set `SQLGUARD_SCHEMA_SOURCE=sqlite`. If Ollama is unavailable or the model is not loaded, check `curl http://localhost:11434/api/tags`, confirm `ollama serve` is running, and verify `SQLGUARD_OLLAMA_MODEL` matches one of the listed model names. A security rejection is not a configuration fallback; use a query within the role policy rather than relaxing the gate.

To route execution through the optional local MCP STDIO server instead of the in-process SQLite executor, install the extra and enable MCP:

```bash
python -m pip install -e ".[dev,mcp]"
export SQLGUARD_MCP_ENABLED=true
python -m sqlguard.demo --question "List order IDs and total amounts"
```

MCP requires `SQLGUARD_QUERY_SOURCE=sqlite`, a configured trusted role, an existing `SQLGUARD_SQLITE_PATH`, and the `mcp` extra. The server receives the same SQLite path, role, and selected policy; its query tool still applies the policy gate and SQLite authorizer. Leave `SQLGUARD_MCP_ENABLED` unset (or set it to `false`) to use direct SQLite execution.

Focused tests (no database needed): `python -m pytest -q tests/unit/test_agent_runtime_query.py tests/security/test_controller_security.py`.

## Run the web app

```bash
python -m pip install -e ".[dev,web]"
# Point to BIRD Mini-Dev financial.sqlite (or place it at data/bird/financial.sqlite, git-ignored)
export SQLGUARD_FINANCIAL_DB=/path/to/minidev/MINIDEV/dev_databases/financial/financial.sqlite
python -m sqlguard.web               # http://127.0.0.1:8000
```

Demo accounts (local only): `admin` / `123456` opens `/home` (Query + Database), `eval` / `123456`
opens `/evaluation/` (the evaluation console). The database is opened read-only and every SQL,
including agent-generated SQL, passes `ReadOnlySQLGate` with the financial table allowlist.
The Query page runs the real `AgentController`, but **its planner is a no-LLM demo** that only
maps a few sample questions to SQL (`src/sqlguard/web/demo_planner.py`); replace it in
`build_planner()` once the LLM planner exists. Sessions are in memory and reset on restart.

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
