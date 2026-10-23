# Module interfaces

The current contracts are Python `Protocol`s and dataclasses. Implementations are injected into `AgentController`, keeping vendor choices out of the orchestration layer.

| Contract | Current interface | Current status |
| --- | --- | --- |
| Controller | `AgentController.run(AgentRequest) -> AgentResult` | Implemented; asynchronous bounded loop with distinct refusal outcome |
| LLM/planning | `Planner.create_plan(question, context) -> Plan` | Interface and deterministic placeholder; no LLM call |
| Tool/MCP | `ToolRegistry.call(name, arguments, timeout_seconds)` | Interface, registry, and mock; no MCP transport |
| Security | `SecurityGate.check(sql) -> SecurityDecision`; `PolicySQLGate(SecurityContext, RolePolicy, mode=...)` | Role/column policy gate (Postgres dialect) with partial answers, `normalized_sql`, hashes, `repairable` and audit; legacy `ReadOnlySQLGate` kept |
| Secure query | `SecureSqlTool(gate, QueryExecutor, audit=...)` (tool name `query`) | Execute boundary: re-check, execute `normalized_sql` only, caps, sanitizer, canary check, untrusted envelope; `PostgresExecutor` per-role credentials |
| Schema / prompt | `SchemaTool(context)` (`get_schema`), `build_system_prompt`, `render_tool_result`, `render_denial` | Role-filtered schema from the reviewed policy; fixed system prompt and nonce-fenced untrusted blocks. Integration guide: [`SECURITY_INTEGRATION.md`](SECURITY_INTEGRATION.md) |
| Attack Lab | `AttackLab(PostgresNoteWriter(dsn), enabled=...)` | Demo-only note save/restore with revisions, active-run lock and audit; not an agent tool |
| Memory | Short-term: `MemoryStore.append(run_id, kind, value)` / `get(run_id, kind)`; semantic: `SemanticMemory.render_for_role(role, policy, schema_context)` | Short-term memory is process-local and TTL-bound; semantic definitions are immutable, versioned, source-linked, and filtered against trusted role grants and available schema |
| Events | `EventSink.emit(Event)` | In-memory sink, SQLite metadata persistence, and run-scoped in-process live fan-out for authenticated SSE; configure `SQLGUARD_EVENT_DB_PATH` (default: `$XDG_STATE_HOME/sqlguard/events.sqlite3` or `~/.local/state/sqlguard/events.sqlite3`) |
| Evaluation | `BenchmarkCase`, `EvaluationResult`, `evaluate(...)` | Offline runner; no official dataset or metric claims |

## Query history API

The admin-only Query History UI uses these endpoints:

- `GET /api/query/history?limit=20&offset=0` returns `{items, total, limit, offset}`.
  Each item contains `run_id`, `started_at`, `ended_at`, `event_count`, terminal `status`,
  terminal `duration_ms`, and a safe `error_category` when a terminal event provides one.
  Runs are ordered newest first; `limit` is 1–100 and `offset` is 0–1,000,000.
- `GET /api/query/history/{run_id}` returns the run ID and its persisted event metadata in
  insertion order. Unknown or malformed run IDs return 404.

Both endpoints require the existing admin session and return 401 when unauthenticated or 403
for business and evaluator roles. This is the project's existing local demo authentication,
not a production authentication or authorization claim. The history store persists only
observability events; it does not retain question text, SQL, query results, or conversation
content for replay.

## Live Query events

The admin Query page opens `GET /api/query/stream/{run_id}` as an authenticated Server-Sent
Events stream before sending `POST /api/query` with the same UUID in `run_id`. The stream requires
the same admin session (401 unauthenticated, 403 for business/evaluator roles). Each `agent_event`
has an SSE event ID and a JSON payload with run ID, event type, timestamp, status, module, step,
duration, safe error category, attempt/retry correlation, counters, budget, and event-specific
observed data. The current Web query runtime uses an in-process tool registry; it does not claim
that a remote MCP transport is invoked. The browser's `Last-Event-ID` cursor replays missing
in-process events after a temporary reconnect; retained event payloads are bounded and expire
after ten minutes. A backend
restart or expired replay window cannot recover transient payloads.

Live payloads such as the authenticated request's prompt, proposed SQL, and filtered output
preview are transient and are not written by the SQLite event store or included in the ordinary
Query response's event list. Playback controls only change presentation; they do not pause the
agent. The SSE broker is process-local, so deployments with multiple workers need sticky routing
or a shared event broker before they can stream runs across workers.

## Adapter requirements

- A planner adapter must declare provider/configuration errors explicitly, respect the controller's call budget, and avoid returning hidden side effects.
- A tool adapter must validate its input schema, enforce the passed timeout, map backend failures to `ToolError` categories/retryability, and avoid embedding secret values in exceptions.
- A database tool must only execute SQL that has passed the gate and must additionally use a read-only least-privilege account, database-level authorization, parameterization where applicable, and bounded result sizes.
- A security gate is synchronous and fail-closed on parse/validation failures. `PolicySQLGate` is bound to the trusted `SecurityContext` (role from the authenticated session) and reads tables/columns/functions from a versioned policy file. Executors must run `decision.normalized_sql`, never the model's string. Violation codes and their `repairable` flag are listed in `src/sqlguard/security/violations.py`.
- Memory and event implementations must minimize sensitive retention. SQLite persistence and
  ordinary Query responses remain metadata-only; transient live payload fields must be bounded,
  emitted only on the admin-authenticated run stream, and never include model chain-of-thought.

## State and failure meanings

`RunStatus` distinguishes `succeeded`, `refused`, `failed`, `timed_out`, and `budget_exhausted`. `AgentState` carries planner-call (`llm_call_count` for compatibility), tool-call, SQL-attempt and retry counters, along with coarse errors, final answer, and failure reason. `max_sql_attempts=None` uses the configured tool-call limit. The demo does not expose provider token usage, cost, or database execution duration.
