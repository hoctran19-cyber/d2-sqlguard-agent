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
| Events | `EventSink.emit(Event)` | Interface and in-memory structured event sink |
| Evaluation | `BenchmarkCase`, `EvaluationResult`, `evaluate(...)` | Offline runner; no official dataset or metric claims |

## Adapter requirements

- A planner adapter must declare provider/configuration errors explicitly, respect the controller's call budget, and avoid returning hidden side effects.
- A tool adapter must validate its input schema, enforce the passed timeout, map backend failures to `ToolError` categories/retryability, and avoid embedding secret values in exceptions.
- A database tool must only execute SQL that has passed the gate and must additionally use a read-only least-privilege account, database-level authorization, parameterization where applicable, and bounded result sizes.
- A security gate is synchronous and fail-closed on parse/validation failures. `PolicySQLGate` is bound to the trusted `SecurityContext` (role from the authenticated session) and reads tables/columns/functions from a versioned policy file. Executors must run `decision.normalized_sql`, never the model's string. Violation codes and their `repairable` flag are listed in `src/sqlguard/security/violations.py`.
- Memory and event implementations must minimize sensitive retention. Event payloads should remain metadata-only unless a reviewed redaction policy is adopted.

## State and failure meanings

`RunStatus` distinguishes `succeeded`, `refused`, `failed`, `timed_out`, and `budget_exhausted`. `AgentState` carries planner-call (`llm_call_count` for compatibility), tool-call, SQL-attempt and retry counters, along with coarse errors, final answer, and failure reason. `max_sql_attempts=None` uses the configured tool-call limit. The demo does not expose provider token usage, cost, or database execution duration.
