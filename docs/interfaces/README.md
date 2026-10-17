# Module interfaces

The current contracts are Python `Protocol`s and dataclasses. Implementations are injected into `AgentController`, keeping vendor choices out of the orchestration layer.

| Contract | Current interface | Current status |
| --- | --- | --- |
| Controller | `AgentController.run(AgentRequest) -> AgentResult` | Implemented; asynchronous bounded loop with distinct refusal outcome |
| LLM/planning | `Planner.create_plan(question, context) -> Plan` | Interface and deterministic placeholder; no LLM call |
| Tool/MCP | `ToolRegistry.call(name, arguments, timeout_seconds)` | Interface, registry, and mock; no MCP transport |
| Security | `SecurityGate.check(sql) -> SecurityDecision` | Interface and SQLGlot read-only baseline |
| Memory | `MemoryStore.append(run_id, kind, value)` / `get(run_id, kind)` | Interface and process-local implementation |
| Events | `EventSink.emit(Event)` | Interface and in-memory structured event sink |
| Evaluation | `BenchmarkCase`, `EvaluationResult`, `evaluate(...)` | Offline runner; no official dataset or metric claims |

## Adapter requirements

- A planner adapter must declare provider/configuration errors explicitly, respect the controller's call budget, and avoid returning hidden side effects.
- A tool adapter must validate its input schema, enforce the passed timeout, map backend failures to `ToolError` categories/retryability, and avoid embedding secret values in exceptions.
- A database tool must only execute SQL that has passed the gate and must additionally use a read-only least-privilege account, database-level authorization, parameterization where applicable, and bounded result sizes.
- A security gate is synchronous and fail-closed on parse/validation failures. Policy owners must specify allowed schemas/tables/functions for their deployment.
- Memory and event implementations must minimize sensitive retention. Event payloads should remain metadata-only unless a reviewed redaction policy is adopted.

## State and failure meanings

`RunStatus` distinguishes `succeeded`, `refused`, `failed`, `timed_out`, and `budget_exhausted`. `AgentState` carries planner-call (`llm_call_count` for compatibility), tool-call, SQL-attempt and retry counters, along with coarse errors, final answer, and failure reason. `max_sql_attempts=None` uses the configured tool-call limit. The demo does not expose provider token usage, cost, or database execution duration.
