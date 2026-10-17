# Initial threat model (working draft)

This is a starter checklist, not a completed threat analysis. The current repository runs no external database or LLM and must not be described as production-secure.

## Assets and trust boundaries

- User questions, schema metadata, generated SQL, query results, and run context.
- The planner/provider boundary (future untrusted model output).
- The security gate boundary between generated SQL and tool execution.
- The MCP/tool and database boundary (currently mock-only).
- Runtime memory and event/log sinks.

## Initial threats and controls

| Threat | Starter control | Remaining work |
| --- | --- | --- |
| Generated DDL/DML or malformed SQL executes | SQLGlot parse; accept exactly one `SELECT`; reject parse failure | Define dialect, functions, CTE policy, resource limits, and comprehensive attack tests |
| Unauthorized table access | Optional case-insensitive table allowlist | Resolve schemas/aliases/identity-specific authorization; enforce grants at the database |
| Bypass through a retry | Security rejection is terminal; retries reuse only already-checked SQL | Revalidate any future regenerated SQL on every attempt |
| Slow/hung tool call | Per-tool `asyncio.wait_for`; retry and overall budgets | Ensure real adapters propagate cancellation and server-side query cancellation |
| Prompt injection in data/schema | No LLM or retrieved untrusted content in demo | Define instruction/data separation, retrieval handling, and injection tests before LLM integration |
| Secret or private data leaks to logs | Event schema excludes request, SQL, and result | Review adapter exceptions, provider telemetry, memory retention and redaction |

## Important limitation

Parsing a statement as `SELECT` does not establish that it is authorized or harmless in every database dialect. Do not connect this starter gate directly to a production database. Use a dialect-specific policy, table/function allowlists, a read-only database principal, row/column controls where required, and independent review.

## Security test direction

Add cases for multi-statement inputs, comments/quoting, CTEs, nested queries, attached schemas, sensitive tables, dangerous functions, dialect mismatch, cancellation, large result sets, and future prompt-injection scenarios. Tests should prove rejected SQL never reaches an execution tool.
