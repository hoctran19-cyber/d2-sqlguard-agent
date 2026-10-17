# Architecture

## Agent and security flow

```mermaid
flowchart TD
    U[User question] --> C[AgentController<br/>implemented]
    C --> M[Short-term Memory<br/>in-process implementation]
    C --> P[Planner interface<br/>deterministic demo only]
    P --> S{SQL Security Gate<br/>SQLGlot read-only check}
    S -- deny --> F[Fail run; do not call tool]
    S -- allow --> T[ToolRegistry interface<br/>in-process mock only]
    T --> R[Result processing<br/>string formatting]
    R --> A[AgentResult]
    C --> E[Structured event sink<br/>in-memory implementation]
    C --> B[Retry and execution budgets<br/>implemented]
    T -. future adapter .-> MCP[MCP client/server<br/>design only]
    P -. future provider .-> LLM[LLM provider<br/>design only]
    T -. future adapter .-> DB[Least-privilege database<br/>not implemented]
    H[Evaluation harness<br/>basic runner] -. creates runs .-> C
```

## Execution and recovery notes

Each run creates an `AgentState`, stores the request, calls a planner once, and checks the returned SQL. Only an allowed query reaches the tool registry. Retry is limited to retryable tool errors/timeouts and consumes the tool-call budget; the SQL policy is rechecked only once because retries reuse the same SQL, and a security rejection is never retried. Planner failures and exhausted retries terminate the run. Run timeout cancels the active coroutine and returns `timed_out`.

The in-memory event sink records lifecycle events with run ID, timestamp, status, and coarse error category. It deliberately does not carry question, SQL, or result payloads. The memory store is process-local and should be scoped/cleared appropriately before long-lived deployments.

## Not yet designed as production-ready

Database identity/authorization, prompt injection handling, LLM repair, safe result redaction, production event export, MCP wire protocol, and official evaluation metrics need team decisions and implementation. The current SQL policy is a useful structural baseline, not a substitute for database-enforced permissions or security review.
