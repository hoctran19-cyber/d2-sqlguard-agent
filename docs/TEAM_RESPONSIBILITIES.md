# Team responsibilities

| Member | Primary ownership | Main paths |
| --- | --- | --- |
| Trần Thái Học — Agent Architecture & Loop | Controller/execution loop, plans and state, MCP/tool integration, per-run memory, retries, timeout/recovery, runtime events | `src/sqlguard/agent/`, `src/sqlguard/mcp/`, `src/sqlguard/memory/`, `src/sqlguard/observability/` |
| Nguyễn Văn Hoàng Khang — Security & Threat Modeling | Threat model, SQL parsing/validation, security gate and policy, prompt-injection defenses, auditing and attack tests | `src/sqlguard/security/`, `docs/threat-model/`, `tests/security/` |
| Tiêu Trí Kiệt — Evaluation & Harness | Dataset/ground truth, evaluation harness, baselines and ablations, metrics, error analysis and reports | `src/sqlguard/evaluation.py`, `evaluation/`, evaluation tests |

## Shared contracts and parallel work

- The controller depends on `Planner`, `SecurityGate`, `ToolRegistry`, `MemoryStore`, and `EventSink` contracts; it should not import vendor-specific LLM or MCP clients.
- Architecture owns orchestration and execution state. Security owns decision semantics and security cases. Evaluation owns case formats and metric definitions. Cross-owner changes to a contract should be agreed and reviewed by the affected owners.
- Keep the mock planner/tool usable so ordinary tests remain offline and deterministic. Add integration tests separately when real adapters are introduced.
- Use benchmark examples that are synthetic or explicitly approved. Never place credentials or private user data in code, logs, fixtures, or reports.
- No D2 guidance was found in the initial workspace inspection. The team must verify the proposed defaults and interfaces against official course/project requirements when available.
