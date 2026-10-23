# Initial architecture decisions and open questions

## Provisional decisions

1. **Python and dataclasses/Protocols:** keep the starter dependency-light beyond SQL parsing and keep component contracts replaceable.
2. **Asynchronous controller:** use coroutine-compatible planner/tool interfaces so future network adapters can be bounded by timeouts.
3. **Fail-closed read-only SQL baseline:** parse with SQLGlot and allow one `SELECT`; this is a baseline, not a complete authorization engine.
4. **Mock-first operation:** provide a deterministic demo with no API key, MCP service, or database requirement.
5. **In-process short-term memory and metadata-only events:** avoid introducing persistent sensitive-data retention before requirements exist.
6. **Configurable provisional budgets:** defaults are copied from the task brief, not verified against official D2 material.

## Team decisions still needed

- Confirm official project/course constraints, database dialect, schema access, deployment, and D2 requirements.
- Select LLM provider and clarify whether planner calls and retries count per attempt.
- Select MCP protocol/library and define tool schemas, authentication, cancellation, and timeout behavior.
- Define tenant/user authorization, allowed schemas/tables/functions, data redaction, and threat-model acceptance criteria.
- Define whether query repair may regenerate SQL and require a new security decision for every generated statement.
- Set memory retention and event-sink policies after privacy requirements are known.
- Specify benchmark source/licensing, ground truth, metric definitions, baselines, and reproducibility protocol.
- Phê duyệt schema business role chuẩn, quyền truy cập và các kiểm soát tổng hợp của analyst trước khi bật SQL; xem [Thiết kế policy và thống nhất schema cho business role](./BUSINESS_ROLE_POLICY_DESIGN.md).
