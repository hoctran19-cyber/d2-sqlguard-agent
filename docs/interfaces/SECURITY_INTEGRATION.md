# Bàn giao security → agent runtime (Khang → Học)

Mục đích: anh Học nối các thành phần security vào controller/planner **mà không phải viết lại logic bảo mật**. Mọi thứ dưới đây đã có test trong `tests/security/`. Phần security không sửa file nào trong `src/sqlguard/agent/`, `mcp/`, `memory/`, `observability/`; quyết định cách ghép là của anh.

## 1. Tóm tắt những gì có sẵn

| Cần cho | Dùng | File |
| --- | --- | --- |
| Tool `execute_sql` (H2) | `SecureSqlTool(gate, PostgresExecutor.from_env(), audit=...)`. Tên tool mặc định là `query` cho khớp controller hiện tại; truyền `name="execute_sql"` nếu đổi | `security/service.py`, `security/postgres.py` |
| Tool `get_schema` | `SchemaTool(context)`: schema lọc theo role, có thể thu hẹp theo `query` | `security/schema.py` |
| Gate trước khi gọi tool | `PolicySQLGate(context, audit=...)`: tương thích `SecurityGate.check(sql)` | `security/gate.py` |
| System prompt + bọc dữ liệu (H1) | `build_system_prompt`, `render_user_question`, `render_tool_result`, `render_denial` | `security/prompting.py` |
| Reflection (H3) | `SecurityDecision.repairable`, `SecurityToolError.decision` | `security/gate.py`, `service.py` |
| Kiểm tra câu trả lời cuối | `find_leaks(answer, policy, role)` | `security/service.py` |
| Audit | `JsonlAuditSink(path)` | `security/audit.py` |

## 2. Tạo một run

```python
from sqlguard.agent.controller import AgentController, RunScope
from sqlguard.agent.runtime import build_query_runtime_factory

# role lấy từ cấu hình/session đã xác thực, KHÔNG từ request body, KHÔNG từ LLM.
# Factory dựng PostgresExecutor theo DSN riêng của role (SQLGUARD_DB_DSN_<ROLE>).
factory = build_query_runtime_factory(role, env, audit=audit)

def run_scope(run_id: str) -> RunScope:
    built = factory.for_run(run_id)  # SecurityContext + gate + SecureSqlTool mới cho từng run
    return RunScope(
        built.gate, InProcessToolRegistry([built.tool]), output_check=built.output_check
    )

controller = AgentController(planner=..., tools=..., security_gate=..., run_scope_factory=run_scope, ...)
```

- **Mỗi run tạo tool/gate mới** (đếm attempt và audit theo run).
- `run_id`: controller gọi `run_scope_factory(state.run_id)` cho mỗi request, nên `SecurityContext`, audit và events dùng cùng `run_id` của `AgentState`.
- Biến môi trường DB: `SQLGUARD_DB_DSN_SALES`, `SQLGUARD_DB_DSN_FINANCE`, `SQLGUARD_DB_DSN_OPERATIONS` (login role `sqlguard_*_app`, xem `db/security/README.md`).

## 3. Planner: dựng messages

```python
from sqlguard.security.policy import load_default_policy
from sqlguard.security.prompting import (build_system_prompt, render_denial,
                                         render_tool_result, render_user_question)

policy = load_default_policy()
messages = [
    {"role": "system", "content": build_system_prompt(policy, context.role, query=question,
                                                       output_format=YOUR_JSON_FORMAT)},
    {"role": "user", "content": render_user_question(question)},
]
# Sau mỗi tool call:
messages.append({"role": "tool", "content": render_tool_result(envelope)})   # rows nằm trong block untrusted
# Sau mỗi lần gate từ chối:
messages.append({"role": "tool", "content": render_denial(decision)})
```

Quy tắc:
- **Không** đưa role vào tham số tool; `SecureSqlTool` và `SchemaTool` từ chối mọi tham số ngoài `sql` / `query` (`invalid_tool_input`).
- **Không** ghép nội dung tool/note vào system prompt; luôn qua `render_tool_result` (có nonce chống giả mạo thẻ đóng).
- `PROMPT_VERSION` trong `prompting.py` nên được ghi cùng config của mỗi lần chạy evaluation.

## 4. Reflection và điều kiện dừng (H3)

| Tín hiệu | Ý nghĩa | Controller nên làm |
| --- | --- | --- |
| `decision.allowed` và `kind == "allow_partial"` | Gate đã tự bỏ cột hiển thị bị cấm | Chạy tiếp; answer phải nêu `removed_columns` |
| `not decision.allowed and decision.repairable` | Cú pháp/schema/subset chưa hỗ trợ, **hoặc** `column_forbidden_narrowable` (cột cấm chỉ ở phần hiển thị/GROUP BY) | Gửi `render_denial(decision)` cho planner, sinh SQL mới, tính vào 3 SQL attempts |
| `not decision.allowed and not decision.repairable` | Vi phạm chính sách (ghi, catalog, hàm cấm, cột cấm ở WHERE/ORDER BY/JOIN/HAVING, bảng cấm) | `REFUSED` ngay, không gọi planner lại |
| `SecurityToolError` từ tool | Gate ở execute boundary chặn (khi pre-check yếu hơn) | Như hàng trên, đọc `error.decision` |
| `ToolError.category == "canary_leak"` | Output check giữ lại kết quả | Dừng, `FAILED`/`REFUSED`, không retry |
| `db_timeout`, `db_permission_denied`, `db_read_only_violation`, `db_error` | DB chặn, quá thời gian hoặc lỗi khác | Dừng `FAILED`, không retry cùng SQL, không gọi planner |
| `db_schema_error`, `db_syntax_error` | SQL đã qua gate nhưng DB không chấp nhận | Controller cho planner **đúng một lần sửa mỗi run** (chỉ gửi mã lỗi cố định, không gửi lỗi DB thô); SQL mới qua gate lại và tính vào budget. Vẫn lỗi thì `FAILED` |
| `db_unavailable` (retryable) | DB không kết nối được | Retry cùng SQL tối đa `max_retries`, không gọi planner |

Mọi SQL mới (kể cả do repair) **phải** qua gate lần nữa. Controller hiện tại đã làm đúng điều này.

## 5. Trước khi trả answer

Controller tự kiểm tra câu trả lời cuối qua `RunScope.output_check`. Với `QueryRuntime` truyền `output_check=built.output_check`: hàm này dùng `find_leaks` với role lấy từ `SecurityContext` tin cậy của run (không bao giờ từ câu hỏi hay model).

- Phát hiện canary: không trả answer, run `FAILED` với `failure_reason="canary_leak"`, event `output_check_completed` (`status="blocked"`) và một audit record `phase="output"`, `outcome="blocked"`; cả hai chỉ có metadata, không có giá trị bị rò.
- Bước kiểm tra hoặc ghi audit của nó lỗi: chặn answer, `failure_reason="output_check_error"` (fail closed).
- Nếu không truyền `output_check` (chế độ mock) thì không kiểm tra thêm; lớp chặn chính vẫn là output check bên trong `SecureSqlTool`.

## 6. Manual SQL mode

Tab SQL thủ công gọi thẳng `SecureSqlTool.call({"sql": sql}, timeout_seconds=3)` với `SecurityContext(request_mode="manual_sql")`: cùng gate, cùng grants, cùng audit, không gọi LLM, không reflection.

## 7. Test để chạy sau khi ghép

```bash
pytest -q tests/security/test_controller_security.py   # controller + gate + tool
pytest -q tests/security                                # toàn bộ security, offline
```
