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
from sqlguard.security.audit import JsonlAuditSink
from sqlguard.security.gate import PolicySQLGate, SecurityContext
from sqlguard.security.postgres import PostgresExecutor
from sqlguard.security.schema import SchemaTool
from sqlguard.security.service import SecureSqlTool

# role lấy từ session đã xác thực (API), KHÔNG từ request body, KHÔNG từ LLM.
context = SecurityContext(role=session.role, user_id=session.user_id, run_id=run_id,
                          request_mode="nl")          # "manual_sql" cho tab SQL thủ công
audit = JsonlAuditSink("artifacts/audit/security.jsonl")
gate = PolicySQLGate(context, audit=audit)            # controller pre-check, ghi mọi quyết định
tools = InProcessToolRegistry([
    SecureSqlTool(PolicySQLGate(context), PostgresExecutor.from_env(), audit=audit),
    SchemaTool(context),
])
controller = AgentController(planner=..., tools=tools, security_gate=gate, ...)
```

- **Mỗi run tạo tool/gate mới** (đếm attempt và audit theo run).
- `run_id`: hiện `AgentState` tự sinh `run_id`, nên audit không nối được với events. Đề nghị: cho `AgentRequest` mang `run_id` (do API tạo) hoặc cho controller nhận `run_id` từ ngoài. Đây là thay đổi phía anh.
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
| `db_timeout`, `db_permission_denied`, `db_read_only_violation` | DB chặn hoặc quá thời gian | Không retry cùng SQL; có thể cho planner một lần sửa nếu là `db_schema_error`/`db_syntax_error` |

Mọi SQL mới (kể cả do repair) **phải** qua gate lần nữa. Controller hiện tại đã làm đúng điều này.

## 5. Trước khi trả answer

```python
from sqlguard.security.service import find_leaks
if find_leaks(final_answer, policy, context.role):
    # không trả answer; status REFUSED/FAILED, error_category="canary_leak"
```

Đề nghị thêm vào event (vẫn metadata-only): `decision_kind`, `violation_codes`, `policy_version`, `repairable`.

## 6. Manual SQL mode

Tab SQL thủ công gọi thẳng `SecureSqlTool.call({"sql": sql}, timeout_seconds=3)` với `SecurityContext(request_mode="manual_sql")`: cùng gate, cùng grants, cùng audit, không gọi LLM, không reflection.

## 7. Test để chạy sau khi ghép

```bash
pytest -q tests/security/test_controller_security.py   # controller + gate + tool
pytest -q tests/security                                # toàn bộ security, offline
```
