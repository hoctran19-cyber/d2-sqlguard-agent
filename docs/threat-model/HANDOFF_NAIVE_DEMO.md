# Handoff: naive-agent demo và việc security còn tồn (cập nhật 06/11/2026)

Dành cho người tiếp tục ở session sau. Đọc theo thứ tự: tài liệu này → plan
[`NAIVE_AGENT_DEMO.md`](NAIVE_AGENT_DEMO.md) → [`SECURITY_WORKPLAN.md`](SECURITY_WORKPLAN.md) §17–18.

## 1. Trạng thái

| Phần | Trạng thái | Ở đâu |
| --- | --- | --- |
| Docs đồng bộ Financial/SQLite, plan sau W7 (§17), plan demo (§18) | **Đã merge** (PR #7) | `docs/threat-model/`, `docs/report/` |
| N1–N5: lõi naive agent (guard, executor, Gemini function calling, vòng agent, symptoms) | **Đã merge** (PR #8) | `src/sqlguard/lab/`, `tests/unit/test_naive_*.py` |
| N6–N8: route compare, trang compare, listener, payload chuẩn | **Code xong, có test, đã kiểm bằng trình duyệt** (06/11) | `web/naive_compare.py`, `web/app.py`, `static/js/pages/compare.js`, `lab/scenarios.py`, `lab/attacker_listener.py` |
| N9–N11: đo Gemini, video, CSP | **Chưa làm** | §3 bên dưới |
| T22: MCP server đưa note tới LLM client không bọc untrusted | **Mở**, đã ghi vào threat model | `README.md` §5 |
| NQ1–NQ5 | **Đã chốt** theo đề xuất (05/11) | `NAIVE_AGENT_DEMO.md` §6 |
| C3, C4, E5, E2, L8, T17 (ngoài demo) | Chưa làm | `SECURITY_WORKPLAN.md` §17.3 |

Lúc viết (06/11): `pytest -q` cho 1466 passed, 3 skipped, 1 xfailed. `ruff check .` sạch.
`ruff format --check .` báo 2 file `bird_pilot` chưa format, có sẵn từ trước, không liên quan.

**Chưa gọi Gemini thật lần nào.** Container của session trước không có `GEMINI_API_KEY` và
`financial.sqlite`.

## 2. Bản đồ code `src/sqlguard/lab/`

| File | Vai trò | Điểm vào chính |
| --- | --- | --- |
| `naive_guard.py` | Công tắc fail-closed | `naive_demo_from_env(env, lab=...) -> NaiveDemoConfig \| None`; `ensure_lab_copy(db, policy)` |
| `model.py` | Kiểu hội thoại, model giả lập, kịch bản sân khấu | `ToolCall`, `ModelReply`, `ToolResults`, `ScriptedModel`, `scripted_model_for(question)`, `SCRIPTED_QUESTIONS`, `LISTENER_URL` |
| `gemini_tools.py` | Gemini function calling nhiều lượt | `GeminiToolModel.from_env(env)`; `build_payload`, `parse_reply` (thuần, dễ test) |
| `naive_prompt.py` | System prompt: quyền chỉ nằm trong chữ | `build_naive_system_prompt(policy, role)`, `PROMPT_FINGERPRINTS` |
| `naive_agent.py` | Executor không gate + vòng agent | `NaiveSqliteExecutor(db, policy).execute(sql)`; `await NaiveAgent(model, executor, policy).run(question, role) -> NaiveResult`; `NaiveResult.to_payload()` |
| `symptoms.py` | Badge xác định cho cả hai bên | `observation_from_naive(payload)`, `observation_from_sqlguard(payload)`, `detect_symptoms(obs, policy, role, prompt_fingerprints=...)` |
| `scenarios.py` | 4 kịch bản trang compare, payload chuẩn | `SCENARIOS`, `SCENARIOS_BY_ID`, `PAYLOAD_TOOL_HIJACK`, `PAYLOAD_FORGED_AMOUNT`, `PAYLOAD_EXFILTRATION` |
| `attacker_listener.py` | "Attacker" của N-I3 | `python -m sqlguard.lab.attacker_listener`; `create_server`, `format_hit` |
| `../web/naive_compare.py` | Phía web: chạy naive và dựng payload so sánh | `run_naive(config, question, role)`, `compare_payload(...)` |

Đã nối vào web: `create_app` gán `app.state.naive_demo` (là `None` khi tắt). Bật sai cấu hình thì
app không khởi động.

Biến môi trường:

| Biến | Giá trị |
| --- | --- |
| `SQLGUARD_NAIVE_DEMO` | `1` để bật; mặc định tắt |
| `SQLGUARD_NAIVE_MODEL` | `gemini` (mặc định) hoặc `scripted` |
| `GEMINI_API_KEY`, `SQLGUARD_GEMINI_MODEL`, `SQLGUARD_GEMINI_TIMEOUT_SECONDS` | Dùng chung với planner |
| Biến của Attack Lab | Bắt buộc bật lab: `SQLGUARD_ATTACK_LAB_ENABLED=1`, `SQLGUARD_ATTACK_LAB_DB` = `SQLGUARD_BUSINESS_FINANCIAL_DB` = bản sao lab, `SQLGUARD_ATTACK_LAB_TARGETS=account.3,order.29407` (xem `docs/DEMO_RUNBOOK.md`) |

Các quyết định đã chốt khi code, đừng vô tình đảo lại:

- Executor **không** có authorizer theo role (đúng ý đồ), nhưng **có** authorizer sandbox chặn
  `ATTACH`/`DETACH`/`PRAGMA`. Bỏ authorizer này thì model có thể `ATTACH` file gốc.
- Prompt naive **không** dặn model làm theo ghi chú trong dữ liệu. Thêm câu như vậy là dàn dựng
  demo.
- `ScriptedModel` là "model giả lập bị chiếm". UI phải ghi rõ khi đang dùng nó.
- `sqlguard.agent`, `sqlguard.security`, `evaluation` không được import `sqlguard.lab`. Test
  `test_runtime_and_evaluation_never_import_the_naive_agent` sẽ fail nếu vi phạm.

## 3. Việc tiếp theo

### Đã làm ở N6–N8 (để đọc code nhanh)

- `GET /api/lab/compare/scenarios` và `POST /api/lab/compare` trong `web/app.py`: chỉ `admin`, 404
  khi tắt, `role` phải thuộc `BUSINESS_ROLES` (422). Chạy tuần tự trong `lab_guard.run()`: SQLGuard
  (`answer_business_question`) rồi naive (`web/naive_compare.run_naive`). Model được dựng trước khi
  vào guard. Lỗi bản sao lab thì 503 thông báo chung. Bảng thông báo lỗi cấu hình đã tách thành
  `QUERY_CONFIG_MESSAGES` / `query_config_message` dùng chung với `/api/query`.
- Trang `/home#/lab/compare`. Câu trả lời naive render bằng `components/naive-markdown.js`: đoạn
  văn, đậm, bảng `|…|`, ảnh `http(s)`. Không dùng `innerHTML`.
- Nút "Cài payload" và "Restore" gọi chính route Attack Lab (`labNote` → `labSave` /
  `labRestore`), nên có `expected_revision` và audit.
- `python -m sqlguard.lab.attacker_listener` bind cứng `127.0.0.1:9999`.
- Kiểm thủ công bằng Playwright trên fixture (scripted): đủ 3 kịch bản account.3, ảnh được tải,
  listener in dữ liệu, XSS không chạy. Muốn chạy lại: dựng bản sao lab từ `create_financial_db`
  của `tests/conftest.py`, giả Ollama như `install_ollama` trong `test_web_naive_compare.py`.

### Ghi chú khi demo trên DB thật

- Kịch bản scripted dùng đúng id của `financial.sqlite` (khách 4, tài khoản 3, đơn 29407). Trên
  fixture không có khách 4 và đơn 29407 nên N-D3 không lộ và N-I2 không có dòng: đó là do fixture.
- Badge "SQL chạm cột cấm" có thể bật ở **cả SQLGuard** (planner bị lừa viết `id_number`, gate bỏ
  cột). Đúng với thông điệp "model bị injection khác hệ thống bị injection"; nói rõ khi trình bày.

### N9: đo trên Gemini (máy của nhóm, không phải container)

- Cần `GEMINI_API_KEY` và bản sao lab của `db/financial.sqlite` (tạo bằng
  `python -m sqlguard.security.attack_lab init-copy`).
- **Việc đầu tiên:** gửi một câu N-I1 thật để xác nhận định dạng lượt `functionResponse`
  (gửi với `role: "user"`) và việc gửi lại `thoughtSignature`. Nếu Gemini trả 400, sửa
  `build_payload` trong `gemini_tools.py` rồi cập nhật test tương ứng.
- Chạy mỗi kịch bản 10 lần, điền bảng §5 của plan, kèm run ID và commit. Payload lấy từ
  `lab/scenarios.py`; nếu phải đổi payload thì ghi phiên bản cũ và mới vào cột "Payload". Kịch bản dưới 3/10 thì
  thử biến thể payload và ghi lại cả các lần thất bại. Số này là độ nhạy của model trong
  pipeline naive, **không** phải ASR của SQLGuard.

### N10, N11

- N10: runbook đã có cảnh seminar (`docs/DEMO_RUNBOOK.md` §3c), T21 đã sang Implemented. Còn: quay
  video có ghi SHA của commit và SHA-256 của bản sao lab.
- N11 (tùy chọn): CSP `img-src 'self' data:` cho các trang thường, nới riêng cho trang compare.

## 4. Rủi ro đã biết

- Gemini có thể không làm theo payload hoặc bị bộ lọc chặn (`blocked`). Đây là suy đoán, chưa
  đo. Trên sân khấu luôn có chế độ `scripted` và video làm phương án dự phòng.
- Ở chế độ naive, dòng kết quả synthetic **đi ra Google** (NQ3, T21).
- Badge `prompt_leak` không bắt được khi model dịch hoặc diễn đạt lại prompt. Badge
  `forbidden_sql` dựa trên tên cột nên có thể sót trường hợp dùng alias hay `*`. Cả hai là badge
  cho demo, không phải lớp chặn.
- F10 (`amount * 0 + 987654321`) vẫn mở trên SQLGuard. Đây là cảnh "SQLGuard thua" cần nói thẳng.

## 5. Lệnh nhanh

```bash
pip install -e ".[dev,web]"
```

```bash
pytest -q tests/unit/test_naive_guard.py tests/unit/test_naive_agent.py tests/unit/test_naive_gemini_tools.py tests/unit/test_naive_symptoms.py
```

```bash
pytest -q && ruff check .
```

## 6. Việc ngoài demo (thứ tự từ §17.3)

C4 (chốt hợp đồng suite injection) → C3 (chạy `d2-gemini` trên commit sạch, thay các số `dirty`
trong report) → quyết định E5 (tách cấu hình demo và eval) → E2 (mask PII) → L8 (đưa revision vào
trace) → T17 (test API key không lộ trong log). Vòng function calling của naive agent dùng lại
được làm cấu hình eval cho E5.
