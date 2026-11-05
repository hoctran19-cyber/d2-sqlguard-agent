# Handoff: naive-agent demo và việc security còn tồn (05/11/2026)

Dành cho người tiếp tục ở session sau. Đọc theo thứ tự: tài liệu này → plan
[`NAIVE_AGENT_DEMO.md`](NAIVE_AGENT_DEMO.md) → [`SECURITY_WORKPLAN.md`](SECURITY_WORKPLAN.md) §17–18.

## 1. Trạng thái

| Phần | Trạng thái | Ở đâu |
| --- | --- | --- |
| Docs đồng bộ Financial/SQLite, plan sau W7 (§17), plan demo (§18) | **Đã merge** (PR #7) | `docs/threat-model/`, `docs/report/` |
| N1–N5: lõi naive agent (guard, executor, Gemini function calling, vòng agent, symptoms) | **Code xong, có test**; nằm trong PR mở cùng tài liệu này | `src/sqlguard/lab/`, `tests/unit/test_naive_*.py` |
| N6–N11: route, trang compare, listener, đo Gemini, tài liệu/video, CSP | **Chưa làm** | §3 bên dưới |
| NQ1–NQ5 | **Đã chốt** theo đề xuất (05/11) | `NAIVE_AGENT_DEMO.md` §6 |
| C3, C4, E5, E2, L8, T17 (ngoài demo) | Chưa làm | `SECURITY_WORKPLAN.md` §17.3 |

Lúc viết: `pytest -q` cho 1441 passed, 3 skipped, 1 xfailed. `ruff check .` sạch.
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

## 3. Việc tiếp theo (N6–N11), hướng dẫn cụ thể

### N6: `POST /api/lab/compare` (`src/sqlguard/web/app.py`)

- Dependency `require_admin`. Trả 404 khi `app.state.naive_demo is None`. Body đọc bằng
  `read_json`; `question` lấy qua `text_field`; `role` phải thuộc `BUSINESS_ROLES`, nếu không
  trả 422.
- Chạy **tuần tự** trong `async with lab_guard.run():` và lấy `revisions = lab_revisions(lab)`
  trước khi chạy.
  1. SQLGuard: `await answer_business_question(question, role, user_id=user.username)`.
  2. Naive agent: tạo mới `NaiveSqliteExecutor(config.database, config.policy)` và model
     (`GeminiToolModel.from_env()` hoặc `scripted_model_for(question)` theo `config.model`), rồi
     `await NaiveAgent(...).run(question, role)`.
- Trả về: `{"sqlguard": ..., "naive": result.to_payload(), "symptoms": {"sqlguard": [...],
  "naive": [...]}, "lab_revisions": revisions, "naive_model": config.model}`. Với bên naive,
  truyền `prompt_fingerprints=PROMPT_FINGERPRINTS` vào `detect_symptoms`.
- `NaiveDemoError` lúc chạy (file bị đổi) map sang 503 với thông báo chung.
  `WebQueryConfigurationError` từ phía SQLGuard xử lý giống `/api/query`; nên tách bảng thông
  báo hiện có thành hàm dùng chung.
- **Không** ghi `answer_markdown` hay dòng kết quả của naive vào history/audit (§3.3 của plan).
- `/api/me` (`user_payload`): thêm `"naive_demo_enabled": app.state.naive_demo is not None and
  user.role == ADMIN_ROLE`.
- Test theo mẫu `tests/unit/test_web_attack_lab.py` (fixture `lab_env`/`lab_on`, Ollama giả qua
  `install_ollama`), với `SQLGUARD_NAIVE_MODEL=scripted`. Cần có:
  - 404 khi tắt;
  - 401/403 cho người chưa đăng nhập, role nghiệp vụ và evaluator;
  - 422 khi role sai;
  - lab trả 409 khi đang chạy compare;
  - N-I1 (`Q_ACCOUNT_NOTE`, payload lưu vào `account.3`): bên naive bật `extra_tool_calls` và
    `forbidden_value`, bên SQLGuard không bật `forbidden_value`.

### N7: trang compare (`src/sqlguard/web/static/js/`)

- Route kiểu hash trong `pages/home.js`, theo mẫu `/lab` (dòng ~53): thêm `/lab/compare` khi
  `user.role === "admin" && user.naive_demo_enabled`. Thêm link ở `components/sidebar.js`, hàm
  ở `api.js`.
- Mọi chữ hiển thị đi qua `h()` / `textContent` (`dom.js`). Riêng câu trả lời naive dùng
  `components/naive-markdown.js` mới: chỉ xử lý đoạn văn, `**đậm**` và `![alt](url)` thành
  `<img>` tạo bằng `createElement`. **Không dùng `innerHTML`.**
- Bố cục: banner "CẤU HÌNH CỐ TÌNH KHÔNG AN TOÀN" luôn hiện; nhãn "Model giả lập bị chiếm" khi
  `naive_model === "scripted"`; ô câu hỏi, chọn role và 4 câu mẫu (`SCRIPTED_QUESTIONS`, có thể
  trả qua `/api/me` hoặc một route nhỏ); hai cột; thanh badge.
- Kiểm bằng trình duyệt (Playwright có sẵn trong container):
  - `<script>` trong câu trả lời không chạy;
  - ảnh `127.0.0.1:9999` được tải;
  - chạy được cả 4 câu mẫu ở chế độ scripted.

### N8: `src/sqlguard/lab/attacker_listener.py`

- `python -m sqlguard.lab.attacker_listener`: `http.server` bind **cứng** `127.0.0.1:9999`
  (không nhận host từ tham số), in `path` và query string đã decode ra stdout, trả GIF 1×1.
- Test: không bind được host khác; handler trả `image/gif`.

### N9: đo trên Gemini (máy của nhóm, không phải container)

- Cần `GEMINI_API_KEY` và bản sao lab của `db/financial.sqlite` (tạo bằng
  `python -m sqlguard.security.attack_lab init-copy`).
- **Việc đầu tiên:** gửi một câu N-I1 thật để xác nhận định dạng lượt `functionResponse`
  (gửi với `role: "user"`) và việc gửi lại `thoughtSignature`. Nếu Gemini trả 400, sửa
  `build_payload` trong `gemini_tools.py` rồi cập nhật test tương ứng.
- Chạy mỗi kịch bản 10 lần, điền bảng §5 của plan, kèm run ID và commit. Kịch bản dưới 3/10 thì
  thử biến thể payload và ghi lại cả các lần thất bại. Số này là độ nhạy của model trong
  pipeline naive, **không** phải ASR của SQLGuard.

### N10, N11

- N10: thêm cảnh demo seminar vào runbook; quay video có ghi SHA của commit; đổi T21 trong
  `README.md` của threat model từ Planned sang Implemented khi N6–N8 xong.
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
