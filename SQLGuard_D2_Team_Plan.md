# SQLGuard D2 — Phân công nhóm và kế hoạch triển khai

> Tài liệu lập kế hoạch dựa trên source `d2-sqlguard-agent-main` và yêu cầu D2 đã cung cấp.  
> Lưu ý: trạng thái bên dưới phản ánh những gì đã kiểm tra/trao đổi; các chức năng cần được nghiệm thu bằng code chạy thực tế và artifacts.

## 1. Đánh giá tổng thể source hiện tại

Repository đã có nền tảng Agent với controller, security gate cơ bản và evaluation runner. Tuy nhiên, đây chưa phải hệ thống SQLGuard D2 hoàn chỉnh: luồng demo còn sử dụng planner xác định trước và tool giả lập, chưa chứng minh được LLM thật và PostgreSQL thật chạy end-to-end.

**Định hướng:** giữ lại phần khung hiện có, hoàn thiện tích hợp và kiểm chứng; không viết lại toàn bộ từ đầu.

## 2. Phân loại các thành phần source

| Thành phần / file | Trạng thái hiện tại | Hướng xử lý |
|---|---|---|
| `src/sqlguard/agent/controller.py` | Có vòng đời run, giới hạn budget, điều phối và xử lý lỗi | Giữ lại; hoàn thiện repair loop và tích hợp thật |
| `src/sqlguard/agent/models.py` | Có model trạng thái và budget | Giữ lại; bổ sung trường cho evaluation nếu cần |
| `src/sqlguard/agent/planning.py` | Có `Planner` protocol và `DemoPlanner` trả SQL cố định | Bổ sung adapter LLM thật |
| `src/sqlguard/mcp/tools.py` | Có `ToolRegistry` và `MockQueryTool` | Bổ sung PostgreSQL tool và MCP theo phạm vi D2 |
| `src/sqlguard/security/gate.py` | Có kiểm tra một câu `SELECT`, tùy chọn allowlist bảng | Mở rộng kiểm tra quyền theo role, cột và dialect PostgreSQL |
| `src/sqlguard/memory/store.py` | Có `InMemoryMemory`, lưu theo run | Bổ sung semantic memory bền vững; hoàn thiện TTL và retention |
| `src/sqlguard/observability/events.py` | Có event sink cấu trúc trong bộ nhớ | Nối với trace lưu bền vững và giao diện Observe |
| `src/sqlguard/evaluation.py` | Có runner cơ bản, ghi status, pass/fail và latency | Mở rộng benchmark, gold results, metrics và xuất artifacts |
| `tests/` | Có unit tests và security tests cho nền tảng hiện tại | Giữ lại; bổ sung integration và regression tests |
| `docs/` | Có tài liệu kiến trúc, interfaces, threat model và evaluation ban đầu | Cập nhật theo implementation thật, không chỉ mô tả thiết kế |

## 3. Phân công chính thức

### Người 1: Học — Agent Architecture & Runtime

**Mục tiêu:** Làm cho Agent thực sự xử lý câu hỏi, sinh SQL, thực thi, nhận lỗi và sửa lỗi.

**Các file chính**
- `src/sqlguard/agent/`
- `src/sqlguard/mcp/`
- `src/sqlguard/memory/`
- `src/sqlguard/observability/`

#### H1. Thay `DemoPlanner` bằng LLM adapter
File: `src/sqlguard/agent/planning.py` và adapter mới nếu cần.

- Giữ `Planner` protocol để tránh phụ thuộc provider trong Controller.
- Tạo adapter gọi LLM thật, cấu hình model bằng biến môi trường.
- Đưa schema được phép, câu hỏi và semantic memory phù hợp vào context.
- Chuẩn hóa output thành `Plan`; xử lý output sai định dạng, timeout và lỗi provider.

#### H2. Thay `MockQueryTool` bằng database adapter
File: `src/sqlguard/mcp/tools.py` và module PostgreSQL mới.

- Kết nối PostgreSQL local bằng tài khoản quyền tối thiểu.
- Chỉ thực thi truy vấn sau khi Security Gate chấp thuận.
- Trả kết quả có cấu trúc thay cho dữ liệu giả như `demo_value=1`.
- Giới hạn thời gian, số dòng và kích thước dữ liệu trả về.
- Tách PostgreSQL adapter và MCP transport nếu nhóm triển khai MCP server riêng.

#### H3. Hoàn thiện Reflection và budget
File: `src/sqlguard/agent/controller.py`, `models.py`.

- Khi DB trả lỗi có thể sửa, gửi observation cho planner để sinh SQL mới.
- Mỗi SQL mới phải qua Security Gate lần nữa.
- Phân biệt lỗi cú pháp, schema, quyền và mất kết nối.
- Không retry khi bị từ chối vì bảo mật.
- Thực thi đúng giới hạn: tối đa 3 SQL attempts, 6 LLM calls, 8 tool calls, SQL timeout 3 giây, run timeout 60 giây, tối đa 100 dòng/64 KiB.

#### H4. Hoàn thiện Memory và trace
File: `src/sqlguard/memory/store.py`, `src/sqlguard/observability/events.py`.

- Short-term memory lưu context theo run và có TTL.
- Semantic memory có 8–12 định nghĩa nghiệp vụ đã duyệt, versioned và lọc theo role.
- Trace phản ánh các bước Retrieve Schema, Generate SQL, Validate Gate, Execute, Observe/Repair và Answer.
- Không ghi API keys, credentials hay Chain-of-Thought vào log.

**Tiêu chí nghiệm thu**
- Một câu hỏi hợp lệ chạy qua LLM và PostgreSQL thật, trả kết quả đúng.
- Một lỗi SQL được sửa thành công hoặc kết thúc đúng theo contract lỗi.
- SQL không hợp lệ/không được phép không tới database tool.
- Trace thể hiện bước và kết quả runtime thực tế.
- Có integration tests với database test, tách biệt unit tests offline.

---

### Người 2: Khang — Security & Threat Modeling

**Mục tiêu:** Chứng minh quyền được thực thi thật và các tấn công bị ngăn chặn.

**Các file chính**
- `src/sqlguard/security/`
- `tests/security/`
- `docs/threat-model/`

#### K1. Chốt permission policy
- Lập permission matrix cho `Sales`, `Finance`, `Operations`.
- `identity_number`: cấm cả ba role.
- `phone_number`: chỉ Operations.
- `unit_cost_vnd` và `bank_reference`: chỉ Finance.
- Operations không được truy cập bảng `payments`.

#### K2. Mở rộng AST Security Gate
- Kiểm tra table/column references, alias, CTE, nested query, multi-statement và các trường hợp bypass.
- Dùng dialect PostgreSQL và kiểm thử với SQL thực tế.
- Chính sách deny-by-default; không dựa vào prompt để bảo vệ quyền.

#### K3. Lớp chặn độc lập ở database (SQLite)
- Cập nhật 21/10: nhóm dùng SQLite + BIRD Financial, bỏ PostgreSQL; grants PostgreSQL không còn dùng.
- Dùng `sqlite3` authorizer trong executor để chỉ cho đọc bảng/cột mà role được phép, chặn PRAGMA, ATTACH, ghi và hàm ngoài allowlist.
- Kiểm tra executor từ chối truy cập trái phép kể cả khi tắt application gate.

#### K4. Kiểm thử injection
- Hai direct injection: D2-I01, D2-I02.
- Hai indirect injection qua dữ liệu `note`: D2-I03, D2-I04.
- Ghi rõ attacker goal, expected behavior, kết quả thực tế và trace.
- Kiểm tra SQL sinh ra sau repair cũng phải qua Security Gate.

#### K5. Audit và Threat Model v1
- Cập nhật threat model theo triển khai thật.
- Ghi các đường tấn công, tài sản, giả định, biện pháp kiểm soát và hạn chế.
- Thêm regression tests cho mỗi bypass hoặc lỗi bảo mật được phát hiện.

**Tiêu chí nghiệm thu**
1. Permission matrix được chốt và có test.
2. SQL bị cấm bị chặn trước khi gọi tool.
3. PostgreSQL tự chặn truy cập trái phép nếu application gate không chặn.
4. Bốn injection cases có kết quả, trace và kết luận.
5. Threat Model v1 và remediation được bàn giao.

**Lưu ý kỹ thuật (cập nhật 21/10):** `PolicySQLGate` hiện parse và normalize bằng dialect `postgres`, trong khi database đã chốt là SQLite (BIRD Financial). Cần chuyển gate sang dialect `sqlite` và viết lại policy cho schema Financial. Kế hoạch chi tiết: `docs/threat-model/SECURITY_WORKPLAN.md` §12.

---

### Người 3: Kiệt — Evaluation & Harness

**Mục tiêu:** Định lượng khả năng hoàn thành truy vấn, bảo mật, khả năng phục hồi và chi phí.

**Các file chính**
- `src/sqlguard/evaluation.py`
- `evaluation/`
- `tests/unit/test_evaluation.py` và các test liên quan

#### T1. Chuẩn bị task manifest và gold data
Tạo 20 task IDs, mỗi task có câu hỏi, role, expected behavior, gold result và nhãn bảo mật.

| Nhóm | Task IDs | Số task |
|---|---|---:|
| Legitimate | D2-L01 đến D2-L10 | 10 |
| Pure Auth | D2-A01, D2-A02 | 2 |
| Mixed | D2-M01, D2-M02 | 2 |
| Injection | D2-I01 đến D2-I04 | 4 |
| Induced Failure | D2-F01, D2-F02 | 2 |
| **Tổng** | | **20** |

#### T2. Hoàn thiện runner
- Chạy `d2-agent` với tối đa 3 SQL attempts.
- Chạy `d2-no-reflection` với tối đa 1 SQL attempt.
- Giữ nguyên model, data, schema, memory, AST Gate và DB grants giữa hai cấu hình.
- Chạy 3 lần cho mỗi task/configuration.
- Ghi per-task result, status, metrics, trace reference và usage.

#### T3. Xây dựng metrics
- Legitimate Success Rate.
- Pure-Auth Refusal Rate.
- Partial Success Rate.
- Unauthorized Access Rate / Disclosure.
- Attack Success Rate.
- Recovery Rate cho F01.
- Robust failure handling cho F02.
- Latency, input/output tokens, số lần gọi và chi phí.

Không chỉ dùng `status == succeeded`: cần so kết quả với gold result/semantics và kiểm tra hành vi bảo mật theo tiêu chí đã chốt trước.

#### T4. Sinh artifacts
Mục tiêu cho bộ đánh giá D2:

```text
artifacts/d2/<experiment-id>/
  manifest.json
  results.jsonl
  clean-pairs.jsonl
  usage.jsonl
  traces/
  summary.csv
  error-analysis.md
  cost-report.md
```

- 20 task IDs × 2 configurations × 3 runs = 120 main task-runs.
- 12 clean counterpart task-runs bổ sung.
- Tổng mục tiêu: 132 task-runs, chưa tính smoke tests.

#### T5. Phân tích lỗi và báo cáo
- Phân loại lỗi: SQL parse/unsupported, SQL logic, false rejection, wrong partial, unauthorized access, injection contamination, timeout/budget, infrastructure và model format.
- Báo raw counts cùng mean ± sample standard deviation qua 3 runs.
- Ghi rõ task nào chưa chạy, usage nào unknown và hạn chế của mẫu nhỏ.
- Không tạo số liệu giả để lấp chỗ trống.

**Tiêu chí nghiệm thu**
- Runner chạy được hai cấu hình trên snapshot cố định.
- Kết quả truy vết được về task, run, commit, model và policy.
- Có `summary.csv`, `error-analysis.md`, `cost-report.md`.
- Báo cáo phân biệt rõ kết quả thực nghiệm với giới hạn hiện tại.

---

## 4. Lịch phối hợp đề xuất

> Lịch dưới đây là kế hoạch từ 18/10 đến 28/10/2026, không phải xác nhận rằng các mốc đã hoàn thành.

| Ngày | Học — Agent | Khang — Security | Kiệt — Evaluation | Mốc chung |
|---|---|---|---|---|
| 18/10 | Chốt interfaces, Planner/Tool contracts | Chốt permission matrix và policy contract | Chốt manifest, gold-result và metrics format | Thống nhất schema, error codes, output format |
| 19–20/10 | Tích hợp LLM, PostgreSQL, memory và repair loop | Hoàn thiện gate, grants và security tests | Tạo 20 task IDs, gold data, runner | Các module có test riêng |
| 21/10 | Ghép luồng end-to-end | Kiểm thử quyền trên luồng tích hợp | Chạy smoke tests và xác nhận artifacts | Một legit, một auth, một failure chạy được |
| 22–23/10 | Sửa lỗi runtime, trace và budget | Chạy 4 injection cases, regression tests | Chạy benchmark hai configs và clean pairs | Bảo toàn traces, logs và usage |
| 24/10 | Hỗ trợ fix lỗi tích hợp | Chốt Threat Model v1 và remediation | Chốt metrics, error analysis và cost report | Chốt số liệu có thể kiểm chứng |
| 25/10 | Cung cấp sơ đồ và bằng chứng runtime | Cung cấp bảng policy và injection evidence | Cung cấp bảng kết quả và artifacts | Nộp PDF 4–6 trang trước 23:59 |
| 26–27/10 | Ổn định luồng demo | Xác minh demo an toàn, Save/Restore | Chuẩn bị bảng số liệu và video backup | Diễn tập demo 8 phút |
| 28/10 | Trình bày luồng Agent | Trình bày security và attack case | Trình bày evaluation và first numbers | Live demo checkpoint |

## 5. Quy tắc GitHub và tích hợp

| Nhánh | Owner | Phạm vi |
|---|---|---|
| `feature/agent-runtime` | Học | Controller, planning, memory, tools, events |
| `feature/security-policy` | Khang | Gate, policy, security tests, threat model |
| `feature/evaluation-harness` | Kiệt | Runner, datasets, metrics, artifacts |
| `main` | Cả nhóm | Chỉ nhận code đã review và test đạt |

Quy tắc phối hợp:

- Không cùng sửa file cốt lõi nếu chưa thống nhất với owner.
- Thay đổi interface Controller, ToolRegistry hoặc SecurityGate phải được bên liên quan review.
- Unit tests phải tiếp tục chạy offline và deterministic.
- Integration tests với PostgreSQL/LLM được tách riêng.
- Không commit `.env`, API keys, credentials, dữ liệu nhạy cảm hoặc log chứa bí mật.
- Mỗi benchmark phải gắn với commit, phiên bản dataset, model và policy tương ứng.
- Khi thay đổi interface, cập nhật tài liệu và test trong cùng pull request.

## 6. Checklist nghiệm thu D2

### Agent Architecture — Học
- [ ] LLM thật được gọi qua Planner adapter.
- [ ] PostgreSQL thực thi SQL qua tool adapter.
- [ ] Reflection sửa lỗi và kiểm tra lại SQL.
- [ ] Memory và runtime trace hoạt động thật.

### Security — Khang
- [ ] Permission matrix theo role được chốt.
- [ ] AST gate kiểm tra đúng dialect PostgreSQL.
- [ ] DB grants độc lập chặn truy cập trái phép.
- [ ] Bốn injection cases có trace và kết luận.

### Evaluation — Kiệt
- [ ] 20 task IDs có gold behavior/result.
- [ ] Hai cấu hình dùng chung model và policy.
- [ ] Runner sinh kết quả cho từng lượt.
- [ ] Có `summary.csv` và `cost-report.md`.

### Delivery — Cả nhóm
- [ ] 12 clean counterparts được đánh giá.
- [ ] Threat Model v1 và phân tích lỗi hoàn chỉnh.
- [ ] PDF báo cáo 4–6 trang.
- [ ] Demo 8 phút và video backup offline.

**Nguyên tắc nghiệm thu:** đánh dấu hoàn thành khi có bằng chứng chạy thực tế, test hoặc artifacts tương ứng; không chỉ dựa vào việc đã viết code.

## 7. Kết luận

Giữ nguyên phân công theo chuyên môn:

- **Học:** làm cho Agent chạy end-to-end và có thể quan sát.
- **Khang:** chứng minh security được thực thi ở cả application và database.
- **Kiệt:** chứng minh hiệu quả bằng benchmark có thể tái lập.

Ưu tiên chung là thống nhất interfaces ngay, tích hợp sớm, chạy security regression và benchmark trước khi dành thời gian polish giao diện. Mục tiêu không phải chỉ có một demo chạy được, mà là có hệ thống chạy thật cùng bằng chứng đủ để bảo vệ các tuyên bố trong báo cáo D2.
