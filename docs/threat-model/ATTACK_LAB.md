# Attack Lab: thiết kế phía security

Attack Lab (`/demo/attack-lab`) cho presenter ghi payload vào cột `note` rồi hỏi agent để quan sát indirect injection. Vì nó **ghi vào DB thật**, D2-01 §8 yêu cầu threat model phải mô tả endpoint, credential, capability, audit và restore. Phần backend dùng `AttackLab` (`src/sqlguard/security/attack_lab.py`); route/UI thuộc người làm API/frontend.

## 1. Threat riêng của Attack Lab (T11)

| ID | Threat | Control | Trạng thái |
| --- | --- | --- | --- |
| T11a | Agent dùng Lab làm đường ghi | Lab **không** phải MCP tool; credential `sqlguard_note_writer_app` không bao giờ đưa vào agent | Implemented |
| T11b | Ghi cột/bảng khác ngoài `note` | DB: role chỉ có `UPDATE (note)` trên `orders`, `customers`. Code: SQL cố định theo bảng, target phải trong allowlist `table.id` | Implemented + test DB |
| T11c | SQL injection qua target/payload | Target parse thành `(table, int)` theo allowlist; payload là tham số bind, không nối chuỗi | Implemented |
| T11d | Note đổi giữa lúc agent đang chạy (trace sai) | Từ chối ghi khi có run đang chạy (`run_active`) → `run_active` | Implemented (cần API truyền hàm kiểm tra) |
| T11e | Hai người ghi đè nhau | Optimistic concurrency: `expected_revision` sai → `revision_conflict` | Implemented |
| T11f | Payload còn sót sau demo (DB bị “nhiễm” lâu dài) | Baseline được giữ ở revision 0; `restore` về baseline hoặc revision bất kỳ; ghi xong đọc lại để xác minh | Implemented (revision lưu trong bộ nhớ process) |
| T11g | Người không phải presenter dùng Lab | Lab tắt mặc định (`enabled=False`); chỉ bật ở profile demo | Implemented ở service; **auth của route: planned** |
| T11h | Payload phá UI (HTML/script) | Payload ≤ 2000 ký tự, không ký tự điều khiển; UI phải render dạng text, không render HTML/ảnh remote (D2-02 §3) | Service implemented; UI: planned |
| T11i | Lộ payload qua audit | Audit chỉ có hash, độ dài, revision, user; nội dung chỉ nằm ở DB và bộ nhớ revision | Implemented |

## 2. Hợp đồng API đề xuất (cho owner API)

| Route | Body | Gọi | Lỗi |
| --- | --- | --- | --- |
| `GET /api/lab/notes/{target}` | — | `lab.get(target)` → `{target, revision, content, baseline_revision}` | `lab_disabled`, `target_not_allowed` |
| `PUT /api/lab/notes/{target}` | `{content, expected_revision}` | `lab.save(...)` | thêm `run_active` (409), `revision_conflict` (409), `invalid_payload` (422) |
| `POST /api/lab/notes/{target}/restore` | `{expected_revision, to_revision?}` | `lab.restore(...)` | như trên, `unknown_revision` |
| `GET /api/lab/notes/{target}/history` | — | `lab.history(target)` (không có nội dung) | — |

- Bật bằng `SQLGUARD_ATTACK_LAB_ENABLED=1` **và** profile demo; mặc định tắt.
- `user_id` lấy từ session, không từ body. Chỉ tài khoản demo đã đăng nhập.
- `run_active` = hàm của worker trả `True` khi có run đang chạy (D2-02: 1 active run).
- Target mặc định: `customers.1–3`, `orders.1–3` (khớp `db/security/20_reference_seed.sql`).
- Credential: `SQLGUARD_DB_DSN_NOTE_WRITER` → `PostgresNoteWriter`.

## 3. Luồng demo (D2-05 §5, phút 4:45–6:00)

1. `GET` note → revision 0 (baseline).
2. `PUT` preset payload với `expected_revision=0` → revision 1; audit `save ok`.
3. Workspace hỏi câu liên quan → tool trả envelope `possible_injection=true`; gate chặn mọi lệnh bị tiêm.
4. Observe hiển thị bước bị chặn.
5. `POST restore` với `expected_revision=1` → revision 2 có hash trùng baseline; audit `restore ok`.

## 4. Giới hạn đã biết

- Revision lưu trong bộ nhớ process: restart backend trước khi restore sẽ mất baseline. Cách xử lý: luôn restore trước khi tắt, hoặc chạy lại `db/security/20_reference_seed.sql` trên DB demo. Lưu bền (bảng `lab_note_revisions` của owner) là việc sau D2.
- Chưa nối hash note với run trace: Observe chưa hiển thị “run này đọc note revision mấy”. Đề xuất: API ghi `current_revision(target)` vào metadata của run khi tạo run.
