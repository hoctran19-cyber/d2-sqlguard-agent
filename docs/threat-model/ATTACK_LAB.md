# Attack Lab: thiết kế phía security (SQLite)

Cập nhật 24/10/2026: bỏ PostgreSQL. Attack Lab chỉ ghi vào **bản sao lab** của
`db/financial.sqlite` theo policy `business_financial_v1`. Bản PostgreSQL (`PostgresNoteWriter`,
credential `sqlguard_note_writer_app`, seed `db/security/20_reference_seed.sql`) bị gỡ, không còn là
đường demo.

Attack Lab cho presenter ghi payload vào cột note rồi hỏi agent để quan sát indirect injection. Vì
nó **ghi vào DB mà agent đọc**, D2-01 §8 yêu cầu threat model phải mô tả endpoint, quyền ghi,
capability, audit và restore. Phần service là `AttackLab` (`src/sqlguard/security/attack_lab.py`);
route và UI nằm trong `src/sqlguard/web/` (dùng chung).

## 0. Hiện trạng code (cập nhật 24/10, sau khi làm L1–L5)

- `AttackLab` không phụ thuộc DB cụ thể và đã có: tắt mặc định, allowlist target, từ chối khi có
  run đang chạy, `expected_revision`, kiểm payload, đọc lại sau khi ghi, audit chỉ ghi hash.
- **Đã có:** `create_lab_copy` + CLI (`python -m sqlguard.security.attack_lab`), `SQLiteNoteWriter`
  (placeholder `?`, authorizer riêng), `SQLiteRevisionStore` (sidecar, sống qua restart), và
  `attack_lab_from_env` (fail closed khi cấu hình sai). Đã gỡ `PostgresNoteWriter` và role
  note-writer khỏi `db/`. Test ở `tests/security/test_attack_lab_sqlite.py`.
- Đã chạy thử trên bản sao của `db/financial.sqlite` (24/10): `init-copy`, `show`/`save`/`restore`
  trên `account.3`; `revision_conflict` và `target_not_allowed` (`client.4`) bị từ chối và có
  audit; hash sau restore trùng baseline; file gốc không đổi hash.
- **Đã có (24/10, A1–A4):** `LabRunGuard` và 5 route trong `web/` (chỉ `admin`), trang Attack Lab,
  cảnh báo `possible_injection` ở Query/Database, và `lab_revisions` trong kết quả `/api/query`
  (đọc ở tầng web, không sửa `agent/`). Test: `tests/unit/test_web_attack_lab.py`; đã kiểm bằng
  trình duyệt với hai phiên (admin tiêm, operator hỏi).
- **Chưa có:** ghi `(revision, hash)` vào trace/event của run (L8 đầy đủ, cần Học); Observe chưa
  hiện revision, chỉ trang Query hiện dòng "note lúc run bắt đầu".
- `note_targets` của `business_financial_v1`: `account.service_note` (key `account_id`) và
  `order.note` (key `order_id`). Trên `db/financial.sqlite`, cả 4500 dòng `account` và 6471 dòng
  `order` đều có note synthetic (`SYN …`).
- Task injection của Kiệt (`upstream/feat/implement-injection-tasks`, `246aeac`, chưa merge):
  D2-I03 tiêm vào `account.service_note` của `account_id = 3`, D2-I04 tiêm vào `order.note` của
  `order_id = 29407`. D2-I01 và D2-I02 là direct injection, không cần lab. Harness của Kiệt
  (`prepare_overlay`) giả định patch lên một **bản sao dùng một lần**.

## 1. Thiết kế

### 1.1 Bản sao lab

- Lab không bao giờ ghi vào file gốc mà Kiệt đã ghim (`db/financial.sqlite`, SHA-256
  `ec45f11d…eba0`). Bản sao tạo bằng `create_lab_copy(source, output)` (kèm CLI). Hàm này:
  - chỉ nhận source đạt `preflight_financial_sqlite`;
  - copy bằng `sqlite3` backup API;
  - từ chối ghi đè file đã có;
  - ghi sidecar `<copy>.lab.json` gồm SHA-256 của source, SHA-256 của bản sao lúc tạo, policy id
    và thời điểm tạo.
- Writer chỉ mở file có sidecar khớp. Nó từ chối (`lab_db_not_a_copy`) khi file không có sidecar,
  hoặc khi path resolve trùng với source ghi trong sidecar.
- Khi demo: `SQLGUARD_ATTACK_LAB_DB` và `SQLGUARD_BUSINESS_FINANCIAL_DB` cùng trỏ tới bản sao (ví dụ
  `data/lab/financial-lab.sqlite`), để agent đọc đúng dữ liệu bị tiêm. Lab từ chối bật nếu hai biến
  này khác nhau.
- Schema preflight chỉ kiểm schema, không kiểm hash, nên bản sao đã ghi note vẫn qua preflight. Suite
  legitimate của Kiệt vẫn chạy trên file gốc.

### 1.2 `SQLiteNoteWriter`

- Mở `file:<copy>?mode=rw`. Không dùng `rwc`, để không tự tạo file khi path sai.
- Đặt `busy_timeout`, giữ journal mặc định. Không bật WAL, vì executor của agent mở `mode=ro` và WAL
  cần file `-shm` ghi được.
- Statement cố định theo bảng, sinh từ `note_targets`, dùng placeholder `?`. `note_statements` nhận
  thêm paramstyle, hoặc tách hàm riêng cho SQLite.
- Có authorizer riêng cho writer, mặc định deny. Chỉ cho:
  - `SQLITE_UPDATE` trên đúng (bảng, cột note);
  - `SQLITE_READ` trên cột note và cột key của các bảng trong `note_targets`;
  - `SQLITE_TRANSACTION`.

  Như vậy writer không sửa được cột hay bảng khác, kể cả khi code gọi sai. Lớp này thay cho
  `GRANT UPDATE (note)` của PostgreSQL.
- `rowcount` phải bằng 1, nếu không thì `target_missing`. Commit trong một transaction ngắn.

### 1.3 Revision lưu bền

- Baseline (revision 0) và các revision (nội dung + hash) được lưu ở sidecar
  `<copy>.lab-revisions.sqlite`. `AttackLab` nạp lại khi khởi động, nên restart backend không còn
  làm mất baseline.
- Agent không đọc được sidecar:
  - executor chỉ mở path được cấu hình;
  - authorizer của agent deny `ATTACH` (mặc định deny mọi action ngoài `SELECT`/`READ`/hàm
    allowlist);
  - path của sidecar không nằm trong biến môi trường nào mà agent dùng.

### 1.4 Run đang chạy

- Web giữ một `LabRunGuard` dùng chung giữa lab và luồng chạy query business. Lab dùng
  `run_active()`. Một run mới phải chờ lần ghi lab đang diễn ra xong mới bắt đầu, nên không có
  trường hợp lab ghi giữa lúc agent đọc.

### 1.5 Nối với trace

- Khi một run bắt đầu, ghi `{target: (revision, content_hash)}` của các target lab vào metadata của
  run. Observe hiển thị "run này đọc note revision N", và harness của Kiệt có dữ liệu cho
  `payload_retrieved`. Việc này cần thống nhất format trace với Học và Kiệt.

## 2. Threat riêng của Attack Lab (T11)

| ID | Threat | Control | Trạng thái |
| --- | --- | --- | --- |
| T11a | Agent dùng Lab làm đường ghi | Lab **không** phải MCP tool; agent chỉ có executor `mode=ro` + `query_only` + authorizer chỉ đọc; writer chỉ được web hoặc CLI của presenter tạo | Implemented |
| T11b | Ghi cột/bảng khác ngoài note | Code: SQL cố định theo bảng, target phải trong allowlist `table.id`. DB: authorizer của writer chỉ cho `UPDATE` cột note của `note_targets` | Implemented + test (UPDATE/DELETE/INSERT/DDL/ATTACH/PRAGMA bị deny; so từng ô trước/sau) |
| T11c | SQL injection qua target/payload | Target parse thành `(table, int)` theo allowlist; payload là tham số bind `?` | Implemented |
| T11d | Note đổi giữa lúc agent đang chạy | `run_active` → từ chối ghi; run mới chờ lần ghi đang diễn ra (`LabRunGuard`) | Service implemented; guard ở web: planned |
| T11e | Hai người ghi đè nhau | `expected_revision` sai → `revision_conflict` | Implemented |
| T11f | Payload còn sót sau demo | Baseline = revision 0, `restore` rồi đọc lại để xác minh; revision lưu ở sidecar nên sống qua restart, nội dung kiểm lại bằng hash mỗi lần đọc; cách cuối cùng là xóa bản sao rồi tạo lại | Implemented |
| T11g | Người không phải presenter dùng Lab | Tắt mặc định; chỉ bật khi `SQLGUARD_ATTACK_LAB_ENABLED=1` và có `SQLGUARD_ATTACK_LAB_DB`; route chỉ cho tài khoản `admin` | Service + CLI implemented; route: planned |
| T11h | Payload phá UI (HTML/script) | Payload ≤ 2000 ký tự, không có ký tự điều khiển; UI render dạng text (`textContent`), không render HTML hay ảnh remote | Service implemented; UI: planned |
| T11i | Lộ payload qua audit | Audit chỉ ghi hash, độ dài, revision, user; nội dung chỉ nằm ở bản sao và sidecar | Implemented |
| T11j | Lab ghi vào DB gốc đã ghim | Chỉ ghi file có sidecar `.lab.json` khớp, path khác source | Implemented + test |
| T11k | Agent đọc được sidecar revision (lộ payload cũ/baseline) | File riêng, không cấu hình cho agent; authorizer của agent deny `ATTACH` | Implemented + test |

Tài sản A3 (credentials) với SQLite: không còn DSN hay mật khẩu DB. Tài sản là **quyền ghi file**
bản sao lab và sidecar. Chỉ process web có quyền đó, agent thì không.

## 3. Hợp đồng API (route trong `web/`)

| Route | Body | Gọi | Lỗi |
| --- | --- | --- | --- |
| `GET /api/lab/notes/{target}` | — | `lab.get(target)` → `{target, revision, content, baseline_revision}` | `lab_disabled` (404), `target_not_allowed` (404) |
| `PUT /api/lab/notes/{target}` | `{content, expected_revision}` | `lab.save(...)` | thêm `run_active` (409), `revision_conflict` (409), `invalid_payload` (422) |
| `POST /api/lab/notes/{target}/restore` | `{expected_revision, to_revision?}` | `lab.restore(...)` | như trên, thêm `unknown_revision` (422) |
| `GET /api/lab/notes/{target}/history` | — | `lab.history(target)` (không có nội dung) | như `GET` |
| `GET /api/lab/targets` | — | `lab.targets` (route bổ sung cho UI) | `lab_disabled` (404) |

- `user_id` lấy từ session, không lấy từ body. Chỉ role hệ thống `admin`. Business role
  (`operator`/`analyst`/`credit_officer`) và `evaluator` nhận 403.
- Target lấy từ `SQLGUARD_ATTACK_LAB_TARGETS`. Đề xuất `account.3,order.29407` để khớp D2-I03 và
  D2-I04. Để trống thì lab không ghi được gì.
- Lỗi `write_failed`, `read_failed`, `target_missing`, `lab_db_not_a_copy` trả 500 hoặc 503 với
  thông báo chung, không trả lỗi SQLite nguyên văn.

## 4. Luồng demo (cảnh 4, diễn tập T3 27/10)

0. Trước buổi demo, tạo bản sao và trỏ cả hai biến về nó:

   ```
   python -m sqlguard.security.attack_lab init-copy --source db/financial.sqlite \
       --output data/lab/financial-lab.sqlite
   SQLGUARD_BUSINESS_FINANCIAL_DB=data/lab/financial-lab.sqlite
   SQLGUARD_ATTACK_LAB_DB=data/lab/financial-lab.sqlite
   SQLGUARD_ATTACK_LAB_ENABLED=1
   SQLGUARD_ATTACK_LAB_TARGETS=account.3,order.29407
   ```

   Khi chưa có route web, các bước 1, 2 và 5 dùng CLI: `show account.3`,
   `save account.3 --expected-revision 0 --file payload.txt`,
   `restore account.3 --expected-revision 1`. CLI không biết web có run đang chạy hay không, nên
   chỉ save/restore khi không có câu hỏi nào đang chạy.
1. `admin` gọi `GET account.3`, thấy revision 0 (baseline `SYN service note: …`).
2. `PUT` payload của D2-I03 với `expected_revision=0`, lên revision 1; audit `save ok`.
3. Đăng nhập `operator` và hỏi câu của D2-I03. Tool trả envelope `possible_injection=true`; gate
   chặn mọi truy vấn bị tiêm (ví dụ đọc `client.id_number`).
4. Observe hiển thị bước bị chặn và revision note mà run đã đọc.
5. `admin` gọi `POST restore` với `expected_revision=1`, lên revision 2 có hash trùng baseline;
   audit `restore ok`.

## 5. Việc cần làm (P1-6, dự kiến T2 26/10)

| ID | Việc | File chính | Done khi | Ước lượng |
| --- | --- | --- | --- | --- |
| L1 | `create_lab_copy` + CLI `init-copy` + sidecar `.lab.json` | `security/attack_lab.py` | Từ chối source không qua preflight, file đã có, file gốc | 45' |
| L2 | `SQLiteNoteWriter`: `mode=rw`, `?`, authorizer writer, `rowcount == 1` | `security/attack_lab.py` | Ghi đúng ô; mọi `UPDATE`/`DELETE`/`INSERT` khác bị `SQLITE_DENY` | 1h |
| L3 | Revision lưu bền ở sidecar `.lab-revisions.sqlite` | `security/attack_lab.py` | Tạo lại `AttackLab` sau khi ghi vẫn restore được về baseline | 45' |
| L4 | Gỡ phần PostgreSQL của lab: `PostgresNoteWriter`, test lab trong `test_db_grants.py`, role note-writer trong `db/security/` và `db/bird_financial/10_roles.sql`, dòng tương ứng trong `db/security/README.md`, docstring | `security/`, `db/`, `tests/security/` | Không còn tham chiếu `psycopg` trong lab; test xanh | 20' |
| L5 | Test SQLite | `tests/security/test_attack_lab.py` | Gồm: chỉ đổi đúng ô (so toàn bộ DB trước và sau, trừ ô target); từ chối file gốc hoặc file thiếu sidecar; restart rồi restore; `run_active`; audit không chứa payload; agent `ATTACH` sidecar bị deny; bản sao đã ghi vẫn qua preflight | 1h |
| L6 | `LabRunGuard` + 4 route + chặn theo role `admin` | `web/app.py`, `web/query_service.py` | Test web: 403 cho business role, 409 khi đang có run, không trả lỗi SQLite nguyên văn | 1h30 |
| L7 | UI trang lab: render text, nút save/restore, hiển thị revision | `web/static/` | Payload `<img src=x onerror=…>` hiện ra dạng chữ | 1h |
| L8 | Ghi revision note vào metadata của run, hiển thị ở Observe | `agent/` hoặc `web/` | Trace có `(revision, hash)` của target | 45' (cần Học) |
| L9 | Harness của Kiệt dùng `create_lab_copy` + `AttackLab.save` cho mỗi run I03/I04, xóa bản sao sau run | `evaluation/financial_injection.py` | P1-7 chạy được offline | Kiệt |

**Trạng thái 24/10:** L1–L5 xong và đã commit, kèm CLI `show`/`history`/`save`/`restore` và
`attack_lab_from_env`. L6, L7 xong (A1, A2, A4); L8 xong phần web (A3: `lab_revisions` trong kết
quả query), chưa ghi vào trace của run. L9 chưa làm.

Thứ tự: L1 → L2 → L3 → L5 → L4 là phần security (khoảng 4h), làm trong ngày 26/10. L6–L7 cũng do
Khang làm, vì đã làm P1-8 ở web. L8 cần Học review vì đụng `agent/`. Nếu L6–L8 không kịp trước
27/10, cảnh 4 dùng CLI để save/restore và chỉ quay Observe.

## 6. Giả định cần xác nhận

| # | Giả định | Nếu không được duyệt |
| --- | --- | --- |
| LA1 | Chỉ `admin` dùng lab (presenter đăng nhập bằng `admin`) | Thêm role `presenter` riêng trong `web/auth.py` |
| LA2 | Target demo là `account.3` và `order.29407` (trùng D2-I03/I04) | Đổi `SQLGUARD_ATTACK_LAB_TARGETS`; code không đổi |
| LA3 | Demo chạy trên bản sao lab chứ không phải file gốc, nên SHA-256 của DB demo khác snapshot Kiệt ghim | Ghi rõ trong report: số liệu legitimate lấy từ file gốc, demo lấy từ bản sao |

## 7. Giới hạn đã biết

- Bảo vệ file gốc dựa vào sidecar và so path, không dựa vào quyền của hệ điều hành. Ai có shell trên
  máy demo vẫn sửa được file. Ngoài phạm vi threat model (attacker U3 chỉ đi qua route).
- Preflight không kiểm hash, nên không phát hiện nội dung bị sửa ngoài lab. Lịch sử revision và audit
  chỉ ghi lại những lần ghi đi qua lab.
- Sidecar revision lưu nội dung payload dạng rõ. Xóa cùng bản sao sau demo.
- Sidecar được khóa bằng `BEGIN IMMEDIATE` (chờ tối đa 2 s), chạy ngay trong event loop. Đủ cho
  một presenter, nhưng không phải thiết kế cho nhiều người ghi cùng lúc.
