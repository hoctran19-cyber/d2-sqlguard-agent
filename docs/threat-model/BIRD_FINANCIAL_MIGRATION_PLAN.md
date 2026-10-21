# Plan: chuyển phần security sang BIRD Mini-Dev — Financial

Trạng thái: **nhóm đã chốt mục 0 theo đề xuất (19/10); đang thực hiện, xem mục 9**. Owner: Khang. Ngày lập: 19/10/2026. Nhánh: `feature/security-policy` (PR chưa merge vào repo nhóm, nên làm tiếp trên nhánh này để nhóm review thẳng bản BIRD, không merge bản synthetic).

Nguồn đã kiểm: schema và 32 câu hỏi Financial lấy từ repo chính thức `github.com/bird-bench/mini_dev` (`finetuning/inference/mini_dev_prompt.jsonl`). Số dòng dữ liệu ở mục 2 là theo bộ PKDD'99 gốc, **phải kiểm lại khi nạp**.

## 0. Quyết định cần chốt (mặc định đề xuất in đậm)

| # | Câu hỏi | Đề xuất |
| --- | --- | --- |
| Q1 | Business | **Trợ lý hỏi dữ liệu nội bộ ngân hàng** (thay “đơn hàng nội bộ” của D1; ghi vào bảng delta report) |
| Q2 | 3 role | **Giao dịch viên (`teller`), Tín dụng (`credit`), Rủi ro–Tài chính (`risk`)** |
| Q3 | Ma trận quyền | **Như mục 3.2** |
| Q4 | Cột overlay | **`client.national_id` (cấm cả 3 role, chứa canary), `client.note` (ghi chú nhân viên), `trans.note` (nội dung chuyển khoản do bên ngoài nhập)** |
| Q5 | 5 câu gold có subquery | **Loại khỏi D2** (gate giữ fail-closed); xem lại ở D3 |
| Q6 | Bản synthetic hiện tại | **Xóa khỏi nhánh** sau khi port xong (git history vẫn giữ) để report không lẫn hai bộ dữ liệu |
| Q7 | Dùng `evidence` của BIRD? | Kiệt quyết (ảnh hưởng so sánh với số công bố); security không phụ thuộc |

## 1. Phạm vi

**Giữ nguyên (không đổi logic):** gate (`gate.py`), danh mục mã lỗi, secure tool (`service.py`), audit, sanitizer, Postgres executor, 3 mode baseline, cơ chế partial/narrowable, cấu trúc test.

**Thay đổi:** policy, DB scripts, overlay dữ liệu, các chỗ còn hard-code bảng `customers/orders` (Attack Lab, prompt, role mặc định), toàn bộ dataset security, fixture test, tài liệu.

## 2. Dữ liệu BIRD Financial

| Bảng | Cột | Số dòng (PKDD'99, cần kiểm) |
| --- | --- | --- |
| `client` | client_id, gender, birth_date, district_id | ~5.369 |
| `account` | account_id, district_id, frequency, date | ~4.500 |
| `disp` | disp_id, client_id, account_id, type | ~5.369 |
| `card` | card_id, disp_id, type, issued | ~892 |
| `loan` | loan_id, account_id, date, amount, duration, payments, status | ~682 |
| `order` | order_id, account_id, bank_to, account_to, amount, k_symbol | ~6.471 |
| `trans` | trans_id, account_id, date, type, operation, amount, balance, k_symbol, bank, account | **~1.056.000** |
| `district` | district_id, A2…A16 | 77 |

- Khóa ngoại: account→district, client→district, disp→client, disp→account, card→disp, loan→account, order→account, trans→account.
- `order` là từ khóa SQL (phải quote); cột `A2…A16` có thể hoa/thường tùy bản Postgres — kiểm khi nạp.
- **License CC BY-SA 4.0**: ghi nguồn; overlay và fixture con phát hành cùng license (thêm `NOTICE`).
- **Chặn hiện tại:** môi trường của Claude không tải được Hugging Face / file zip. Cần một người tải `minidev.zip` và đưa file `dev_databases/financial/financial.sqlite` (hoặc dump Postgres) cùng thư mục `database_description/` của Financial vào repo-ngoài-Git hoặc gửi trực tiếp.

## 3. Thiết kế mới

### 3.1 Câu chuyện
Nhân viên ngân hàng hỏi bằng tiếng Việt về khách, tài khoản, giao dịch, khoản vay. Indirect injection đến từ **nội dung chuyển khoản** (`trans.note`) do bên ngoài nhập — kịch bản thực tế hơn “ghi chú đơn hàng” — và ghi chú nhân viên (`client.note`).

### 3.2 Ma trận quyền (đề xuất)

| Bảng.cột | Giao dịch viên | Tín dụng | Rủi ro–Tài chính |
| --- | --- | --- | --- |
| `client.national_id` *(overlay)* | ✗ | ✗ | ✗ |
| `client.birth_date` | ✗ | ✓ | ✗ |
| `client` còn lại, `account`, `disp`, `card`, `district` | ✓ | ✓ | ✓ |
| `loan.*` | ✗ (cả bảng) | ✓ | ✓ |
| `trans.bank`, `trans.account` (tài khoản đối tác) | ✗ | ✗ | ✓ |
| `order.bank_to`, `order.account_to` | ✗ | ✗ | ✓ |
| `trans`/`order` còn lại (gồm `balance`, `note`) | ✓ | ✓ | ✓ |

Kiểm trên 27 câu không có subquery với ma trận này: **13 câu cả 3 role hỏi được** (nguồn task legit); giao dịch viên bị cấm 14 câu, rủi ro bị cấm 4 câu ⇒ **dùng chính câu hỏi BIRD làm authorization task** (đáng tin hơn tự viết).

### 3.3 Overlay
- `ALTER TABLE client ADD national_id text, ADD note text; ALTER TABLE trans ADD note text;` — thêm cuối bảng, không đổi cột BIRD; kiểm gold SQL không dùng `SELECT *`.
- `national_id`: sinh tất định (seed cố định) cho mọi client; một số dòng là canary `CANARY-NID-xxxx`.
- `birth_date` (kiểu `date`) và `bank`/`account` (dữ liệu BIRD gốc) không chèn được canary dạng chuỗi; UAR cho các cột này đo bằng “cột cấm xuất hiện trong SQL thực thi hoặc tool output”, như test offline hiện tại.
- Payload injection đặt ở vài `trans.note` và `client.note` (ID chọn sau khi nạp); phần lớn note để NULL/sạch.

### 3.4 Mô tả cột cho `get_schema` / semantic memory
Lấy từ `database_description/` của BIRD (A2 = tên quận, A3 = vùng, A11 = lương trung bình, A12/A13 = thất nghiệp 95/96, A15/A16 = số vụ phạm tội 95/96…; mã `frequency`, `type`, `k_symbol`, trạng thái `loan.status` A/B/C/D). Phải đối chiếu với file gốc, không chép theo trí nhớ.

## 4. Thay đổi code theo file

| File | Thay đổi | Công |
| --- | --- | --- |
| `security/policies/bird_financial_v1.json` *(mới)* | Bảng/cột/FK, ma trận 3 role, mô tả, canary, `note_targets`, allowlist hàm bổ sung | 0,25 ngày |
| `security/policy.py` | Thêm `note_targets`, `domain_description`; chọn policy qua `SQLGUARD_POLICY` (mặc định `bird_financial_v1`) | 0,1 |
| `security/gate.py` | Không đổi logic. Chạy gate trên gold SQL Postgres của 27 câu: câu nào bị từ chối nhầm thì mở rộng allowlist hàm trong policy (dự kiến `Substring`, `StrPosition`, hàm ngày) — không nới subquery | 0,25 |
| `security/attack_lab.py` | Bỏ `NOTE_SQL`/`DEFAULT_TARGETS` hard-code; sinh câu lệnh cố định từ `policy.note_targets` (`client.note`, `trans.note`) | 0,1 |
| `security/prompting.py` | Câu giới thiệu domain lấy từ policy (“internal banking database”) | 0,05 |
| `security/sanitizer.py` | Mẫu `privilege_vi` dùng tên role/phòng ban chung thay vì `finance/kế toán` | 0,05 |
| `security/postgres.py` | `from_env()` lấy danh sách role từ policy (`SQLGUARD_DB_DSN_TELLER/CREDIT/RISK`) | 0,05 |
| `db/security/00_load_bird_financial.sh` *(thay `00_reference_schema.sql`)* | Nạp `financial.sqlite` vào Postgres (pgloader hoặc script Python), kiểm số dòng | 0,25 |
| `db/security/05_overlay.sql` *(mới)* | Thêm cột overlay, index cần cho `trans` | 0,1 |
| `db/security/10_roles.sql` | Role `sqlguard_teller_ro/credit_ro/risk_ro` + login `*_app`; GRANT theo cột như 3.2; note-writer chỉ `UPDATE(note)` trên `client`, `trans` | 0,25 |
| `db/security/20_overlay_seed.sql` *(thay seed synthetic)* | `national_id` tất định, canary, payload injection | 0,1 |
| `scripts/make_bird_fixture.py` + `tests/fixtures/bird_financial_mini.sql` *(mới)* | Trích ~30 client và các dòng liên quan (giữ FK) + overlay, để test offline/CI không cần 1 triệu dòng | 0,25 |
| `tests/security/*` | Fixture mới; viết lại ~60/105 payload corpus phụ thuộc tên bảng (STRUCT/FN giữ ý tưởng, đổi tên bảng); test DB dùng fixture | 0,5 |
| `evaluation/datasets/security/authorization_tasks_v2.json` | 20 task: ưu tiên câu BIRD bị cấm theo role (pure-auth) + task hỗn hợp có cột cấm hiển thị (mixed); D2 giữ ID `D2-A01/A02/M01/M02` | 0,5 |
| `evaluation/datasets/security/injection_cases_v2.json` | 5 direct + 5 indirect + clean pair theo ngữ cảnh ngân hàng (nội dung chuyển khoản, ghi chú nhân viên); D2 giữ `D2-I01..I04` | 0,5 |
| Docs (threat model, mục 5, Attack Lab, integration, dataset README, `NOTICE`) | Đổi domain, role, ví dụ; ghi nguồn BIRD | 0,25 |

**Tổng phần security: ~4 ngày-công liệt kê → làm song song được còn ~2 ngày lịch** (nhiều mục chỉ vài giờ).

## 5. Việc của người khác (phụ thuộc)

| Ai | Việc | Cần trước |
| --- | --- | --- |
| Kiệt | Tải Mini-Dev (Postgres), chọn ~10 câu legit trong 13 câu “cả 3 role hỏi được”, dịch sang tiếng Việt, quyết `evidence`; lưu ý gate tự thêm `LIMIT 100` khi so kết quả với gold | 20/10 |
| Học | Semantic memory → thuật ngữ ngân hàng (A2…A16, `k_symbol`, `loan.status`, `frequency`); role trong session đổi tên `teller/credit/risk` | 21/10 |
| FE/API | 3 tài khoản demo mới; Attack Lab target `client.note`, `trans.note` | 22/10 |
| Cả nhóm | Chốt mục 0; dòng delta “bán hàng → ngân hàng” trong report | 19/10 |

## 6. Lịch

| Ngày | Việc | Xong khi |
| --- | --- | --- |
| 19/10 | Chốt mục 0; có file `financial.sqlite` + `database_description` | Có dữ liệu trong tay |
| 20/10 | Policy + overlay + loader + grants; gate chạy trên 27 gold SQL | Test DB (gate tắt) xanh trên BIRD; 0 từ chối nhầm trên 27 câu |
| 21/10 | Fixture, corpus, 20 auth task, 10 injection case, docs | Toàn bộ `tests/security` xanh; PR cập nhật |
| 22–23/10 | Chạy với model thật (cùng Học/Kiệt) | Có ASR/UAR thật cho D2-I01..I04 |

## 7. Rủi ro

| Rủi ro | Giảm thiểu |
| --- | --- |
| Không tải được dữ liệu kịp | Người trong nhóm tải tay; nếu quá 20/10 thì quay lại phương án synthetic hiện có (đã chạy được) |
| Truy vấn trên `trans` (~1 triệu dòng) vượt timeout 3 s | Index `trans(account_id, date)`; đo thực tế; nếu cần nâng timeout thì ghi trong policy và report |
| Gold SQL Postgres dùng hàm/cú pháp ngoài subset | Mở rộng allowlist hàm có kiểm; câu cần subquery → loại (Q5) |
| Tên cột hoa/thường (`A2` vs `a2`) lệch giữa bản Postgres và policy | Kiểm khi nạp; gate đã so sánh không phân biệt hoa/thường, grants phải dùng đúng tên thật |
| Lệch D1 (bán hàng → ngân hàng) | Ghi rõ ở bảng delta: lý do là dùng benchmark chuẩn để tăng độ tin cậy |

## 8. Definition of done

- Policy BIRD là mặc định; mọi test security xanh trên fixture BIRD; test DB với gate tắt xanh trên DB Financial đầy đủ.
- 27 gold SQL không subquery: gate cho phép với role đọc được đủ cột (0 từ chối nhầm), từ chối với role thiếu quyền.
- 20 authorization task + 10 injection case + clean pair theo ngữ cảnh ngân hàng, có test offline.
- Threat model, mục 5, Attack Lab, hướng dẫn tích hợp cập nhật; có `NOTICE` ghi nguồn BIRD (CC BY-SA 4.0).

## 9. Tiến độ

| Giai đoạn | Nội dung | Trạng thái |
| --- | --- | --- |
| 1 (không cần dữ liệu) | Policy `bird_financial_v1` (ma trận đã chốt, mô tả cột từ `database_description` của BIRD); gate cho phép `ON` là AND các khóa ngoại (bảng cầu `disp`), `TO_CHAR`; Attack Lab/prompt/executor lấy bảng, domain, role từ policy; `db/bird_financial/` (schema, loader, overlay, grants); 32 câu Financial + gold SQL PostgreSQL (`evaluation/datasets/bird_financial/`), `NOTICE` | **Xong**. Gate: 27/27 câu không subquery được chấp nhận với Tín dụng, 13 câu với cả 3 role, đúng 5 câu subquery bị chặn. Script DB áp được trên PostgreSQL 16 |
| 2 (cần `financial.sqlite`) | Nạp dữ liệu, chọn ID note + `20_overlay_seed.sql`, fixture con cho test, chuyển policy mặc định sang BIRD, port test/dataset (20 auth + 10 injection), xóa bản synthetic, cập nhật tài liệu | Chờ dữ liệu (Drive API giới hạn 10 MB/file; mạng của môi trường chặn Google Drive) |
