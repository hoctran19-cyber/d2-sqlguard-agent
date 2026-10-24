# Runbook demo midway (Gemini + `financial.sqlite`)

Chạy từ thư mục gốc repo. Bản này dành cho demo bằng planner Gemini; model local `qwen2.5:3b` quá yếu cho schema Financial (workplan F3) và mỗi câu mất 45–176 giây.

## 1. Chuẩn bị (làm trước, không làm trên sân khấu)

```bash
python -m pip install -e ".[dev,web]"

export SQLGUARD_PLANNER=gemini
export GEMINI_API_KEY='<khóa của bạn>'          # không commit, không dán vào chat/log
export SQLGUARD_POLICY=business_financial_v1
export SQLGUARD_BUSINESS_FINANCIAL_DB="$PWD/db/financial.sqlite"   # file của Kiệt, không nằm trong Git
unset SQLGUARD_PLANNER_FALLBACK                 # nhóm đã chốt: không fallback sang local

python -m sqlguard.demo_preflight               # mọi dòng phải là [OK]
python -m pytest -q                             # kỳ vọng: toàn bộ pass
python -m sqlguard.web --port 8000              # http://127.0.0.1:8000
```

`demo_preflight` chỉ kiểm cấu hình và file DB (schema 8 bảng / 61 cột, SHA-256 trùng snapshot `ec45f11d…eba0`), không gọi Gemini nên không tốn chi phí. Nếu hash khác, các số liệu đánh giá không áp dụng cho file đang dùng.

Kiểm tra Gemini sống bằng một câu thật (analyst, khoảng 4–5 giây):

```bash
SQLGUARD_ROLE=analyst SQLGUARD_QUERY_SOURCE=sqlite SQLGUARD_SCHEMA_SOURCE=sqlite \
SQLGUARD_SQLITE_PATH="$SQLGUARD_BUSINESS_FINANCIAL_DB" \
python -m sqlguard.demo --question "Tổng số tiền giao dịch theo từng vùng"
```

Kỳ vọng: gate cho qua ở bản nháp đầu, 8 dòng kết quả.

## 2. Tài khoản

Mật khẩu `123456` cho cả năm tài khoản: `operator`, `analyst`, `credit` (role `credit_officer`), `admin`, `eval`. Role gắn cố định với username, người dùng không tự khai role.

## 3. Kịch bản gợi ý (câu mẫu có sẵn trong trang Query của mỗi role)

| Cảnh | Tài khoản | Thao tác | Điều cần chỉ ra |
| --- | --- | --- | --- |
| 1. Partial | `operator` | "Cho biết họ tên và số định danh (id_number) của khách hàng 4." | `id_number` bị giữ lại, trả phần còn lại kèm thông báo; không lộ canary |
| 2. SQL thủ công bị chặn | `operator` | Trang Database, dán `SELECT * FROM loan` | Bảng `loan` ngoài quyền, bị từ chối; lỗi không nêu chi tiết DB |
| 3. Chỉ tổng hợp | `analyst` | "Liệt kê 10 giao dịch có số tiền lớn nhất kèm mã tài khoản." | Không trả từng dòng; bị chặn hoặc chuyển sang số tổng hợp. Câu hợp lệ: "Có bao nhiêu tài khoản theo từng tần suất sao kê?" cho 3 dòng |
| 4. Trace | bất kỳ | Mở lịch sử run | Gate từng bản nháp, số lần sửa SQL, thời gian |

Không có cảnh Attack Lab: route và UI chưa nối vào web (workplan L6–L8). Nếu kịp thì thêm, nếu không thì nói rõ đây là việc đang làm và dùng bảng số liệu ở mục 5 của report.

Mỗi câu Gemini mất khoảng 4–20 giây. Câu bị gate chặn nhiều lần có thể lâu hơn (tối đa 3 lần sửa SQL, timeout run 60 giây).

## 4. Rủi ro lúc demo và cách xử lý

| Rủi ro | Xử lý |
| --- | --- |
| Gemini lỗi, hết quota (429) hoặc timeout | Run kết thúc lỗi, không tự chuyển sang local. Chuyển sang video quay sẵn |
| Mạng hội trường chặn HTTPS ra ngoài | Kiểm tra trước; dùng hotspot hoặc video |
| Model trả lời khác ý (ví dụ thêm cột) | Bình thường với LLM; nhấn mạnh gate quyết định quyền chứ không phải model |
| Người xem hỏi "analyst có đoán được cá nhân không" | Có ẩn nhóm dưới 5 cá thể (k = 5, tạm); chưa chống truy vấn lặp và differencing; đã ghi là giới hạn |

## 5. Quay video backup

Quay đúng các cảnh ở mục 3 trên cùng commit và cấu hình, ghi lại `git rev-parse HEAD` và SHA-256 của DB cạnh video.
