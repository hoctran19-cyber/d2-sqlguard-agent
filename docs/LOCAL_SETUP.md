# Chạy SQLGuard Web trên máy local

Hướng dẫn ngắn để chạy web app (Query dùng Ollama + SQLite tổng hợp). Mọi lệnh chạy từ **thư mục gốc repo**.

## 1. Môi trường Python (>= 3.11)

```bash
python3 --version                      # cần >= 3.11
test -d .venv || python3 -m venv .venv # chỉ tạo nếu chưa có
source .venv/bin/activate
which python                           # phải trỏ vào .venv/bin/python
python -m pip install -e ".[dev,web]"
```

## 2. Database Financial (cho trang Database)

File BIRD `financial.sqlite` cần có sẵn tại `data/bird/financial.sqlite` (git-ignored, không được tạo tự động):

```bash
export SQLGUARD_FINANCIAL_DB="$PWD/data/bird/financial.sqlite"
test -f "$SQLGUARD_FINANCIAL_DB" && echo OK || echo "Thiếu file financial.sqlite"
```

Nếu file của bạn nằm ở `data/financial.sqlite` thì chỉ trỏ biến tới đó khi file thực sự tồn tại ở vị trí này.

## 3. Ollama + model

```bash
ollama list                              # đã cài model nào
curl -s http://localhost:11434/api/tags  # server có đang chạy không
```

- Chỉ chạy `ollama serve` (ở terminal riêng) nếu `curl` báo không kết nối được.
- Chỉ chạy `ollama pull qwen3:8b` nếu `qwen3:8b` chưa có trong danh sách.

## 4. Tạo fixture SQLite tổng hợp (một lần)

```bash
test -f /tmp/sqlguard-web-demo.sqlite || python -m sqlguard.demo_fixture --output /tmp/sqlguard-web-demo.sqlite
```

Lệnh tạo fixture từ chối ghi đè file đã có. Nếu file đã tồn tại thì bỏ qua — **không xoá hay ghi đè**.

## 5. Chạy web app

```bash
export SQLGUARD_WEB_QUERY_MODE=synthetic_sqlite
export SQLGUARD_WEB_DEMO_SQLITE_PATH=/tmp/sqlguard-web-demo.sqlite
export SQLGUARD_PLANNER=ollama
export SQLGUARD_OLLAMA_MODEL=qwen3:8b
export SQLGUARD_OLLAMA_TIMEOUT_SECONDS=60
python -m sqlguard.web --port 8000      # http://127.0.0.1:8000
```

Dừng server: `Ctrl+C`.

Lưu ý:

- `export` chỉ có hiệu lực trong terminal hiện tại; mở terminal mới phải export lại (kể cả `SQLGUARD_FINANCIAL_DB`).
- `.env` / `.env.example` **không** được tự động nạp.
- Không cần npm, PostgreSQL hay service evaluation riêng.

## 6. Sử dụng

| Tài khoản | Mật khẩu | Trang |
| --- | --- | --- |
| `admin` | `123456` | `/home` — Query + Database |
| `eval` | `123456` | `/evaluation/` — console evaluation |

**Hai nguồn dữ liệu tách biệt:**

- **Query** (chế độ `synthetic_sqlite`): Ollama sinh SQL trên fixture tổng hợp `/tmp/sqlguard-web-demo.sqlite`, policy `d2_synthetic_v1`, role demo `sales`. Câu mẫu: `List order IDs and total amounts` → kỳ vọng order `101`/`102`, tổng `120000`/`230000` (SQL sinh ra có thể khác tuỳ model).
- **Database**: duyệt BIRD `financial.sqlite` qua `SQLGUARD_FINANCIAL_DB`, mở read-only, đi qua `ReadOnlySQLGate`.

**Evaluation:** `/evaluation/` được mount trên cùng server (chỉ khi chạy từ thư mục gốc repo), chỉ chạy fixture (scripted planner, SQLite in-memory), không gọi LLM.

**Giới hạn:**

- Query synthetic chỉ có **một lần thử SQL** (`max_sql_attempts=1`), không có vòng reflection/repair trên web.
- Các role nghiệp vụ (`operator`, `analyst`, `credit_officer`) bị chặn truy vấn dữ liệu (API trả 403).
- Muốn Query dùng lại database Financial: bỏ `SQLGUARD_WEB_QUERY_MODE` và khởi động lại server. Khi đó Query dùng **demo planner** (không LLM) dù `SQLGUARD_PLANNER=ollama`.

## 7. Xử lý sự cố

- `externally-managed-environment` khi `pip install`: `python` không phải của venv (vd. conda base đang bật) → `conda deactivate`, kích hoạt lại `.venv`.
- Trang Database báo không tìm thấy database: kiểm tra `test -f "$SQLGUARD_FINANCIAL_DB"` trong đúng terminal chạy server.
- Query báo thiếu đường dẫn / database synthetic: kiểm tra `SQLGUARD_WEB_DEMO_SQLITE_PATH` và file `/tmp/...` còn tồn tại (`/tmp` có thể bị dọn khi khởi động lại máy).
- Query báo yêu cầu Ollama: đặt `SQLGUARD_PLANNER=ollama`.
- Run thất bại / timeout: kiểm tra `curl http://localhost:11434/api/tags`, tên model khớp `SQLGUARD_OLLAMA_MODEL` và trạng thái model qua `ollama ps`. Toàn bộ run còn có giới hạn 60 giây; chỉ tăng timeout Ollama không tăng giới hạn này.
- Cổng 8000 bị chiếm: dùng `--port 8001`.
- `/evaluation/` trả 503: chạy server từ thư mục gốc repo.
