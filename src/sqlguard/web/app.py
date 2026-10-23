"""Backend FastAPI của web app SQLGuard. Chạy bằng: python -m sqlguard.web

Routes giao diện (UI.md):
  /            -> chuyển tới /login (chưa đăng nhập) hoặc trang chủ của user
  /login       -> form đăng nhập
  /home        -> khung sidebar + Query/Database (tài khoản admin);
                  role nghiệp vụ chỉ có thông báo + Info tham chiếu, API dữ liệu trả 403
  /evaluation/ -> console evaluation đã có (chỉ tài khoản eval)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi import Query as FastAPIQuery
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from sqlguard.observability.events import (
    DEFAULT_HISTORY_LIMIT,
    MAX_HISTORY_LIMIT,
    MAX_HISTORY_OFFSET,
    Event,
    EventStoreError,
    LiveEventHub,
    LiveEventSink,
    SQLiteEventStore,
)
from sqlguard.observability.trace import assess_trace, serialize_trace_event
from sqlguard.web.auth import (
    ADMIN_ROLE,
    BUSINESS_ROLES,
    EVALUATOR_ROLE,
    ROLE_LABELS,
    SESSION_COOKIE,
    SESSION_TTL_SECONDS,
    SessionStore,
    User,
    authenticate,
)
from sqlguard.web.database import (
    DatabaseUnavailable,
    FinancialDatabase,
    QueryError,
    QueryTimeout,
    resolve_db_path,
)
from sqlguard.web.query_service import (
    WebQueryConfigurationError,
    answer_question,
    build_gate,
    explain_denial,
    query_sample_payload,
)
from sqlguard.web.role_reference import role_reference

STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY_BYTES = 64_000  # Câu hỏi/SQL đều ngắn; chặn body quá lớn.
MAX_TEXT_LENGTH = 5_000


def _sse_message(event_name: str, data: dict) -> str:
    return f"event: {event_name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


def _sse_event(sequence: int, event: Event) -> str:
    data = serialize_trace_event(event, sequence)
    data["stream_sequence"] = sequence
    return (
        f"id: {sequence}\nevent: agent_event\n"
        f"data: {json.dumps(data, separators=(',', ':'), ensure_ascii=False)}\n\n"
    )


def create_app(db_path: Path | None = None) -> FastAPI:
    """Tạo app. Test truyền db_path riêng; khi chạy thật thì đọc từ biến môi trường."""
    app = FastAPI(title="SQLGuard", docs_url="/api/docs", redoc_url=None)
    sessions = SessionStore()
    database = FinancialDatabase(db_path or resolve_db_path())
    live_events = LiveEventHub()
    app.state.live_events = live_events

    # ---------- Hàm tiện ích dùng chung ----------

    def current_user(request: Request) -> User | None:
        return sessions.get(request.cookies.get(SESSION_COOKIE))

    def require_admin(request: Request) -> User:
        """Dependency cho API dữ liệu: phải đăng nhập bằng tài khoản được xem dữ liệu."""
        user = current_user(request)
        if user is None:
            raise HTTPException(401, "Chưa đăng nhập")
        if user.role != ADMIN_ROLE:
            # Role nghiệp vụ cũng bị chặn ở đây cho tới khi có Security Gate cho policy Financial.
            raise HTTPException(403, "Tài khoản này không được xem dữ liệu")
        return user

    def require_info_user(request: Request) -> User:
        """Dependency cho popup Info: admin và ba role nghiệp vụ (không gồm evaluator)."""
        user = current_user(request)
        if user is None:
            raise HTTPException(401, "Chưa đăng nhập")
        if user.role != ADMIN_ROLE and user.role not in BUSINESS_ROLES:
            raise HTTPException(403, "Tài khoản này không có trang Info")
        return user

    def user_payload(user: User) -> dict:
        # data_access cho UI biết có hiện Query/Database không; server vẫn tự kiểm từng API.
        return {
            "username": user.username,
            "role": user.role,
            "role_label": ROLE_LABELS.get(user.role, user.role),
            "home": user.home,
            "data_access": user.role == ADMIN_ROLE,
        }

    async def read_json(request: Request) -> dict:
        """Đọc body JSON có giới hạn kích thước; chỉ nhận object."""
        # Chống CSRF đơn giản: chỉ nhận JSON (form của site khác không gửi được kiểu này
        # mà không qua preflight) và nếu có Origin thì phải cùng host.
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise HTTPException(415, "Chỉ nhận application/json")
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
            raise HTTPException(403, "Origin không hợp lệ")
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, "Body quá lớn")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HTTPException(400, "JSON không hợp lệ") from None
        if not isinstance(payload, dict):
            raise HTTPException(400, "Body phải là JSON object")
        return payload

    def text_field(payload: dict, name: str) -> str:
        value = payload.get(name)
        if not isinstance(value, str) or not value.strip():
            raise HTTPException(422, f"Thiếu trường {name}")
        if len(value) > MAX_TEXT_LENGTH:
            raise HTTPException(422, f"{name} quá dài")
        return value.strip()

    def database_call(function, *args, **kwargs):
        """Gọi database và đổi lỗi database thành mã HTTP dễ hiểu cho UI."""
        try:
            return function(*args, **kwargs)
        except DatabaseUnavailable as error:
            raise HTTPException(503, str(error)) from None

    def spa() -> FileResponse:
        # Mọi trang giao diện dùng chung một file HTML; JavaScript tự render theo URL.
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    # ---------- Bảo vệ trang Evaluation (chỉ tài khoản eval) ----------

    @app.middleware("http")
    async def guard_evaluation(request: Request, call_next):
        path = request.url.path
        if path == "/evaluation" or path.startswith("/evaluation/"):
            user = current_user(request)
            is_api = path.startswith("/evaluation/api/")
            if user is None:
                if is_api:
                    return JSONResponse({"detail": "Chưa đăng nhập"}, status_code=401)
                return RedirectResponse("/login", status_code=303)
            if user.role != EVALUATOR_ROLE:
                if is_api:
                    return JSONResponse({"detail": "Không có quyền"}, status_code=403)
                return RedirectResponse(user.home, status_code=303)
            if path == "/evaluation":
                # Cần dấu "/" cuối để các đường dẫn tương đối của console hoạt động.
                return RedirectResponse("/evaluation/", status_code=307)
        return await call_next(request)

    @app.middleware("http")
    async def revalidate_static(request: Request, call_next):
        response = await call_next(request)
        # File JS/CSS luôn được kiểm tra lại với server, tránh trình duyệt dùng bản cũ.
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    # ---------- Routes giao diện ----------

    @app.get("/", include_in_schema=False)
    def root(request: Request):
        user = current_user(request)
        return RedirectResponse(user.home if user else "/login", status_code=303)

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request):
        user = current_user(request)
        return RedirectResponse(user.home, status_code=303) if user else spa()

    @app.get("/home", include_in_schema=False)
    def home_page(request: Request):
        user = current_user(request)
        if user is None:
            return RedirectResponse("/login", status_code=303)
        # Admin và role nghiệp vụ dùng /home; tài khoản eval chỉ dùng trang Evaluation.
        if user.role != ADMIN_ROLE and user.role not in BUSINESS_ROLES:
            return RedirectResponse(user.home, status_code=303)
        return spa()

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # ---------- API đăng nhập ----------

    @app.post("/api/login")
    async def login(request: Request):
        payload = await read_json(request)
        # Chỉ đọc username/password; trường khác (ví dụ "role") bị bỏ qua.
        user = authenticate(str(payload.get("username", "")), str(payload.get("password", "")))
        if user is None:
            raise HTTPException(401, "Sai tên đăng nhập hoặc mật khẩu")
        response = JSONResponse(user_payload(user))
        response.set_cookie(
            SESSION_COOKIE,
            sessions.create(user),
            max_age=SESSION_TTL_SECONDS,
            httponly=True,  # JavaScript không đọc được cookie.
            samesite="strict",  # Không gửi cookie từ site khác.
            path="/",
        )
        return response

    @app.post("/api/logout")
    async def logout(request: Request):
        sessions.delete(request.cookies.get(SESSION_COOKIE))
        response = JSONResponse({"ok": True})
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/api/me")
    def me(request: Request):
        user = current_user(request)
        if user is None:
            raise HTTPException(401, "Chưa đăng nhập")
        return user_payload(user)

    # ---------- API dữ liệu (tài khoản admin) ----------

    @app.get("/api/tables")
    def tables(user: User = Depends(require_admin)):
        return {"database": "financial", "tables": database_call(database.table_names)}

    @app.get("/api/info")
    def info(user: User = Depends(require_info_user)):
        """Popup Info: user được đọc những bảng/cột nào.

        Admin: toàn bộ dữ liệu, đọc cột thật từ database. Role nghiệp vụ: ma trận tham chiếu
        tĩnh (không chạm database), tách rõ với quyền thực tế đang bị tắt.
        """
        if user.role in BUSINESS_ROLES:
            return {
                "username": user.username,
                "role": user.role,
                "role_label": ROLE_LABELS[user.role],
                "access": "reference",
                "effective_access": {
                    "data_queries": "disabled",
                    "reason": "Chưa có policy runtime được duyệt cho role này; policy "
                    "bird_financial_v1 khai báo role và schema khác.",
                },
                "note": "Bảng dưới đây là quyền tham chiếu, chưa được enforce trong runtime và "
                "không phải quyền truy cập đang có hiệu lực. Chưa có crosswalk được duyệt giữa "
                "role/schema này và bird_financial_v1; mọi API dữ liệu trả 403.",
                "reference": role_reference(user.role),
            }
        columns = database_call(database.table_columns)
        return {
            "username": user.username,
            "role": user.role,
            "access": "full",
            "note": "Admin được đọc toàn bộ dữ liệu; role theo nghiệp vụ chưa được chốt.",
            "tables": [
                {"name": name, "columns": cols, "access": "full"} for name, cols in columns.items()
            ],
        }

    @app.post("/api/sql")
    async def run_sql(request: Request, user: User = Depends(require_admin)):
        """Chạy SQL thủ công (trang Database / bảng kết quả), luôn qua Security Gate."""
        payload = await read_json(request)
        sql = text_field(payload, "sql")
        page = payload.get("page", 1)
        if type(page) is not int or page < 1:
            raise HTTPException(422, "page phải là số nguyên >= 1")
        decision = build_gate(database_call(database.table_names)).check(sql)
        if not decision.allowed:
            raise HTTPException(422, explain_denial(decision))
        try:
            result = await asyncio.to_thread(database_call, database.run_page, sql, page=page)
        except QueryTimeout:
            raise HTTPException(408, "Truy vấn vượt quá thời gian cho phép.") from None
        except QueryError:
            raise HTTPException(400, "Database không thể hoàn tất truy vấn.") from None
        return result.to_dict()

    @app.get("/api/query/samples")
    def query_samples(user: User = Depends(require_admin)):
        """Câu hỏi mẫu cho chế độ Query đang cấu hình; không khẳng định planner đã chạy."""
        try:
            return query_sample_payload()
        except WebQueryConfigurationError:
            raise HTTPException(503, "Cấu hình Query Web không hợp lệ") from None

    @app.get("/api/query/history")
    def query_history(
        limit: int = FastAPIQuery(DEFAULT_HISTORY_LIMIT, ge=1, le=MAX_HISTORY_LIMIT),
        offset: int = FastAPIQuery(0, ge=0, le=MAX_HISTORY_OFFSET),
        user: User = Depends(require_admin),
    ):
        """Danh sách metadata các run Query; chỉ admin được truy cập."""
        try:
            return SQLiteEventStore.from_env().list_runs(limit=limit, offset=offset)
        except EventStoreError:
            raise HTTPException(503, "Không thể đọc lịch sử Query.") from None

    @app.get("/api/query/history/{run_id}")
    def query_history_run(run_id: str, user: User = Depends(require_admin)):
        """Chuỗi event metadata của một run; không trả SQL, câu hỏi hay kết quả."""
        if len(run_id) > 64:
            raise HTTPException(404, "Không tìm thấy lần chạy.")
        try:
            normalized_run_id = str(UUID(run_id))
        except ValueError:
            raise HTTPException(404, "Không tìm thấy lần chạy.") from None
        try:
            events = SQLiteEventStore.from_env().events_for_run(normalized_run_id)
        except EventStoreError:
            raise HTTPException(503, "Không thể đọc lịch sử Query.") from None
        if not events:
            raise HTTPException(404, "Không tìm thấy lần chạy.")
        return {
            "run_id": normalized_run_id,
            "events": [
                {
                    "run_id": event.run_id,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp.isoformat(),
                    "status": event.status,
                    "duration_ms": event.duration_ms,
                    "error_category": event.error_category,
                }
                for event in events
            ],
        }

    @app.get("/api/query/stream/{run_id}")
    async def query_event_stream(
        run_id: str,
        request: Request,
        user: User = Depends(require_admin),
    ):
        """Stream authenticated, run-scoped events and replay them after reconnect."""
        if len(run_id) > 64:
            raise HTTPException(404, "Không tìm thấy lần chạy.")
        try:
            normalized_run_id = str(UUID(run_id))
        except ValueError:
            raise HTTPException(404, "Không tìm thấy lần chạy.") from None
        raw_last_event_id = request.headers.get("last-event-id", "0")
        try:
            last_event_id = int(raw_last_event_id)
        except ValueError:
            raise HTTPException(400, "Event cursor không hợp lệ.") from None
        if last_event_id < 0:
            raise HTTPException(400, "Event cursor không hợp lệ.")

        try:
            subscription = live_events.subscribe(normalized_run_id, last_event_id)
        except RuntimeError:
            raise HTTPException(503, "Live event stream chưa sẵn sàng.") from None

        async def stream():
            def completion_message() -> str:
                records, capture_status = live_events.snapshot(normalized_run_id)
                trace = [serialize_trace_event(event, sequence) for sequence, event in records]
                return _sse_message(
                    "stream_complete",
                    {
                        "run_id": normalized_run_id,
                        "trace_assessment": assess_trace(trace, capture_status=capture_status),
                    },
                )

            try:
                yield ": connected\n\n"
                if subscription.replay_gap:
                    yield _sse_message(
                        "stream_gap",
                        {"run_id": normalized_run_id, "reason": "replay_window_exceeded"},
                    )
                for sequence, event in subscription.replay:
                    yield _sse_event(sequence, event)
                if subscription.completed:
                    yield completion_message()
                    return
                while not await request.is_disconnected():
                    try:
                        item = await asyncio.wait_for(subscription.queue.get(), timeout=15)
                    except TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    if item is None:
                        yield completion_message()
                        return
                    sequence, event = item
                    yield _sse_event(sequence, event)
            finally:
                live_events.unsubscribe(normalized_run_id, subscription.subscriber_id)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
        )

    @app.post("/api/query")
    async def query(request: Request, user: User = Depends(require_admin)):
        """Câu hỏi ngôn ngữ tự nhiên -> AgentController -> kết quả cho trang Query."""
        payload = await read_json(request)
        question = text_field(payload, "question")
        run_id = payload.get("run_id")
        live_sink = None
        if run_id is not None:
            if not isinstance(run_id, str) or len(run_id) > 64:
                raise HTTPException(422, "run_id không hợp lệ")
            try:
                run_id = str(UUID(run_id))
                live_events.prepare(run_id)
            except ValueError:
                raise HTTPException(422, "run_id không hợp lệ") from None
            except RuntimeError:
                raise HTTPException(503, "Live event stream chưa sẵn sàng.") from None
            live_sink = LiveEventSink(live_events)
        try:
            answer = await answer_question(
                database,
                question,
                run_id=run_id,
                live_sink=live_sink,
            )
            if run_id is not None:
                records, capture_status = live_events.snapshot(run_id)
                trace_events = [
                    serialize_trace_event(event, sequence) for sequence, event in records
                ]
                answer["trace_events"] = trace_events
                answer["trace_assessment"] = assess_trace(
                    trace_events, capture_status=capture_status
                )
            return answer
        except EventStoreError:
            raise HTTPException(503, "Không thể khởi tạo event store.") from None
        except DatabaseUnavailable as error:
            raise HTTPException(503, str(error)) from None
        except WebQueryConfigurationError as error:
            safe_detail = {
                "synthetic_database_path_missing": (
                    "Chưa cấu hình database SQLite tổng hợp cho Query Web."
                ),
                "synthetic_database_missing": (
                    "Không tìm thấy database SQLite tổng hợp đã cấu hình."
                ),
                "synthetic_mode_requires_ollama": (
                    "Chế độ SQLite tổng hợp yêu cầu SQLGUARD_PLANNER=ollama."
                ),
                "planner_configuration_invalid": "Cấu hình Ollama không hợp lệ.",
                "query_runtime_unavailable": "Query runtime chưa sẵn sàng.",
                "query_role_missing": "Query runtime thiếu role tin cậy.",
                "query_unknown_role": "Role runtime không được policy cho phép.",
                "query_sqlite_path_missing": "Query runtime thiếu đường dẫn SQLite.",
                "query_sqlite_db_missing": "Không tìm thấy SQLite database đã cấu hình.",
                "query_sqlite_db_unavailable": "Không thể mở SQLite database đã cấu hình.",
                "schema_sqlite_path_missing": "Schema runtime thiếu đường dẫn SQLite.",
                "schema_sqlite_db_missing": "Không tìm thấy SQLite database cho schema.",
                "schema_sqlite_db_unavailable": "Không thể mở SQLite database cho schema.",
                "schema_sqlite_error": "Không thể đọc schema SQLite đã cấu hình.",
                "schema_empty": "SQLite database không có schema được policy hỗ trợ.",
                "schema_unknown_role": "Role schema không được policy cho phép.",
            }.get(error.category, "Query Web chưa sẵn sàng theo cấu hình hiện tại.")
            raise HTTPException(503, safe_detail) from None
        finally:
            if run_id is not None:
                live_events.complete(run_id)

    # ---------- Gắn console Evaluation đã có vào /evaluation/ ----------

    try:
        # Package evaluation nằm ở thư mục gốc repo: chỉ import được khi chạy từ repo.
        from evaluation.web.app import app as evaluation_app
    except ImportError:
        evaluation_app = None
    if evaluation_app is not None:
        app.mount("/evaluation", evaluation_app)
    else:

        @app.get("/evaluation/", include_in_schema=False)
        def evaluation_missing():
            raise HTTPException(503, "Console evaluation chỉ có khi chạy từ thư mục gốc repo")

    return app


app = create_app()
