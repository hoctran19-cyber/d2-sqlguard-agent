"""Test web app SQLGuard trên một database SQLite nhỏ mô phỏng các bảng financial."""

import sqlite3

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sqlguard.web.app import create_app  # noqa: E402
from sqlguard.web.auth import SESSION_COOKIE  # noqa: E402
from sqlguard.web.database import FinancialDatabase, QueryTimeout  # noqa: E402


@pytest.fixture
def db_path(tmp_path):
    """Database giả lập: đủ bảng/cột cho các câu hỏi mẫu, 25 khoản vay để có 2 trang."""
    path = tmp_path / "financial.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE client (client_id INTEGER PRIMARY KEY, gender TEXT);
        CREATE TABLE account (account_id INTEGER PRIMARY KEY, frequency TEXT);
        CREATE TABLE card (card_id INTEGER PRIMARY KEY, type TEXT);
        CREATE TABLE loan (loan_id INTEGER PRIMARY KEY, account_id INTEGER, date TEXT,
                           amount INTEGER, duration INTEGER, status TEXT);
        CREATE TABLE trans (trans_id INTEGER PRIMARY KEY, account_id INTEGER, date TEXT,
                            type TEXT, operation TEXT, amount REAL, balance REAL);
        CREATE TABLE "order" (order_id INTEGER PRIMARY KEY, amount REAL, k_symbol TEXT);
        INSERT INTO client VALUES (1, 'F'), (2, 'M'), (3, 'F');
        INSERT INTO "order" VALUES (1, 10.5, NULL);
        """
    )
    connection.executemany(
        "INSERT INTO loan VALUES (?, 1, '1997-01-01', ?, 12, 'A')",
        [(i, i * 1000) for i in range(1, 26)],
    )
    connection.commit()
    connection.close()
    return path


@pytest.fixture
def anonymous(db_path):
    return TestClient(create_app(db_path))


def login(client, username, password="123456"):
    return client.post("/api/login", json={"username": username, "password": password})


@pytest.fixture
def admin(anonymous):
    assert login(anonymous, "admin").status_code == 200
    return anonymous


# ---------- Điều hướng và đăng nhập ----------


def test_root_redirects_by_login_state(anonymous):
    assert anonymous.get("/", follow_redirects=False).headers["location"] == "/login"
    assert anonymous.get("/home", follow_redirects=False).headers["location"] == "/login"
    login(anonymous, "admin")
    assert anonymous.get("/", follow_redirects=False).headers["location"] == "/home"
    assert anonymous.get("/login", follow_redirects=False).headers["location"] == "/home"
    assert anonymous.get("/home").status_code == 200


def test_wrong_password_is_rejected_and_api_needs_login(anonymous):
    assert login(anonymous, "admin", "wrong").status_code == 401
    assert login(anonymous, "nobody").status_code == 401
    assert anonymous.get("/api/me").status_code == 401
    assert anonymous.get("/api/tables").status_code == 401


def test_unknown_session_cookie_does_not_authorize_data_api(anonymous):
    anonymous.cookies.set(SESSION_COOKIE, "unknown-session-token")

    assert anonymous.get("/api/tables").status_code == 401


def test_session_cookie_is_httponly_and_logout_ends_session(anonymous):
    response = login(anonymous, "admin")
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert anonymous.get("/api/me").json()["username"] == "admin"
    anonymous.post("/api/logout", json={})
    assert anonymous.get("/api/me").status_code == 401


def test_eval_account_only_reaches_evaluation(anonymous):
    body = login(anonymous, "eval").json()
    assert body["home"] == "/evaluation/"
    assert anonymous.get("/", follow_redirects=False).headers["location"] == "/evaluation/"
    assert anonymous.get("/home", follow_redirects=False).headers["location"] == "/evaluation/"
    assert "Evaluation Console" in anonymous.get("/evaluation/").text
    assert anonymous.get("/evaluation/api/schema").status_code == 200
    assert anonymous.get("/api/tables").status_code == 403


def test_admin_and_anonymous_cannot_open_evaluation(anonymous):
    assert anonymous.get("/evaluation/", follow_redirects=False).headers["location"] == "/login"
    assert anonymous.get("/evaluation/api/schema").status_code == 401
    login(anonymous, "admin")
    assert anonymous.get("/evaluation/", follow_redirects=False).headers["location"] == "/home"
    assert anonymous.get("/evaluation/api/schema").status_code == 403


def test_post_requires_json_and_same_origin(admin):
    form = admin.post("/api/sql", content=b"sql=x", headers={"Content-Type": "text/plain"})
    assert form.status_code == 415
    foreign = admin.post(
        "/api/sql", json={"sql": "SELECT 1"}, headers={"Origin": "http://evil.example"}
    )
    assert foreign.status_code == 403


# ---------- Database: danh sách bảng, phân trang, Security Gate ----------


def test_tables_and_info(admin):
    tables = admin.get("/api/tables").json()["tables"]
    assert tables == ["account", "card", "client", "loan", "order", "trans"]
    info = admin.get("/api/info").json()
    assert info["access"] == "full"
    assert {"name": "client", "columns": ["client_id", "gender"], "access": "full"} in info[
        "tables"
    ]


def test_sql_is_paginated_by_20_rows(admin):
    first = admin.post("/api/sql", json={"sql": "SELECT * FROM loan ORDER BY loan_id"}).json()
    assert (first["total_rows"], first["total_pages"], len(first["rows"])) == (25, 2, 20)
    second = admin.post(
        "/api/sql", json={"sql": "SELECT * FROM loan ORDER BY loan_id;", "page": 2}
    ).json()
    assert [row[0] for row in second["rows"]] == [21, 22, 23, 24, 25]
    # Trang vượt quá thì trả trang cuối; bảng tên trùng từ khóa vẫn truy vấn được.
    assert admin.post("/api/sql", json={"sql": "SELECT * FROM loan", "page": 9}).json()["page"] == 2
    order = admin.post("/api/sql", json={"sql": 'SELECT * FROM "order"'}).json()
    assert order["rows"] == [[1, 10.5, None]]


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM loan",
        "SELECT 1; DROP TABLE loan",
        "SELECT * FROM sqlite_master",
        "ATTACH DATABASE 'x.db' AS x",
        "",
    ],
)
def test_gate_blocks_unsafe_sql(admin, sql):
    response = admin.post("/api/sql", json={"sql": sql})
    assert response.status_code == 422
    # Lệnh ghi bị chặn trước khi tới database: bảng vẫn còn đủ dữ liệu.
    assert admin.post("/api/sql", json={"sql": "SELECT * FROM loan"}).json()["total_rows"] == 25


def test_sql_errors_and_bad_page(admin):
    response = admin.post("/api/sql", json={"sql": "SELECT private_marker FROM client"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Database không thể hoàn tất truy vấn."}
    assert "private_marker" not in response.text
    assert "Traceback" not in response.text
    assert admin.post("/api/sql", json={"sql": "SELECT 1", "page": 0}).status_code == 422
    assert admin.post("/api/sql", json={"sql": "SELECT 1", "page": True}).status_code == 422


def test_sql_timeout_does_not_expose_exception_details(admin, monkeypatch):
    def timeout(*args, **kwargs):
        raise QueryTimeout("private SQL detail at /private/database.sqlite")

    monkeypatch.setattr(FinancialDatabase, "run_page", timeout)

    response = admin.post("/api/sql", json={"sql": "SELECT private_marker FROM client"})

    assert response.status_code == 408
    assert response.json() == {"detail": "Truy vấn vượt quá thời gian cho phép."}
    assert "private SQL detail" not in response.text
    assert "/private/database.sqlite" not in response.text
    assert "private_marker" not in response.text


def test_slow_query_is_interrupted(db_path):
    database = FinancialDatabase(db_path)
    with pytest.raises(QueryTimeout):
        database.run_page(
            "SELECT COUNT(*) FROM loan a, loan b, loan c, loan d, loan e", timeout_seconds=0.001
        )


def test_missing_database_returns_503(tmp_path):
    client = TestClient(create_app(tmp_path / "missing.sqlite"))
    login(client, "admin")
    assert client.get("/api/tables").status_code == 503


# ---------- Query: câu hỏi qua AgentController ----------


def test_sample_question_gives_full_answer(admin):
    samples = admin.get("/api/query/samples").json()
    assert samples["planner"] == "demo-no-llm"
    body = admin.post(
        "/api/query", json={"question": "Có bao nhiêu khách hàng trong hệ thống?"}
    ).json()
    assert body["status"] == "full"
    assert body["sql"] == "SELECT COUNT(*) AS client_count FROM client"
    assert body["result"]["columns"] == ["client_count"]
    assert body["result"]["rows"] == [[3]]
    assert body["run_id"]
    assert {"security_check_completed", "tool_call_completed"} <= {
        event["type"] for event in body["events"]
    }


def test_write_request_is_refused_without_table(admin):
    body = admin.post("/api/query", json={"question": "Xóa toàn bộ dữ liệu khoản vay."}).json()
    assert body["status"] == "refused"
    assert body["sql"] == "DELETE FROM loan"
    assert body["result"] is None
    assert "SELECT" in body["reason"]
    assert admin.post("/api/sql", json={"sql": "SELECT * FROM loan"}).json()["total_rows"] == 25


def test_unknown_question_reports_missing_llm(admin):
    body = admin.post("/api/query", json={"question": "Doanh thu tháng 9?"}).json()
    assert body["status"] == "failed"
    assert body["sql"] is None and body["result"] is None
    assert "LLM" in body["reason"]


def test_query_requires_question(admin):
    assert admin.post("/api/query", json={}).status_code == 422
    assert admin.post("/api/query", json={"question": "x" * 6000}).status_code == 422
