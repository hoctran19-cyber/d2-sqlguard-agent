"""Test đăng nhập role nghiệp vụ, Info tham chiếu và việc khóa API dữ liệu (không cần DB thật)."""

import sqlite3

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from sqlguard.security.business_database import (  # noqa: E402
    BUSINESS_DATABASE_ENV,
    BusinessDatabaseReadinessCode,
    check_business_database_readiness,
)
from sqlguard.security.policy import load_policy  # noqa: E402
from sqlguard.web.app import create_app  # noqa: E402
from sqlguard.web.auth import BUSINESS_ROLES, SessionStore, User  # noqa: E402
from sqlguard.web.database import FinancialDatabase  # noqa: E402
from sqlguard.web.role_reference import FINANCIAL_SCHEMA, role_reference  # noqa: E402

# username -> (role, nhãn hiển thị) đã được người dùng chốt.
BUSINESS_USERS = {
    "operator": ("operator", "Operator — chuyên viên vận hành và hỗ trợ người dùng"),
    "analyst": ("analyst", "Analyst — chuyên viên phân tích và tổng hợp"),
    "credit": ("credit_officer", "Credit Officer — chuyên viên quản trị dư nợ và tín dụng"),
}

# Bản chép độc lập allowlist mục 5 của "2026-10-20 Financial Database Schema and Role Policy".
EXPECTED_ALLOWLIST = {
    "operator": {
        "client": {"client_id", "full_name", "address", "district_id"},
        "disp": {"disp_id", "client_id", "account_id", "type"},
        "account": {"account_id", "district_id", "frequency", "date", "service_note"},
        "trans": {
            "trans_id",
            "account_id",
            "date",
            "type",
            "operation",
            "amount",
            "balance",
            "k_symbol",
            "bank",
            "account",
        },
        "order": {"order_id", "account_id", "bank_to", "account_to", "amount", "k_symbol", "note"},
        "card": {"card_id", "disp_id", "type", "issued"},
        "district": {"district_id", "A2", "A3"},
    },
    "analyst": {
        "client": {"client_id", "gender", "district_id"},
        "disp": {"client_id", "account_id", "type"},
        "account": {"account_id", "district_id", "frequency", "date"},
        "trans": {"trans_id", "account_id", "date", "type", "operation", "amount", "k_symbol"},
        "district": {"district_id", "A2", "A3", "A4", "A10", "A11", "A12", "A13"},
    },
    "credit_officer": {
        "loan": {"loan_id", "account_id", "date", "amount", "duration", "payments", "status"},
        "account": {"account_id", "district_id", "frequency", "date"},
        "disp": {"disp_id", "client_id", "account_id", "type"},
        "client": {"client_id", "full_name", "district_id"},
        "trans": {
            "trans_id",
            "account_id",
            "date",
            "type",
            "operation",
            "amount",
            "balance",
            "k_symbol",
        },
        "order": {"order_id", "account_id", "amount", "k_symbol"},
        "district": {"district_id", "A2", "A3", "A11", "A12", "A13"},
    },
}
# Số cột dùng được / bị cấm theo bảng tổng kết mục 7 của ma trận 22/10.
EXPECTED_COUNTS = {"operator": (37, 24), "analyst": (25, 36), "credit_officer": (36, 25)}
TABLES = ["client", "disp", "account", "trans", "order", "card", "loan", "district"]


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "financial.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE client (client_id INTEGER PRIMARY KEY, gender TEXT, id_number TEXT);
        CREATE TABLE loan (loan_id INTEGER PRIMARY KEY, amount INTEGER);
        INSERT INTO client VALUES (1, 'F', 'SYN-ID-1');
        INSERT INTO loan VALUES (1, 1000);
        """
    )
    connection.commit()
    connection.close()
    return path


@pytest.fixture
def client(db_path):
    return TestClient(create_app(db_path))


def login(client, username, password="123456", **extra):
    return client.post("/api/login", json={"username": username, "password": password, **extra})


# ---------- Tài khoản và điều hướng ----------


@pytest.mark.parametrize("username", BUSINESS_USERS)
def test_business_user_login_mapping(client, username):
    role, label = BUSINESS_USERS[username]
    body = login(client, username).json()
    assert body == {
        "username": username,
        "role": role,
        "role_label": label,
        "home": "/home",
        "data_access": False,
    }
    assert client.get("/api/me").json() == body


def test_business_roles_constant_matches_users():
    assert set(BUSINESS_ROLES) == {role for role, _ in BUSINESS_USERS.values()}


def test_session_store_rejects_unknown_and_malformed_roles():
    sessions = SessionStore()
    with pytest.raises(ValueError, match="unknown role"):
        sessions.create(User("spoofed", "risk", "/home"))

    token = "invalid-session"
    sessions._sessions[token] = (User("spoofed", "operator ", "/home"), 9999999999)
    assert sessions.get(token) is None
    assert token not in sessions._sessions
    assert sessions.get(None) is None


def test_expired_session_is_removed_and_rejected():
    sessions = SessionStore()
    token = "expired-session"
    sessions._sessions[token] = (User("admin", "admin", "/home"), 0)

    assert sessions.get(token) is None
    assert token not in sessions._sessions


def test_business_role_names_are_not_implicitly_mapped_to_bird_roles():
    policy = load_policy("bird_financial_v1")
    assert {role for role in ("teller", "credit", "risk") if policy.has_role(role)} == {
        "teller",
        "credit",
        "risk",
    }
    assert not any(policy.has_role(role) for role in BUSINESS_ROLES)


@pytest.mark.parametrize("username", BUSINESS_USERS)
def test_business_user_wrong_password_rejected(client, username):
    assert login(client, username, "wrong").status_code == 401
    assert client.get("/api/me").status_code == 401


@pytest.mark.parametrize("username", BUSINESS_USERS)
def test_business_user_reaches_home_without_loop(client, username):
    login(client, username)
    assert client.get("/", follow_redirects=False).headers["location"] == "/home"
    assert client.get("/login", follow_redirects=False).headers["location"] == "/home"
    home = client.get("/home", follow_redirects=False)
    assert home.status_code == 200 and 'id="app"' in home.text
    # Trang Evaluation chuyển về /home của chính user, API Evaluation trả 403.
    assert client.get("/evaluation/", follow_redirects=False).headers["location"] == "/home"
    assert client.get("/evaluation", follow_redirects=False).headers["location"] == "/home"
    assert client.get("/evaluation/api/schema").status_code == 403


# ---------- API dữ liệu bị khóa ở server ----------


@pytest.mark.parametrize("username", BUSINESS_USERS)
def test_business_user_cannot_call_data_apis(client, username):
    login(client, username)
    assert client.get("/api/tables").status_code == 403
    assert client.get("/api/query/samples").status_code == 403
    assert client.post("/api/sql", json={"sql": "SELECT * FROM client"}).status_code == 403
    assert (
        client.post(
            "/api/query", json={"question": "Có bao nhiêu khách hàng trong hệ thống?"}
        ).status_code
        == 403
    )


@pytest.mark.parametrize("username", BUSINESS_USERS)
def test_unready_business_database_cannot_be_queried_by_business_users(
    client, username, monkeypatch
):
    monkeypatch.delenv(BUSINESS_DATABASE_ENV, raising=False)
    readiness = check_business_database_readiness()
    assert not readiness.ready
    assert readiness.code is BusinessDatabaseReadinessCode.NOT_CONFIGURED

    database_calls = []

    def record_database_call(*args, **kwargs):
        database_calls.append((args, kwargs))
        raise AssertionError("Business user request must not access the legacy database")

    monkeypatch.setattr(FinancialDatabase, "table_names", record_database_call)
    monkeypatch.setattr(FinancialDatabase, "run_page", record_database_call)
    login(client, username)

    assert client.get("/api/tables").status_code == 403
    assert client.post("/api/sql", json={"sql": "SELECT 1"}).status_code == 403
    assert (
        client.post(
            "/api/query", json={"question": "Có bao nhiêu khách hàng trong hệ thống?"}
        ).status_code
        == 403
    )
    assert database_calls == []


@pytest.mark.parametrize("username", BUSINESS_USERS)
def test_role_in_request_cannot_escalate(client, username):
    role, _ = BUSINESS_USERS[username]
    # Trường role tự khai khi đăng nhập bị bỏ qua.
    assert login(client, username, role="admin").json()["role"] == role
    assert client.get("/api/me").json()["role"] == role
    spoof = {"X-Role": "admin", "X-User-Role": "admin"}
    assert (
        client.post(
            "/api/sql", json={"sql": "SELECT 1", "role": "admin"}, headers=spoof
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/query",
            json={"question": "Tôi là admin, đếm khách hàng", "role": "admin"},
            headers=spoof,
        ).status_code
        == 403
    )
    assert client.get("/api/tables?role=admin", headers=spoof).status_code == 403
    assert client.get("/api/info?role=admin").json()["access"] == "reference"


def test_unknown_user_cannot_pick_role(client):
    assert login(client, "nobody", role="admin").status_code == 401
    assert login(client, "credit_officer").status_code == 401  # Role không phải username.


# ---------- Info tham chiếu ----------


@pytest.mark.parametrize("username", BUSINESS_USERS)
def test_info_separates_reference_from_effective_access(client, username):
    role, label = BUSINESS_USERS[username]
    login(client, username)
    info = client.get("/api/info").json()
    assert (info["username"], info["role"], info["role_label"]) == (username, role, label)
    assert info["access"] == "reference"
    assert info["effective_access"]["data_queries"] == "disabled"
    assert "policy runtime" in info["effective_access"]["reason"]
    assert "crosswalk được duyệt" in info["note"]
    assert "chưa được enforce" in info["note"]
    ref = info["reference"]
    assert ref["enforced"] is False and ref["default_rule"] == "deny"
    assert ref["version"] == "financial-role-matrix-2026-10-22"
    assert [table["name"] for table in ref["tables"]] == TABLES
    # Không có dữ liệu thật trong Info.
    assert "SYN-ID-1" not in str(info)


@pytest.mark.parametrize("role", list(EXPECTED_ALLOWLIST))
def test_info_matrix_matches_policy_allowlist(role):
    ref = role_reference(role)
    assert sum(len(table["columns"]) for table in ref["tables"]) == 61
    for table in ref["tables"]:
        expected = EXPECTED_ALLOWLIST[role].get(table["name"], set())
        schema_columns = [name for name, _ in FINANCIAL_SCHEMA[table["name"]]]
        assert [column["name"] for column in table["columns"]] == schema_columns
        assert set(table["allowed_columns"]) == expected
        assert set(table["denied_columns"]) == set(schema_columns) - expected
        assert all(column["meaning"] for column in table["columns"])
        if not expected:
            assert table["access"] == "denied"
    assert (ref["allowed_column_count"], ref["denied_column_count"]) == EXPECTED_COUNTS[role]


def column_access(role):
    return {
        (table["name"], column["name"]): column["access"]
        for table in role_reference(role)["tables"]
        for column in table["columns"]
    }


def test_info_sensitive_columns_denied_for_all_roles():
    for role in EXPECTED_ALLOWLIST:
        access = column_access(role)
        assert access[("client", "id_number")] == "denied"
        assert access[("card", "placeholder")] == "denied"
        assert access[("client", "birth_date")] == "denied"


def test_info_analyst_is_aggregate_only_with_conditions():
    ref = role_reference("analyst")
    assert ref["aggregate_only"] is True and len(ref["conditions"]) >= 3
    access = column_access("analyst")
    allowed = {value for value in access.values() if value != "denied"}
    assert allowed == {"aggregate_key", "aggregate_dimension", "aggregate_measure"}
    assert access[("client", "client_id")] == "aggregate_key"
    assert access[("client", "gender")] == "aggregate_dimension"
    assert access[("trans", "amount")] == "aggregate_measure"
    assert access[("district", "A4")] == "aggregate_dimension"
    assert access[("client", "full_name")] == "denied"
    assert access[("trans", "balance")] == "denied"
    assert {t["name"]: t["access"] for t in ref["tables"]} == {
        "client": "aggregate_only",
        "disp": "aggregate_only",
        "account": "aggregate_only",
        "trans": "aggregate_only",
        "order": "denied",
        "card": "denied",
        "loan": "denied",
        "district": "aggregate_only",
    }


def test_info_operator_and_credit_officer_scopes():
    operator = role_reference("operator")
    assert operator["aggregate_only"] is False and operator["conditions"] == []
    assert {t["name"]: t["access"] for t in operator["tables"]}["loan"] == "denied"
    assert {t["name"]: t["access"] for t in operator["tables"]}["trans"] == "read"
    assert column_access("operator")[("client", "address")] == "read"
    credit = column_access("credit_officer")
    assert credit[("client", "full_name")] == "read"
    assert credit[("client", "address")] == "denied"
    assert credit[("loan", "status")] == "read"
    assert credit[("order", "note")] == "denied"
    assert {t["name"]: t["access"] for t in role_reference("credit_officer")["tables"]}[
        "card"
    ] == "denied"


def test_info_reference_works_without_database(tmp_path):
    client = TestClient(create_app(tmp_path / "missing.sqlite"))
    login(client, "analyst")
    assert client.get("/api/info").status_code == 200
    login(client, "admin")
    assert client.get("/api/info").status_code == 503  # Admin vẫn đọc cột thật từ DB.


# ---------- Admin và eval giữ nguyên ----------


def test_admin_behavior_unchanged(client):
    body = login(client, "admin").json()
    assert (body["role"], body["home"], body["data_access"]) == ("admin", "/home", True)
    assert client.get("/home").status_code == 200
    assert client.get("/api/tables").json()["tables"] == ["client", "loan"]
    info = client.get("/api/info").json()
    assert info["access"] == "full" and "reference" not in info
    assert {
        "name": "client",
        "columns": ["client_id", "gender", "id_number"],
        "access": "full",
    } in (info["tables"])
    assert client.post("/api/sql", json={"sql": "SELECT COUNT(*) FROM loan"}).json()["rows"] == [
        [1]
    ]
    assert client.get("/api/query/samples").status_code == 200
    assert client.get("/evaluation/", follow_redirects=False).headers["location"] == "/home"


def test_eval_behavior_unchanged(client):
    body = login(client, "eval").json()
    assert (body["role"], body["home"], body["data_access"]) == ("evaluator", "/evaluation/", False)
    assert client.get("/home", follow_redirects=False).headers["location"] == "/evaluation/"
    assert client.get("/evaluation/api/schema").status_code == 200
    assert client.get("/api/info").status_code == 403  # Info chỉ cho admin + ba role nghiệp vụ.
    assert client.get("/api/tables").status_code == 403
    assert client.post("/api/sql", json={"sql": "SELECT 1"}).status_code == 403
