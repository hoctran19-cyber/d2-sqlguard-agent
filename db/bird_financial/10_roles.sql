-- Database-enforced least privilege for the BIRD Financial policy (bird-financial-v1),
-- independent of the AST gate. Must stay identical to
-- src/sqlguard/security/policies/bird_financial_v1.json; tests/security/test_db_grants.py checks
-- every (role, table, column) privilege against it. Column-level grants only, so columns added
-- later (such as the overlay) are never readable by default.
--
-- Group roles (NOLOGIN) hold privileges; *_app login roles inherit them. Passwords are NOT set
-- here: the deploy step runs ALTER ROLE ... PASSWORD from a secret store / env, never Git.
-- Idempotent. Run as the migration owner / superuser after 00_schema.sql and 05_overlay.sql.

DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['sqlguard_teller_ro', 'sqlguard_credit_ro', 'sqlguard_risk_ro', 'sqlguard_note_writer'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
    FOREACH r IN ARRAY ARRAY['sqlguard_teller_app', 'sqlguard_credit_app', 'sqlguard_risk_app', 'sqlguard_note_writer_app'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
                           'NOREPLICATION CONNECTION LIMIT 5', r);
        END IF;
    END LOOP;
    EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$;

GRANT sqlguard_teller_ro TO sqlguard_teller_app;
GRANT sqlguard_credit_ro TO sqlguard_credit_app;
GRANT sqlguard_risk_ro TO sqlguard_risk_app;
GRANT sqlguard_note_writer TO sqlguard_note_writer_app;

-- Session guard rails applied at login of each runtime role.
ALTER ROLE sqlguard_teller_app SET default_transaction_read_only = on;
ALTER ROLE sqlguard_credit_app SET default_transaction_read_only = on;
ALTER ROLE sqlguard_risk_app SET default_transaction_read_only = on;
ALTER ROLE sqlguard_teller_app SET statement_timeout = '3s';
ALTER ROLE sqlguard_credit_app SET statement_timeout = '3s';
ALTER ROLE sqlguard_risk_app SET statement_timeout = '3s';
ALTER ROLE sqlguard_note_writer_app SET statement_timeout = '3s';
ALTER ROLE sqlguard_teller_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE sqlguard_credit_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE sqlguard_risk_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE sqlguard_note_writer_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE sqlguard_teller_app SET search_path = public;
ALTER ROLE sqlguard_credit_app SET search_path = public;
ALTER ROLE sqlguard_risk_app SET search_path = public;
ALTER ROLE sqlguard_note_writer_app SET search_path = public;

-- Nobody but the owner may create objects; no implicit table access.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public
    TO sqlguard_teller_ro, sqlguard_credit_ro, sqlguard_risk_ro, sqlguard_note_writer;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM sqlguard_teller_ro, sqlguard_credit_ro, sqlguard_risk_ro, sqlguard_note_writer;

-- Resource-abuse functions callable by PUBLIC by default.
REVOKE EXECUTE ON FUNCTION pg_sleep(double precision) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep_for(interval) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep_until(timestamp with time zone) FROM PUBLIC;

-- Nobody gets client.national_id.

-- Giao dịch viên: no birth_date, no loan table, no counterparty bank/account.
GRANT SELECT (account_id, district_id, frequency, date)
    ON account TO sqlguard_teller_ro;
GRANT SELECT (card_id, disp_id, type, issued)
    ON card TO sqlguard_teller_ro;
GRANT SELECT (client_id, gender, district_id, note)
    ON client TO sqlguard_teller_ro;
GRANT SELECT (disp_id, client_id, account_id, type)
    ON disp TO sqlguard_teller_ro;
GRANT SELECT (district_id, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16)
    ON district TO sqlguard_teller_ro;
GRANT SELECT (order_id, account_id, amount, k_symbol)
    ON "order" TO sqlguard_teller_ro;
GRANT SELECT (trans_id, account_id, date, type, operation, amount, balance, k_symbol, note)
    ON trans TO sqlguard_teller_ro;

-- Tín dụng: adds birth_date and loans; no counterparty bank/account.
GRANT SELECT (account_id, district_id, frequency, date)
    ON account TO sqlguard_credit_ro;
GRANT SELECT (card_id, disp_id, type, issued)
    ON card TO sqlguard_credit_ro;
GRANT SELECT (client_id, gender, birth_date, district_id, note)
    ON client TO sqlguard_credit_ro;
GRANT SELECT (disp_id, client_id, account_id, type)
    ON disp TO sqlguard_credit_ro;
GRANT SELECT (district_id, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16)
    ON district TO sqlguard_credit_ro;
GRANT SELECT (loan_id, account_id, date, amount, duration, payments, status)
    ON loan TO sqlguard_credit_ro;
GRANT SELECT (order_id, account_id, amount, k_symbol)
    ON "order" TO sqlguard_credit_ro;
GRANT SELECT (trans_id, account_id, date, type, operation, amount, balance, k_symbol, note)
    ON trans TO sqlguard_credit_ro;

-- Rủi ro–Tài chính: adds loans and counterparty bank/account; no birth_date.
GRANT SELECT (account_id, district_id, frequency, date)
    ON account TO sqlguard_risk_ro;
GRANT SELECT (card_id, disp_id, type, issued)
    ON card TO sqlguard_risk_ro;
GRANT SELECT (client_id, gender, district_id, note)
    ON client TO sqlguard_risk_ro;
GRANT SELECT (disp_id, client_id, account_id, type)
    ON disp TO sqlguard_risk_ro;
GRANT SELECT (district_id, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16)
    ON district TO sqlguard_risk_ro;
GRANT SELECT (loan_id, account_id, date, amount, duration, payments, status)
    ON loan TO sqlguard_risk_ro;
GRANT SELECT (order_id, account_id, bank_to, account_to, amount, k_symbol)
    ON "order" TO sqlguard_risk_ro;
GRANT SELECT (trans_id, account_id, date, type, operation, amount, balance, k_symbol, bank, account, note)
    ON trans TO sqlguard_risk_ro;

-- Attack Lab note writer: may only rewrite note columns. Never given to the agent.
GRANT SELECT (client_id, note), UPDATE (note) ON client TO sqlguard_note_writer;
GRANT SELECT (trans_id, note), UPDATE (note) ON trans TO sqlguard_note_writer;
