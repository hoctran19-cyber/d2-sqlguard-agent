-- Database-enforced least privilege, independent of the AST gate (defense in depth).
-- Must stay identical to src/sqlguard/security/policies/d2_synthetic_v1.json; the DB test
-- tests/security/test_db_grants.py checks every (role, table, column) privilege against it.
--
-- Group roles (NOLOGIN) hold privileges; *_app login roles inherit them. Passwords are NOT set
-- here: the deploy step runs ALTER ROLE ... PASSWORD from a secret store / env, never Git.
-- Idempotent: safe to re-run after schema changes. Run as the migration owner / superuser.

DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['sqlguard_sales_ro', 'sqlguard_finance_ro', 'sqlguard_ops_ro'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
    FOREACH r IN ARRAY ARRAY['sqlguard_sales_app', 'sqlguard_finance_app', 'sqlguard_ops_app'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE '
                           'NOREPLICATION CONNECTION LIMIT 5', r);
        END IF;
    END LOOP;
    EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$;

GRANT sqlguard_sales_ro TO sqlguard_sales_app;
GRANT sqlguard_finance_ro TO sqlguard_finance_app;
GRANT sqlguard_ops_ro TO sqlguard_ops_app;

-- Session guard rails applied at login of each runtime role.
ALTER ROLE sqlguard_sales_app SET default_transaction_read_only = on;
ALTER ROLE sqlguard_finance_app SET default_transaction_read_only = on;
ALTER ROLE sqlguard_ops_app SET default_transaction_read_only = on;
ALTER ROLE sqlguard_sales_app SET statement_timeout = '3s';
ALTER ROLE sqlguard_finance_app SET statement_timeout = '3s';
ALTER ROLE sqlguard_ops_app SET statement_timeout = '3s';
ALTER ROLE sqlguard_sales_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE sqlguard_finance_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE sqlguard_ops_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE sqlguard_sales_app SET search_path = public;
ALTER ROLE sqlguard_finance_app SET search_path = public;
ALTER ROLE sqlguard_ops_app SET search_path = public;

-- Nobody but the owner may create objects; no implicit table access.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public
    TO sqlguard_sales_ro, sqlguard_finance_ro, sqlguard_ops_ro;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM sqlguard_sales_ro, sqlguard_finance_ro, sqlguard_ops_ro;

-- Resource-abuse functions callable by PUBLIC by default.
REVOKE EXECUTE ON FUNCTION pg_sleep(double precision) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep_for(interval) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_sleep_until(timestamp with time zone) FROM PUBLIC;

-- Sales: no identity_number, phone_number, unit_cost_vnd, bank_reference.
GRANT SELECT (customer_id, full_name, city, segment, created_at, note)
    ON customers TO sqlguard_sales_ro;
GRANT SELECT (order_id, customer_id, order_date, status, channel, total_amount_vnd, note)
    ON orders TO sqlguard_sales_ro;
GRANT SELECT (order_item_id, order_id, product_id, quantity, unit_price_vnd)
    ON order_items TO sqlguard_sales_ro;
GRANT SELECT (product_id, product_name, category, list_price_vnd)
    ON products TO sqlguard_sales_ro;
GRANT SELECT (payment_id, order_id, paid_date, amount_vnd, method, status)
    ON payments TO sqlguard_sales_ro;

-- Finance: adds unit_cost_vnd and bank_reference; still no identity_number/phone_number.
GRANT SELECT (customer_id, full_name, city, segment, created_at, note)
    ON customers TO sqlguard_finance_ro;
GRANT SELECT (order_id, customer_id, order_date, status, channel, total_amount_vnd, note)
    ON orders TO sqlguard_finance_ro;
GRANT SELECT (order_item_id, order_id, product_id, quantity, unit_price_vnd, unit_cost_vnd)
    ON order_items TO sqlguard_finance_ro;
GRANT SELECT (product_id, product_name, category, list_price_vnd)
    ON products TO sqlguard_finance_ro;
GRANT SELECT (payment_id, order_id, paid_date, amount_vnd, method, status, bank_reference)
    ON payments TO sqlguard_finance_ro;

-- Operations: adds phone_number; no payments table at all.
GRANT SELECT (customer_id, full_name, city, segment, created_at, phone_number, note)
    ON customers TO sqlguard_ops_ro;
GRANT SELECT (order_id, customer_id, order_date, status, channel, total_amount_vnd, note)
    ON orders TO sqlguard_ops_ro;
GRANT SELECT (order_item_id, order_id, product_id, quantity, unit_price_vnd)
    ON order_items TO sqlguard_ops_ro;
GRANT SELECT (product_id, product_name, category, list_price_vnd)
    ON products TO sqlguard_ops_ro;
