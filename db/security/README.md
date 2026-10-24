# Database security layer

Database-enforced least privilege for SQLGuard. It is independent of the AST gate: the tests in `tests/security/test_db_grants.py` send forbidden SQL **with the gate switched off** and expect PostgreSQL itself to refuse.

| File | Purpose | Run as |
| --- | --- | --- |
| `00_reference_schema.sql` | Synthetic reference schema of policy `d2-synthetic-v1` (draft until D2-03 freezes the dataset) | migration owner |
| `10_roles.sql` | Group roles with column-level `GRANT SELECT`, login roles with read-only/timeout/search_path settings. Idempotent. (The Attack Lab no longer uses PostgreSQL; see `docs/threat-model/ATTACK_LAB.md`.) | migration owner / superuser |
| `20_reference_seed.sql` | Minimal rows with canaries in every forbidden column and the injection notes used by `evaluation/datasets/security/injection_cases_v1.json` (customers #2–3, orders #1–3); customer #1 keeps a clean note | migration owner |
| `30_local_role_passwords.sh` | Local-only bootstrap of the three agent login passwords from environment variables; uses psql literal quoting | local PostgreSQL container |

## Roles

| Login role (runtime credential) | Inherits | Can do |
| --- | --- | --- |
| `sqlguard_sales_app` | `sqlguard_sales_ro` | `SELECT` on Sales columns only; read-only sessions; 3 s statement timeout |
| `sqlguard_finance_app` | `sqlguard_finance_ro` | `SELECT` on Finance columns only; same session settings |
| `sqlguard_ops_app` | `sqlguard_ops_ro` | `SELECT` on Operations columns only; no `payments` |

Nobody gets `identity_number`, `CREATE` on `public`, `TEMPORARY` on the database, or `pg_sleep*`.

The grants must stay identical to `src/sqlguard/security/policies/d2_synthetic_v1.json`; the DB test compares every (role, table, column) privilege with the policy.

## Local PostgreSQL 16 sandbox

Prerequisites: Docker Engine or Docker Desktop with the Compose plugin. This sandbox loads the
synthetic schema and seed rows above; it does not load BIRD data. It is intended for local
development and disposable security tests, not for production.

1. Copy `.env.example` to `.env`, then replace every `replace-with-...` password with a unique
   local secret using URL-safe characters (letters, digits, `-`, `_`). Keep the file private
   (`chmod 600 .env`); `.env` is ignored by Git. The three `SQLGUARD_DB_PASSWORD_*` values must
   match the corresponding host DSNs. If you change `SQLGUARD_PG_PORT`, update the port in all
   four DSNs too. Do not commit `.env`.
2. Start PostgreSQL:

```bash
docker compose --env-file .env -f compose.postgres-sandbox.yml up -d
```

Compose binds the database only to `127.0.0.1` (port `SQLGUARD_PG_PORT`, default `54329`) and
uses the named volume `sqlguard-pg16-data`. The official PostgreSQL image processes
`/docker-entrypoint-initdb.d` files in name order, only when it initializes an empty data
directory. The existing schema, roles and seed SQL therefore run before the local password
bootstrap. Editing those files does not update an already initialized volume; use the reset
procedure below when you intentionally need a fresh sandbox.

3. Inspect service health and verify that the schema and seed tables initialized:

```bash
docker compose --env-file .env -f compose.postgres-sandbox.yml ps
docker compose --env-file .env -f compose.postgres-sandbox.yml exec -T postgres \
  psql -U sqlguard_admin -d sqlguard_local -c \
  "SELECT current_database(), (SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public') AS public_tables, (SELECT count(*) FROM customers) AS customers, (SELECT count(*) FROM products) AS products, (SELECT count(*) FROM orders) AS orders, (SELECT count(*) FROM order_items) AS order_items, (SELECT count(*) FROM payments) AS payments"
```

4. Configure a host-side SQLGuard process with the role-specific DSNs in `.env`. The examples
   point at the three `sqlguard_*_app` login roles and the local database. To export the
   settings into a development shell without printing them, source your own shell-compatible
   `.env`:

```bash
set -a
. ./.env
set +a
```

`PostgresExecutor.from_env()` reads `SQLGUARD_DB_DSN_SALES`,
`SQLGUARD_DB_DSN_FINANCE`, and `SQLGUARD_DB_DSN_OPERATIONS`, then selects only the DSN matching
the authenticated role.

The security integration tests can use the local admin connection (the test fixture creates
and drops its own temporary databases):

```bash
python -m pytest -q -m db tests/security/test_db_grants.py tests/security/test_agent_postgres_e2e.py
```

Those tests reset the cluster-wide runtime-role passwords to temporary test values. To restore
the local `.env` passwords before using SQLGuard again, rerun the password bootstrap explicitly:

```bash
docker compose --env-file .env -f compose.postgres-sandbox.yml exec -T postgres \
  sh /docker-entrypoint-initdb.d/30_local_role_passwords.sh
```

Stop the service without deleting data:

```bash
docker compose --env-file .env -f compose.postgres-sandbox.yml down
```

Reset the sandbox only when you intend to permanently delete its local database data:

```bash
docker compose --env-file .env -f compose.postgres-sandbox.yml down -v
```

The `-v` option deletes the named volume and all sandbox data. Normal shutdown with `down`
does not delete it. Do not run `docker compose config` in a shared terminal: it renders
interpolated environment values, including passwords.

## Known residual risk

Runtime roles can still read PostgreSQL system catalogs such as `pg_catalog.pg_class` (metadata only; `pg_authid` is denied and `information_schema.columns` lists only granted columns). The AST gate blocks every catalog reference; see `docs/threat-model/README.md` §8.
