# Database security layer

Database-enforced least privilege for SQLGuard. It is independent of the AST gate: the tests in `tests/security/test_db_grants.py` send forbidden SQL **with the gate switched off** and expect PostgreSQL itself to refuse.

| File | Purpose | Run as |
| --- | --- | --- |
| `00_reference_schema.sql` | Synthetic reference schema of policy `d2-synthetic-v1` (draft until D2-03 freezes the dataset) | migration owner |
| `10_roles.sql` | Group roles with column-level `GRANT SELECT`, login roles with read-only/timeout/search_path settings, note-writer for the Attack Lab. Idempotent. | migration owner / superuser |
| `20_reference_seed.sql` | Minimal rows with canaries in every forbidden column and two injection notes, for security tests and the demo | migration owner |

## Roles

| Login role (runtime credential) | Inherits | Can do |
| --- | --- | --- |
| `sqlguard_sales_app` | `sqlguard_sales_ro` | `SELECT` on Sales columns only; read-only sessions; 3 s statement timeout |
| `sqlguard_finance_app` | `sqlguard_finance_ro` | `SELECT` on Finance columns only; same session settings |
| `sqlguard_ops_app` | `sqlguard_ops_ro` | `SELECT` on Operations columns only; no `payments` |
| `sqlguard_note_writer_app` | `sqlguard_note_writer` | `UPDATE (note)` on `orders`/`customers` only; Attack Lab backend only, never the agent |

Nobody gets `identity_number`, `CREATE` on `public`, `TEMPORARY` on the database, or `pg_sleep*`.

The grants must stay identical to `src/sqlguard/security/policies/d2_synthetic_v1.json`; the DB test compares every (role, table, column) privilege with the policy.

## Setup

```bash
psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 -f db/security/00_reference_schema.sql
psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 -f db/security/10_roles.sql
psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 -f db/security/20_reference_seed.sql   # test/demo DB only
# Passwords come from a secret store or local env, never from Git:
psql "$ADMIN_DSN" -c "ALTER ROLE sqlguard_sales_app PASSWORD '$SALES_DB_PASSWORD'"
```

The backend reads one DSN per role from `SQLGUARD_DB_DSN_SALES`, `SQLGUARD_DB_DSN_FINANCE`, `SQLGUARD_DB_DSN_OPERATIONS` (`PostgresExecutor.from_env()`), and picks the DSN from the authenticated session's role.

## Known residual risk

Runtime roles can still read PostgreSQL system catalogs such as `pg_catalog.pg_class` (metadata only; `pg_authid` is denied and `information_schema.columns` lists only granted columns). The AST gate blocks every catalog reference; see `docs/threat-model/README.md` §8.
