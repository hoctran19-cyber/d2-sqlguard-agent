# BIRD Financial database (policy `bird-financial-v1`)

The team's evaluation and demo database: BIRD Mini-Dev `financial` (CC BY-SA 4.0, see `NOTICE`) plus a security overlay. Business framing: an internal banking assistant for three roles.

| File | Purpose |
| --- | --- |
| `00_schema.sql` | BIRD tables with primary/foreign keys; lower-case columns so BIRD's PostgreSQL gold SQL runs unchanged |
| `load_financial.py` | Copies `financial.sqlite` into PostgreSQL (row counts verified), then runs the scripts below |
| `05_overlay.sql` | Adds `client.national_id` (synthetic, canaries on the 3 lowest `client_id`s), `client.note`, `trans.note`; indexes |
| `10_roles.sql` | Column-level grants for `sqlguard_teller_*`, `sqlguard_credit_*`, `sqlguard_risk_*`, note writer; read-only, 3 s timeout |
| `20_overlay_seed.sql` | Injection payloads in a few notes (added once IDs are chosen on the loaded data) |

## Role matrix

| Column | Teller (Giao dịch viên) | Credit (Tín dụng) | Risk (Rủi ro–Tài chính) |
| --- | --- | --- | --- |
| `client.national_id` (overlay) | ✗ | ✗ | ✗ |
| `client.birth_date` | ✗ | ✓ | ✗ |
| `loan.*` | ✗ (whole table) | ✓ | ✓ |
| `trans.bank`, `trans.account`, `order.bank_to`, `order.account_to` | ✗ | ✗ | ✓ |
| everything else, including `client.note`, `trans.note` | ✓ | ✓ | ✓ |

## Load

```bash
pip install -e ".[postgres]"
python db/bird_financial/load_financial.py \
    --sqlite <minidev>/MINIDEV/dev_databases/financial/financial.sqlite \
    --dsn "host=localhost user=postgres dbname=sqlguard"
# then set passwords for sqlguard_*_app from your secret store and export
# SQLGUARD_POLICY=bird_financial_v1 SQLGUARD_DB_DSN_TELLER=... SQLGUARD_DB_DSN_CREDIT=... SQLGUARD_DB_DSN_RISK=...
```

Migration status and remaining steps: `docs/threat-model/BIRD_FINANCIAL_MIGRATION_PLAN.md`.
