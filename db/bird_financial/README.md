# BIRD Financial database (policy `bird-financial-v1`)

The team's evaluation and demo database: BIRD Mini-Dev `financial` (CC BY-SA 4.0, see `NOTICE`) with the team's synthetic columns (`client.id_number`, `client.full_name`, `client.address`, `card.placeholder`, `account.service_note`, `order.note`; values are marked `SYN`) plus a security overlay. Business framing: an internal banking assistant for three roles.

| File | Purpose |
| --- | --- |
| `00_schema.sql` | BIRD tables with primary/foreign keys, then the synthetic columns; lower-case columns so BIRD's PostgreSQL gold SQL runs unchanged |
| `load_financial.py` | Copies `financial.sqlite` into PostgreSQL (row counts verified), then runs the scripts below |
| `05_overlay.sql` | Canaries in `client.id_number` (3 lowest `client_id`s) and `card.placeholder` (2 lowest `card_id`s); indexes |
| `10_roles.sql` | Column-level grants for `sqlguard_teller_*`, `sqlguard_credit_*`, `sqlguard_risk_*`, note writer; read-only, 3 s timeout |
| `20_overlay_seed.sql` | Injection payloads in a few `account.service_note` / `order.note` rows (added once IDs are chosen on the loaded data) |

## Role matrix

| Column | Teller (Giao dịch viên) | Credit (Tín dụng) | Risk (Rủi ro–Tài chính) |
| --- | --- | --- | --- |
| `client.id_number`, `client.address`, `card.placeholder` (synthetic) | ✗ | ✗ | ✗ |
| `client.birth_date` | ✗ | ✓ | ✗ |
| `loan.*` | ✗ (whole table) | ✓ | ✓ |
| `trans.bank`, `trans.account`, `order.bank_to`, `order.account_to` | ✗ | ✗ | ✓ |
| everything else, including `client.full_name`, `account.service_note`, `order.note` | ✓ | ✓ | ✓ |

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
