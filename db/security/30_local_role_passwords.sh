#!/bin/sh
set -eu

: "${SQLGUARD_DB_PASSWORD_SALES:?Set SQLGUARD_DB_PASSWORD_SALES in .env}"
: "${SQLGUARD_DB_PASSWORD_FINANCE:?Set SQLGUARD_DB_PASSWORD_FINANCE in .env}"
: "${SQLGUARD_DB_PASSWORD_OPERATIONS:?Set SQLGUARD_DB_PASSWORD_OPERATIONS in .env}"

psql --no-psqlrc --set=ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" <<'SQL'
\getenv sales_password SQLGUARD_DB_PASSWORD_SALES
\getenv finance_password SQLGUARD_DB_PASSWORD_FINANCE
\getenv operations_password SQLGUARD_DB_PASSWORD_OPERATIONS

ALTER ROLE sqlguard_sales_app PASSWORD :'sales_password';
ALTER ROLE sqlguard_finance_app PASSWORD :'finance_password';
ALTER ROLE sqlguard_ops_app PASSWORD :'operations_password';
SQL
