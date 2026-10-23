"""Load BIRD Mini-Dev ``financial.sqlite`` into PostgreSQL and apply the security layer.

Usage (admin / migration-owner DSN of an empty database):

    python db/bird_financial/load_financial.py \
        --sqlite path/to/dev_databases/financial/financial.sqlite \
        --dsn "host=localhost user=postgres dbname=sqlguard"

Steps: 00_schema.sql -> copy every table (row counts verified) -> 05_overlay.sql ->
10_roles.sql -> 20_overlay_seed.sql. Re-running on a loaded database is refused unless
``--replace`` is given, which drops and recreates the BIRD tables.
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Parents before children so foreign keys hold during COPY.
TABLES = ("district", "account", "client", "disp", "card", "loan", "order", "trans")
SCRIPTS_AFTER_COPY = ("05_overlay.sql", "10_roles.sql", "20_overlay_seed.sql")


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def load(sqlite_path: Path, dsn: str, *, replace: bool) -> dict[str, int]:
    import psycopg

    source = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    counts: dict[str, int] = {}
    with psycopg.connect(dsn, autocommit=True) as conn:
        existing = conn.execute("SELECT to_regclass('public.trans') IS NOT NULL").fetchone()[0]
        if existing and not replace:
            raise SystemExit("BIRD tables already exist; pass --replace to reload")
        if replace:
            conn.execute("DROP TABLE IF EXISTS " + ", ".join(map(_quote, TABLES)) + " CASCADE")
        conn.execute((HERE / "00_schema.sql").read_text(encoding="utf-8"))
        for table in TABLES:
            cursor = source.execute(f"SELECT * FROM {_quote(table)}")
            columns = [description[0].lower() for description in cursor.description]
            target = f"{_quote(table)} ({', '.join(map(_quote, columns))})"
            with conn.cursor() as pg, pg.copy(f"COPY {target} FROM STDIN") as copy:
                for row in cursor:
                    copy.write_row(row)
            expected = source.execute(f"SELECT COUNT(*) FROM {_quote(table)}").fetchone()[0]
            (loaded,) = conn.execute(f"SELECT COUNT(*) FROM {_quote(table)}").fetchone()
            if loaded != expected:
                raise SystemExit(f"{table}: loaded {loaded} rows, expected {expected}")
            counts[table] = loaded
        for script in SCRIPTS_AFTER_COPY:
            path = HERE / script
            if path.exists():
                conn.execute(path.read_text(encoding="utf-8"))
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sqlite", type=Path, required=True)
    parser.add_argument("--dsn", required=True)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    for table, count in load(args.sqlite, args.dsn, replace=args.replace).items():
        print(f"{table:10} {count:>9} rows")


if __name__ == "__main__":
    main()
