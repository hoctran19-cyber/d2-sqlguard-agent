"""Create a small synthetic SQLite database for the SQLGuard CLI demo."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path


def create_demo_database(path: str | Path) -> Path:
    """Create a policy-shaped fixture with synthetic rows; never overwrite an existing file."""
    destination = Path(path).expanduser()
    if destination.exists():
        raise FileExistsError("output file already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(destination) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE customers (
                customer_id INTEGER PRIMARY KEY,
                full_name TEXT NOT NULL,
                city TEXT NOT NULL,
                segment TEXT NOT NULL,
                created_at TEXT NOT NULL,
                phone_number TEXT,
                identity_number TEXT,
                note TEXT
            );
            CREATE TABLE orders (
                order_id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                order_date TEXT NOT NULL,
                status TEXT NOT NULL,
                channel TEXT NOT NULL,
                total_amount_vnd INTEGER NOT NULL,
                note TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
            );
            CREATE TABLE products (
                product_id INTEGER PRIMARY KEY,
                product_name TEXT NOT NULL,
                category TEXT NOT NULL,
                list_price_vnd INTEGER NOT NULL
            );
            CREATE TABLE order_items (
                order_item_id INTEGER PRIMARY KEY,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price_vnd INTEGER NOT NULL,
                unit_cost_vnd INTEGER NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(order_id),
                FOREIGN KEY (product_id) REFERENCES products(product_id)
            );
            CREATE TABLE payments (
                payment_id INTEGER PRIMARY KEY,
                order_id INTEGER NOT NULL,
                paid_date TEXT NOT NULL,
                amount_vnd INTEGER NOT NULL,
                method TEXT NOT NULL,
                status TEXT NOT NULL,
                bank_reference TEXT,
                FOREIGN KEY (order_id) REFERENCES orders(order_id)
            );
            INSERT INTO customers VALUES
                (1, 'Demo Customer A', 'Hanoi', 'retail', '2025-01-01',
                 '0000000000', 'SYNTHETIC-ID-001', 'synthetic fixture'),
                (2, 'Demo Customer B', 'Da Nang', 'enterprise', '2025-01-02',
                 '0000000000', 'SYNTHETIC-ID-002', 'synthetic fixture');
            INSERT INTO orders VALUES
                (101, 1, '2025-01-03', 'completed', 'web', 120000, 'synthetic fixture'),
                (102, 2, '2025-01-04', 'shipped', 'store', 230000, 'synthetic fixture');
            INSERT INTO products VALUES
                (201, 'Demo Product A', 'general', 60000),
                (202, 'Demo Product B', 'general', 115000);
            INSERT INTO order_items VALUES
                (301, 101, 201, 2, 60000, 30000),
                (302, 102, 202, 2, 115000, 70000);
            INSERT INTO payments VALUES
                (401, 101, '2025-01-03', 120000, 'card', 'success', 'SYNTHETIC-REF-001'),
                (402, 102, '2025-01-04', 230000, 'transfer', 'success', 'SYNTHETIC-REF-002');
            """
        )
    return destination


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create the synthetic SQLite database used by the SQLGuard demo."
    )
    parser.add_argument(
        "--output",
        default="data/sqlguard-demo.sqlite",
        help="new database path (existing files are never overwritten)",
    )
    args = parser.parse_args(argv)
    try:
        create_demo_database(args.output)
    except (OSError, sqlite3.Error, ValueError):
        print("Could not create the synthetic demo database.", file=sys.stderr)
        return 1
    print("Created synthetic SQLGuard demo database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
