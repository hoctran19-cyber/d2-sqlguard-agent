-- Provisional SQLite fixture, not a PostgreSQL migration or production dataset.
CREATE TABLE customer (
  customer_id INTEGER PRIMARY KEY, name TEXT NOT NULL, region TEXT NOT NULL,
  phone_number TEXT, identity_number TEXT, note TEXT NOT NULL
);
CREATE TABLE "order" (
  order_id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customer(customer_id),
  ordered_at TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE item (
  item_id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES "order"(order_id),
  product_name TEXT NOT NULL, quantity INTEGER NOT NULL, unit_price_vnd INTEGER NOT NULL
);
CREATE TABLE payment (
  payment_id INTEGER PRIMARY KEY, order_id INTEGER REFERENCES "order"(order_id),
  amount_vnd INTEGER NOT NULL, status TEXT NOT NULL, paid_at TEXT
);
CREATE TABLE "transaction" (
  transaction_id INTEGER PRIMARY KEY, payment_id INTEGER REFERENCES payment(payment_id),
  kind TEXT NOT NULL, amount_vnd INTEGER NOT NULL, occurred_at TEXT NOT NULL
);
INSERT INTO customer VALUES
 (1,'Customer A','South','PHONE_TEST_001','ID_TEST_001','Giao buoi sang'),
 (2,'Customer B','North','PHONE_TEST_002','ID_TEST_002','Goi truoc khi giao'),
 (3,'Customer C','South','PHONE_TEST_003','ID_TEST_003','Giao tai quay');
INSERT INTO "order" VALUES
 (101,1,'2026-09-10','completed'),(102,2,'2026-09-12','cancelled'),
 (103,3,'2026-09-15','pending');
INSERT INTO item VALUES
 (1,101,'Notebook',2,50000),(2,101,'Pen',5,10000),
 (3,102,'Bag',1,90000),(4,103,'Book',1,70000);
INSERT INTO payment VALUES
 (201,101,150000,'successful','2026-09-10'),
 (202,102,90000,'failed','2026-09-12');
INSERT INTO "transaction" VALUES
 (301,201,'capture',150000,'2026-09-10');
