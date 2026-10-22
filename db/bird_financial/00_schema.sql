-- BIRD Mini-Dev "financial" database (CC BY-SA 4.0, https://github.com/bird-bench/mini_dev),
-- recreated in PostgreSQL with primary and foreign keys. Column names are lower case so the
-- BIRD PostgreSQL gold SQL (unquoted A2..A16, quoted "order") runs unchanged.
-- Run as the migration owner. Data is loaded by load_financial.py.

CREATE TABLE IF NOT EXISTS district (
    district_id integer PRIMARY KEY,
    a2 text, a3 text, a4 text, a5 text, a6 text, a7 text,
    a8 integer, a9 integer, a10 real, a11 integer, a12 real, a13 real,
    a14 integer, a15 integer, a16 integer
);

CREATE TABLE IF NOT EXISTS account (
    account_id integer PRIMARY KEY,
    district_id integer NOT NULL REFERENCES district (district_id),
    frequency text,
    date date
);

CREATE TABLE IF NOT EXISTS client (
    client_id integer PRIMARY KEY,
    gender text,
    birth_date date,
    district_id integer NOT NULL REFERENCES district (district_id)
);

CREATE TABLE IF NOT EXISTS disp (
    disp_id integer PRIMARY KEY,
    client_id integer NOT NULL REFERENCES client (client_id),
    account_id integer NOT NULL REFERENCES account (account_id),
    type text
);

CREATE TABLE IF NOT EXISTS card (
    card_id integer PRIMARY KEY,
    disp_id integer NOT NULL REFERENCES disp (disp_id),
    type text,
    issued date
);

CREATE TABLE IF NOT EXISTS loan (
    loan_id integer PRIMARY KEY,
    account_id integer NOT NULL REFERENCES account (account_id),
    date date,
    amount integer,
    duration integer,
    payments real,
    status text
);

CREATE TABLE IF NOT EXISTS "order" (
    order_id integer PRIMARY KEY,
    account_id integer NOT NULL REFERENCES account (account_id),
    bank_to text,
    account_to integer,
    amount real,
    k_symbol text
);

CREATE TABLE IF NOT EXISTS trans (
    trans_id integer PRIMARY KEY,
    account_id integer NOT NULL REFERENCES account (account_id),
    date date,
    type text,
    operation text,
    amount integer,
    balance integer,
    k_symbol text,
    bank text,
    account integer
);
