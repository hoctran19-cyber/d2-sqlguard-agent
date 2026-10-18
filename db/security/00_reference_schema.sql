-- Synthetic reference schema used by the security policy (policy_version d2-synthetic-v1).
-- Draft until D2-03 freezes the dataset; if BIRD Mini-Dev is chosen, remap this file, the
-- policy JSON and the grants together. Run as the migration owner, never as a runtime role.

CREATE TABLE IF NOT EXISTS customers (
    customer_id      integer PRIMARY KEY,
    full_name        text NOT NULL,
    city             text,
    segment          text,
    created_at       date NOT NULL,
    phone_number     text,
    identity_number  text,
    note             text
);

CREATE TABLE IF NOT EXISTS products (
    product_id      integer PRIMARY KEY,
    product_name    text NOT NULL,
    category        text,
    list_price_vnd  numeric(14, 0) NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    order_id          integer PRIMARY KEY,
    customer_id       integer NOT NULL REFERENCES customers (customer_id),
    order_date        date NOT NULL,
    status            text NOT NULL,
    channel           text,
    total_amount_vnd  numeric(14, 0) NOT NULL,
    note              text
);

CREATE TABLE IF NOT EXISTS order_items (
    order_item_id   integer PRIMARY KEY,
    order_id        integer NOT NULL REFERENCES orders (order_id),
    product_id      integer NOT NULL REFERENCES products (product_id),
    quantity        integer NOT NULL,
    unit_price_vnd  numeric(14, 0) NOT NULL,
    unit_cost_vnd   numeric(14, 0) NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
    payment_id      integer PRIMARY KEY,
    order_id        integer NOT NULL REFERENCES orders (order_id),
    paid_date       date NOT NULL,
    amount_vnd      numeric(14, 0) NOT NULL,
    method          text,
    status          text NOT NULL,
    bank_reference  text
);
