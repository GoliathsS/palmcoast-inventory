
-- PostgreSQL schema for Palm Coast Inventory

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    barcode TEXT UNIQUE NOT NULL,
    stock INTEGER DEFAULT 0,
    min_stock INTEGER DEFAULT 0,
    cost_per_unit REAL DEFAULT 0,
    siteone_sku TEXT
);

CREATE TABLE technicians (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE scan_logs (
    id SERIAL PRIMARY KEY,
    product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
    action TEXT,
    timestamp TEXT,
    technician TEXT
);
