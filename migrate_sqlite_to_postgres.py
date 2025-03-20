import sqlite3
import psycopg2
from psycopg2.extras import execute_values

# --- CONFIGURATION ---
SQLITE_DB = "inventory.db"  # local path to your SQLite DB
POSTGRES_URL = "YOUR_RENDER_POSTGRES_CONNECTION_STRING"  # 🔁 Replace this

# --- Connect to both databases ---
sqlite_conn = sqlite3.connect(SQLITE_DB)
sqlite_cur = sqlite_conn.cursor()

pg_conn = psycopg2.connect(POSTGRES_URL)
pg_cur = pg_conn.cursor()

# --- Migrate products ---
sqlite_cur.execute("SELECT name, barcode, stock, min_stock, cost_per_unit, siteone_sku FROM products")
products = sqlite_cur.fetchall()
execute_values(pg_cur,
    "INSERT INTO products (name, barcode, stock, min_stock, cost_per_unit, siteone_sku) VALUES %s",
    products)

# --- Migrate technicians ---
sqlite_cur.execute("SELECT name FROM technicians")
technicians = sqlite_cur.fetchall()
execute_values(pg_cur,
    "INSERT INTO technicians (name) VALUES %s",
    technicians)

# --- Migrate scan logs ---
sqlite_cur.execute("SELECT product_id, action, timestamp, technician FROM scan_logs")
scan_logs = sqlite_cur.fetchall()
execute_values(pg_cur,
    "INSERT INTO scan_logs (product_id, action, timestamp, technician) VALUES %s",
    scan_logs)

pg_conn.commit()

print("✅ Migration complete!")

# --- Close connections ---
pg_cur.close()
pg_conn.close()
sqlite_cur.close()
sqlite_conn.close()
