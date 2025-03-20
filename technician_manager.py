# technician_manager.py
import psycopg2
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'inventory.db')
# This is just an example, replace with your actual Render internal DB URL
conn = psycopg2.connect(
    "postgresql://palmcoast_inventory_db_user:3vu51Xo0fR2xUXaJKzezTTngjgoY9Ko9@dpg-cve249ogph6c73cbbbb0-a.virginia-postgres.render.com/palmcoast_inventory_db"
)

def init_technician_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS technicians (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        """)
        conn.commit()

def add_technician(name):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO technicians (name) VALUES (?)", (name,))
        conn.commit()

def remove_technician(name):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM technicians WHERE name = ?", (name,))
        conn.commit()

def get_all_technicians():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM technicians ORDER BY name ASC")
        return [row[0] for row in c.fetchall()]

if __name__ == "__main__":
    init_technician_db()
    print("✅ Technician table ready.")
