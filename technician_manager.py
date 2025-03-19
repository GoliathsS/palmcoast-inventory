# technician_manager.py
import sqlite3

DB_PATH = "inventory.db"

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
