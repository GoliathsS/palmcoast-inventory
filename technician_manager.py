# technician_manager.py
import psycopg2

# Use your actual PostgreSQL connection string
DATABASE_URL = "postgresql://palmcoast_inventory_db_user:3vu51Xo0fR2xUXaJKzezTTngjgoY9Ko9@dpg-cve249ogph6c73cbbbb0-a.virginia-postgres.render.com/palmcoast_inventory_db"

def add_technician(name):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("INSERT INTO technicians (name) VALUES (%s) ON CONFLICT (name) DO NOTHING", (name,))
    conn.commit()
    cur.close()
    conn.close()

def remove_technician(name):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("DELETE FROM technicians WHERE name = %s", (name,))
    conn.commit()
    cur.close()
    conn.close()

def get_all_technicians():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT name FROM technicians ORDER BY name ASC")
    results = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()
    return results

