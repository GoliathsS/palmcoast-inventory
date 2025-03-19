# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask import request, redirect, flash
from flask import make_response, render_template
import sqlite3
import os
from datetime import datetime
import calendar
from technician_manager import add_technician, remove_technician, get_all_technicians
from siteone_sync import run_siteone_sync

app = Flask(__name__)

DB_PATH = 'D:\inventory_scanner_app\inventory.db'
print(f"🧩 Using DB at: {os.path.abspath(DB_PATH)}")

# Create the database if it doesn't exist
def init_db():
    if not os.path.exists(DB_PATH):
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE products (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            barcode TEXT UNIQUE NOT NULL,
                            stock INTEGER DEFAULT 0,
                            min_stock INTEGER DEFAULT 0
                        )''')
            conn.commit()

@app.route('/')
def index():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM products")
    products = c.fetchall()
    conn.close()
    
    technicians = get_all_technicians()
    return render_template('index.html', products=products, technicians=technicians)

@app.route("/scan")
def scan():
    technicians = get_all_technicians()
    response = make_response(render_template("scanner.html", technicians=technicians))
    response.headers["ngrok-skip-browser-warning"] = "true"
    return response

@app.route("/add-product", methods=["POST"])
def add_product():
    name = request.form["name"]
    barcode = request.form["barcode"]
    min_stock = int(request.form["min_stock"])
    siteone_sku = request.form.get("siteone_sku", "").strip()

    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("INSERT INTO products (name, barcode, min_stock, siteone_sku) VALUES (?, ?, ?, ?)",
                  (name, barcode, min_stock, siteone_sku))
        conn.commit()
    return redirect("/")

@app.route('/edit-product/<int:product_id>', methods=['POST'])
def edit_product(product_id):
    data = request.form
    name = data['name']
    barcode = data['barcode']
    min_stock = int(data['min_stock'])

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE products SET name=?, barcode=?, min_stock=? WHERE id=?",
              (name, barcode, min_stock, product_id))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete-product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM products WHERE id=?", (product_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/scan-action', methods=['POST'])
def scan_action():
    barcode = request.json['barcode']
    direction = request.json['direction']  # 'in' or 'out'
    technician = request.json.get('technician', '')  # Grab technician from request

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get product info
    c.execute("SELECT id, stock FROM products WHERE barcode=?", (barcode,))
    result = c.fetchone()

    if result:
        product_id, stock = result
        new_stock = stock + 1 if direction == 'in' else max(stock - 1, 0)

        # Update stock
        c.execute("UPDATE products SET stock=? WHERE id=?", (new_stock, product_id))

        # Insert into scan_logs with technician
        timestamp = datetime.now().isoformat()
        c.execute("""
            INSERT INTO scan_logs (product_id, action, timestamp, technician)
            VALUES (?, ?, ?, ?)
        """, (product_id, direction, timestamp, technician))

        conn.commit()
        status = 'success'
    else:
        status = 'not_found'

    conn.close()
    return jsonify({'status': status})

@app.route("/history")
def history():
    selected_month = request.args.get("month")
    selected_tech = request.args.get("technician")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Prepare base query and filters
    query = """
        SELECT p.name, s.action, s.timestamp, s.technician, p.cost_per_unit
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE 1=1
    """
    params = []

    if selected_month:
        start_date = f"{selected_month}-01"
        end_date = f"{selected_month}-31"
        query += " AND s.timestamp BETWEEN ? AND ?"
        params += [start_date, end_date]

    if selected_tech:
        query += " AND s.technician = ?"
        params.append(selected_tech)

    query += " ORDER BY s.timestamp DESC"
    c.execute(query, params)
    logs = c.fetchall()

    # Summary of cost per tech per month
    summary_query = """
        SELECT s.technician, SUM(p.cost_per_unit) as total_cost
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE s.action = 'out'
    """
    summary_params = []
    if selected_month:
        summary_query += " AND s.timestamp BETWEEN ? AND ?"
        summary_params += [start_date, end_date]
    if selected_tech:
        summary_query += " AND s.technician = ?"
        summary_params.append(selected_tech)

    summary_query += " GROUP BY s.technician"
    c.execute(summary_query, summary_params)
    summary = c.fetchall()

    conn.close()

    return render_template("history.html", logs=logs, summary=summary,
                           selected_month=selected_month,
                           selected_tech=selected_tech)

@app.route("/add-technician", methods=["POST"])
def add_technician_route():
    name = request.form.get("tech_name")
    if name:
        add_technician(name.strip())
    return redirect("/")

@app.route("/remove-technician", methods=["POST"])
def remove_technician_route():
    name = request.form.get("tech_name")
    if name:
        remove_technician(name.strip())
    return redirect("/")

@app.route("/sync-siteone", methods=["POST"])
def sync_siteone():
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return "Missing login credentials", 400

    success, message = run_siteone_sync()
    if success:
        print("✅ SiteOne sync completed.")
    else:
        print(f"❌ Sync error: {message}")
    return redirect(url_for("index"))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0')
