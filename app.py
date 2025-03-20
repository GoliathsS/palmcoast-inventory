from flask import Flask, render_template, request, jsonify, redirect, url_for
import psycopg2
import os
from datetime import datetime
from technician_manager import add_technician, remove_technician, get_all_technicians
from siteone_sync import run_siteone_sync

app = Flask(__name__)

# PostgreSQL connection settings (replace with your actual Render credentials)
DATABASE_URL = os.environ.get("DATABASE_URL", "YOUR_RENDER_POSTGRES_CONNECTION_STRING")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

@app.route('/')
def index():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM products ORDER BY id")
    products = cur.fetchall()
    cur.close()
    conn.close()

    technicians = get_all_technicians()
    return render_template('index.html', products=products, technicians=technicians)

@app.route("/scan")
def scan():
    technicians = get_all_technicians()
    return render_template("scanner.html", technicians=technicians)

@app.route("/add-product", methods=["POST"])
def add_product():
    name = request.form["name"]
    barcode = request.form["barcode"]
    min_stock = int(request.form["min_stock"])
    siteone_sku = request.form.get("siteone_sku", "").strip()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO products (name, barcode, min_stock, siteone_sku)
        VALUES (%s, %s, %s, %s)
    """, (name, barcode, min_stock, siteone_sku))
    conn.commit()
    cur.close()
    conn.close()
    return redirect("/")

@app.route('/edit-product/<int:product_id>', methods=['POST'])
def edit_product(product_id):
    data = request.form
    name = data['name']
    barcode = data['barcode']
    min_stock = int(data['min_stock'])

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE products SET name=%s, barcode=%s, min_stock=%s WHERE id=%s",
                (name, barcode, min_stock, product_id))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete-product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('index'))

@app.route('/scan-action', methods=['POST'])
def scan_action():
    barcode = request.json['barcode']
    direction = request.json['direction']
    technician = request.json.get('technician', '')

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, stock FROM products WHERE barcode=%s", (barcode,))
    result = cur.fetchone()

    if result:
        product_id, stock = result
        new_stock = stock + 1 if direction == 'in' else max(stock - 1, 0)

        cur.execute("UPDATE products SET stock=%s WHERE id=%s", (new_stock, product_id))

        timestamp = datetime.now().isoformat()
        cur.execute("INSERT INTO scan_logs (product_id, action, timestamp, technician) VALUES (%s, %s, %s, %s)",
                    (product_id, direction, timestamp, technician))

        conn.commit()
        status = 'success'
    else:
        status = 'not_found'

    cur.close()
    conn.close()
    return jsonify({'status': status})

@app.route("/history")
def history():
    selected_month = request.args.get("month")
    selected_tech = request.args.get("technician")

    conn = get_db_connection()
    cur = conn.cursor()

    base_query = """
        SELECT p.name, s.action, s.timestamp, s.technician, p.cost_per_unit
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE 1=1
    """
    params = []

    if selected_month:
        start_date = f"{selected_month}-01"
        end_date = f"{selected_month}-31"
        base_query += " AND s.timestamp BETWEEN %s AND %s"
        params += [start_date, end_date]

    if selected_tech:
        base_query += " AND s.technician = %s"
        params.append(selected_tech)

    base_query += " ORDER BY s.timestamp DESC"
    cur.execute(base_query, tuple(params))
    logs = cur.fetchall()

    summary_query = """
        SELECT s.technician, SUM(p.cost_per_unit)
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE s.action = 'out'
    """
    summary_params = []

    if selected_month:
        summary_query += " AND s.timestamp BETWEEN %s AND %s"
        summary_params += [start_date, end_date]

    if selected_tech:
        summary_query += " AND s.technician = %s"
        summary_params.append(selected_tech)

    summary_query += " GROUP BY s.technician"
    cur.execute(summary_query, tuple(summary_params))
    summary = cur.fetchall()

    cur.close()
    conn.close()
    
    # Calculate total cost from the summary data
    total_cost = sum(row[1] for row in summary)
    return render_template("history.html", logs=logs, summary=summary,
                           selected_month=selected_month,
                           selected_tech=selected_tech,
                           total_cost=total_cost)


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
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

