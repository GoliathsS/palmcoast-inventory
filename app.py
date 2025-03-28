from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
import psycopg2
import os
import fitz  # PyMuPDF
import re
from werkzeug.utils import secure_filename
from datetime import datetime
from technician_manager import add_technician, remove_technician, get_all_technicians
from decimal import Decimal, ROUND_HALF_UP

app = Flask(__name__)

# PostgreSQL connection settings (replace with your actual Render credentials)
DATABASE_URL = os.environ.get("DATABASE_URL", "YOUR_RENDER_POSTGRES_CONNECTION_STRING")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

@app.route('/')
def index():
    category_filter = request.args.get('category', 'All')  # Get ?category= value from URL

    conn = get_db_connection()
    cur = conn.cursor()
    
    # Filter products based on category
    if category_filter == 'All':
        cur.execute("SELECT * FROM products ORDER BY id")
    else:
        cur.execute("SELECT * FROM products WHERE category = %s ORDER BY id", (category_filter,))
    products = cur.fetchall()

    # Total inventory value
    cur.execute("SELECT SUM(stock * cost_per_unit) FROM products")
    total_value = cur.fetchone()[0] or 0

    # Lawn and Pest counts
    cur.execute("SELECT COUNT(*) FROM products WHERE category = 'Lawn'")
    lawn_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM products WHERE category = 'Pest'")
    pest_count = cur.fetchone()[0]
    
    cur.close()
    conn.close()

    technicians = get_all_technicians()
    return render_template(
        'index.html',
        products=products,
        technicians=technicians,
        total_value=total_value,
        category_filter=category_filter,
        lawn_count=lawn_count,
        pest_count=pest_count
    )

@app.route("/scan")
def scan():
    technicians = get_all_technicians()
    return render_template("scanner.html", technicians=technicians)

@app.route("/add-product", methods=["POST"])
def add_product():
    name = request.form["name"]
    barcode = request.form["barcode"]
    min_stock = int(request.form["min_stock"])
    cost_per_unit = float(request.form.get("cost_per_unit", 0))
    siteone_sku = request.form.get("siteone_sku", "").strip()
    category = request.form.get("category", "Pest")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO products (name, barcode, min_stock, cost_per_unit, siteone_sku, category)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (name, barcode, min_stock, cost_per_unit, siteone_sku, category))
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
    cost_per_unit = float(data.get('cost_per_unit', 0.0))
    category = data.get('category', 'Pest')
    siteone_sku = data.get('siteone_sku', '').strip()

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE products
        SET name=%s,
            barcode=%s,
            min_stock=%s,
            cost_per_unit=%s,
            category=%s,
            siteone_sku=%s
        WHERE id=%s
    """, (name, barcode, min_stock, cost_per_unit, category, siteone_sku, product_id))
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

    # Get unique months from scan_logs
    cur.execute("SELECT DISTINCT TO_CHAR(timestamp::date, 'YYYY-MM') FROM scan_logs ORDER BY 1 DESC")
    months = [row[0] for row in cur.fetchall()]

    # Get all technician names
    cur.execute("SELECT DISTINCT technician FROM scan_logs WHERE technician IS NOT NULL AND technician != '' ORDER BY technician")
    technicians = [row[0] for row in cur.fetchall()]

    # Fetch logs
    base_query = """
        SELECT p.name, s.action, s.timestamp, s.technician, p.cost_per_unit
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE 1=1
    """
    params = []

    if selected_month:
        base_query += " AND TO_CHAR(s.timestamp::date, 'YYYY-MM') = %s"
        params.append(selected_month)

    if selected_tech:
        base_query += " AND s.technician = %s"
        params.append(selected_tech)

    base_query += " ORDER BY s.timestamp DESC"
    cur.execute(base_query, tuple(params))
    logs = cur.fetchall()

    # Total cost summary
    summary_query = """
        SELECT s.technician, SUM(p.cost_per_unit)
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE s.action = 'out'
    """
    summary_params = []

    if selected_month:
        summary_query += " AND TO_CHAR(s.timestamp::date, 'YYYY-MM') = %s"
        summary_params.append(selected_month)

    if selected_tech:
        summary_query += " AND s.technician = %s"
        summary_params.append(selected_tech)

    summary_query += " GROUP BY s.technician"
    cur.execute(summary_query, tuple(summary_params))
    summary = cur.fetchall()
    total_cost = sum(row[1] for row in summary)

    cur.close()
    conn.close()

    return render_template("history.html",
        logs=logs,
        summary=summary,
        total_cost=total_cost,
        selected_month=selected_month,
        selected_tech=selected_tech,
        months=months,
        technicians=technicians
    )

@app.route("/settings")
def settings():
    technicians = get_all_technicians()
    return render_template("settings.html", technicians=technicians)

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

@app.route('/static/manifest.json')
def manifest():
    return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route("/sync-siteone", methods=["POST"])
def sync_siteone():
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return "Missing login credentials", 400

    success, message = run_siteone_sync()
    return redirect(url_for("index"))

@app.route("/print-report")
def print_report():
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM products ORDER BY category, name")
    products = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("print_report.html", products=products, now=datetime.now())

@app.route('/upload-invoice', methods=['GET', 'POST'])
def upload_invoice():
    if request.method == 'POST':
        file = request.files['pdf']
        if not file or not file.filename.endswith('.pdf'):
            return "Invalid file format", 400

        filename = secure_filename(file.filename)
        filepath = os.path.join('/tmp', filename)
        file.save(filepath)

        import fitz  # PyMuPDF
        doc = fitz.open(filepath)
        full_text = "\n".join(page.get_text() for page in doc)

        updates = []
        lines = full_text.split("\n")
        
        with open("/tmp/pdf_debug_output.txt", "w", encoding="utf-8") as f:
            f.write("---- RAW LINES FROM PDF ----\n")
            for i, line in enumerate(lines):
                f.write(f"{i:03}: {line}\n")


        # Loop and extract SKU + Price from expected pattern
        for i in range(len(lines)):
            line = lines[i].strip()
            # Detect SKUs: numeric with optional dash, usually 6+ characters
            if re.match(r'^[0-9A-Z\-]{6,}$', line):
                sku = line
                unit_price = None

                # Look ahead up to 10 lines to find unit price like "$91.833/"
                for j in range(i+1, min(i+10, len(lines))):
                    price_match = re.search(r"\$([\d\.,]+)\s*/", lines[j])
                    if price_match:
                        unit_price = float(price_match.group(1).replace(",", ""))
                        break

                if unit_price is not None:
                    # Compare and update price in DB
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute("SELECT id, cost_per_unit FROM products WHERE siteone_sku = %s", (sku,))
                    match = cur.fetchone()
                    if match:
                        product_id, old_price = match
                        if old_price != unit_price:
                            cur.execute("UPDATE products SET cost_per_unit = %s WHERE id = %s", (unit_price, product_id))
                            updates.append(f"🟢 {sku}: ${old_price:.2f} → ${unit_price:.2f}")
                    conn.commit()
                    cur.close()
                    conn.close()
                    break  # Done with this SKU

        return render_template("upload_result.html", updates=updates)

    return render_template("upload_invoice.html")

@app.route('/static/debug')
def view_debug_output():
    try:
        with open("/tmp/pdf_debug_output.txt", "r", encoding="utf-8") as f:
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "No debug output found.", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

