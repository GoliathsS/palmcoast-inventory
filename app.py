from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session
import psycopg2
import os
import fitz  # PyMuPDF
import re
from werkzeug.utils import secure_filename
from datetime import datetime
from technician_manager import add_technician, remove_technician, get_all_technicians
from decimal import Decimal, ROUND_HALF_UP
from rapidfuzz import process, fuzz
import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("invoice")

app = Flask(__name__)

# Ensure upload folders exist
UPLOAD_FOLDERS = [
    'static/uploads/sds',
    'static/uploads/labels',
    'static/uploads/barcodes'
]

for folder in UPLOAD_FOLDERS:
    os.makedirs(folder, exist_ok=True)

# PostgreSQL connection settings (replace with your actual Render credentials)
DATABASE_URL = os.environ.get("DATABASE_URL", "YOUR_RENDER_POSTGRES_CONNECTION_STRING")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

@app.route('/')
def index():
    # If the logged-in user is a tech, redirect to SDS portal
    if session.get('role') == 'tech':
        return redirect(url_for('sds_portal'))

    # Otherwise continue to load admin dashboard
    conn = get_db_connection()
    cur = conn.cursor()

    category_filter = request.args.get('category', 'All')
    if category_filter == 'All':
        cur.execute("SELECT * FROM products ORDER BY id")
    else:
        cur.execute("SELECT * FROM products WHERE category = %s ORDER BY id", (category_filter,))
    products = cur.fetchall()

    cur.execute("SELECT SUM(stock * cost_per_unit) FROM products")
    total_value = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM products WHERE category = 'Lawn'")
    lawn_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM products WHERE category = 'Pest'")
    pest_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM products WHERE category = 'Wildlife'")
    wildlife_count = cur.fetchone()[0]

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
        pest_count=pest_count,
        wildlife_count=wildlife_count
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
    units_per_item = int(data.get('units_per_item', 1))
    
    # Safely calculate unit cost
    unit_cost = round(cost_per_unit / units_per_item, 2) if units_per_item else 0.0

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE products
        SET name=%s,
            barcode=%s,
            min_stock=%s,
            cost_per_unit=%s,
            category=%s,
            siteone_sku=%s,
            units_per_item=%s,
            unit_cost=%s
        WHERE id=%s
    """, (name, barcode, min_stock, cost_per_unit, category, siteone_sku, units_per_item, unit_cost, product_id))
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

    # Fetch product info
    cur.execute("SELECT id, stock, units_per_item, units_remaining, unit_cost FROM products WHERE barcode=%s", (barcode,))
    result = cur.fetchone()

    if result:
        product_id, stock, units_per_item, units_remaining, unit_cost = result
        units_per_item = units_per_item or 1
        units_remaining = units_remaining or (stock * units_per_item)
        unit_cost = unit_cost or 0.0

        if direction == 'out':
            if units_remaining <= 0:
                cur.close()
                conn.close()
                return jsonify({'status': 'not_enough_units'})
            units_remaining -= 1
        else:
            units_remaining += units_per_item  # Add 1 item worth of units
            stock += 1

        new_stock = units_remaining // units_per_item

        # Update product stock
        cur.execute(
            "UPDATE products SET stock=%s, units_remaining=%s WHERE id=%s",
            (new_stock, units_remaining, product_id)
        )

        # Log scan event
        timestamp = datetime.now().isoformat()
        logged_cost = unit_cost if direction == 'out' else round(unit_cost * units_per_item, 2)

        cur.execute(
            "INSERT INTO scan_logs (product_id, action, timestamp, technician, unit_cost) VALUES (%s, %s, %s, %s, %s)",
            (product_id, direction, timestamp, technician, logged_cost)
        )

        conn.commit()
        status = 'success'
    else:
        status = 'not_found'

    cur.close()
    conn.close()
    return jsonify({'status': status})

@app.route('/sds')
def sds_portal():
    filter_type = request.args.get('filter', '')
    conn = get_db_connection()
    cur = conn.cursor()

    if filter_type == 'has_sds':
        cur.execute("""
            SELECT id, name, epa_number, sds_url, label_url, barcode_img_url, sds_uploaded_on
            FROM products
            WHERE sds_url IS NOT NULL
            ORDER BY name;
        """)
    else:
        cur.execute("""
            SELECT id, name, epa_number, sds_url, label_url, barcode_img_url, sds_uploaded_on
            FROM products
            ORDER BY name;
        """)

    products = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('sds_view.html', products=products, today=date.today())

@app.route('/edit-sds', methods=['GET', 'POST'])
def edit_sds():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        product_id = request.form['product_id']

        # Handle SDS PDF upload
        sds_file = request.files.get('sds_pdf')
        sds_url = None
        if sds_file and sds_file.filename != '':
            sds_filename = secure_filename(sds_file.filename)
            sds_path = os.path.join('static/uploads/sds', sds_filename)
            sds_file.save(sds_path)
            sds_url = '/' + sds_path.replace("\\", "/")

        # Handle Label PDF upload
        label_file = request.files.get('label_pdf')
        label_url = None
        if label_file and label_file.filename != '':
            label_filename = secure_filename(label_file.filename)
            label_path = os.path.join('static/uploads/labels', label_filename)
            label_file.save(label_path)
            label_url = '/' + label_path.replace("\\", "/")

        # Handle Barcode Image upload
        barcode_file = request.files.get('barcode_img')
        barcode_img_url = None
        if barcode_file and barcode_file.filename != '':
            barcode_filename = secure_filename(barcode_file.filename)
            barcode_path = os.path.join('static/uploads/barcodes', barcode_filename)
            barcode_file.save(barcode_path)
            barcode_img_url = '/' + barcode_path.replace("\\", "/")

        # Build dynamic SQL update (only update what was provided)
        updates = []
        values = []

        if sds_url:
            updates.append("sds_url = %s")
            values.append(sds_url)
        if label_url:
            updates.append("label_url = %s")
            values.append(label_url)
        if barcode_img_url:
            updates.append("barcode_img_url = %s")
            values.append(barcode_img_url)

        if updates:
            values.append(product_id)
            query = f"UPDATE products SET {', '.join(updates)} WHERE id = %s"
            cur.execute(query, tuple(values))
            conn.commit()

        cur.close()
        conn.close()
        return redirect(url_for('edit_sds'))

    # GET: Load product list
    cur.execute("SELECT id, name FROM products ORDER BY name;")
    products = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('edit_sds.html', products=products)

@app.route('/corrections', methods=['GET', 'POST'])
def corrections():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        log_id = request.form['log_id']
        action_type = request.form.get('action_type', 'update')

        if action_type == 'delete':
            cur.execute("DELETE FROM scan_logs WHERE id = %s", (log_id,))
        else:
            action = request.form['action']
            technician = request.form['technician']
            unit_cost = float(request.form.get('unit_cost') or 0.0)

            cur.execute("""
                UPDATE scan_logs
                SET action = %s, technician = %s, unit_cost = %s
                WHERE id = %s
            """, (action, technician, unit_cost, log_id))

        conn.commit()

    # Filters
    start = request.args.get('start') or datetime.now().strftime('%Y-%m-01')
    end = request.args.get('end') or datetime.now().strftime('%Y-%m-%d')
    technician_filter = request.args.get('technician') or ""

    # Build query
    base_query = """
        SELECT s.id, s.timestamp, p.name, s.action, s.technician, s.unit_cost
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE s.timestamp BETWEEN %s AND %s
    """
    params = [start, end + " 23:59:59"]

    if technician_filter:
        base_query += " AND s.technician = %s"
        params.append(technician_filter)

    base_query += " ORDER BY s.timestamp DESC"

    cur.execute(base_query, tuple(params))
    logs = cur.fetchall()

    # Technician list for filter dropdown
    cur.execute("SELECT DISTINCT technician FROM scan_logs WHERE technician IS NOT NULL AND technician != '' ORDER BY technician")
    techs = [row[0] for row in cur.fetchall()]

    cur.close()
    conn.close()

    return render_template("corrections.html",
        logs=logs,
        technicians=techs,
        selected_tech=technician_filter,
        start=start,
        end=end
    )

@app.route("/history")
def history():
    selected_month = request.args.get("month")
    selected_tech = request.args.get("technician")

    conn = get_db_connection()
    cur = conn.cursor()

    # Unique months for filter dropdown
    cur.execute("SELECT DISTINCT TO_CHAR(timestamp::date, 'YYYY-MM') FROM scan_logs ORDER BY 1 DESC")
    months = [row[0] for row in cur.fetchall()]

    # Technician list
    cur.execute("SELECT DISTINCT technician FROM scan_logs WHERE technician IS NOT NULL AND technician != '' ORDER BY technician")
    technicians = [row[0] for row in cur.fetchall()]

    # Logs with unit_cost from scan_logs
    base_query = """
        SELECT p.name, s.action, s.timestamp, s.technician, s.unit_cost
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

    # Summary by technician + product
    summary_query = """
        SELECT s.technician, p.name, COUNT(*) AS quantity, MAX(s.unit_cost), SUM(s.unit_cost)
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

    summary_query += " GROUP BY s.technician, p.name ORDER BY s.technician, p.name"
    cur.execute(summary_query, tuple(summary_params))
    summary = cur.fetchall()

    total_cost = sum((row[4] or 0) for row in summary)

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

def normalize(text):
    text = re.sub(r'[^a-zA-Z0-9\s]', '', text)  # remove punctuation
    text = re.sub(r'\s+', ' ', text)  # normalize spacing
    return text.lower().strip()

@app.route('/upload-invoice', methods=['GET', 'POST'])
def upload_invoice():
    if request.method == 'POST':
        file = request.files['pdf']
        if not file or not file.filename.endswith('.pdf'):
            return "Invalid file format", 400

        filename = secure_filename(file.filename)
        filepath = os.path.join('/tmp', filename)
        file.save(filepath)

        doc = fitz.open(filepath)
        lines = []
        for page in doc:
            lines.extend(page.get_text().splitlines())

        # Load DB products
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, name, cost_per_unit FROM products")
        db_products = cur.fetchall()
        cur.close()

        name_list = [p[1] for p in db_products]
        normalized_db_names = [normalize(n) for n in name_list]

        updates = []
        debug_log = []
        debug_log.append(f"📄 PDF contains {len(lines)} total lines")

        i = 0
        while i < len(lines) - 8:
            sku = lines[i].strip()

            if not re.match(r'^[0-9A-Z\-]{6,}$', sku):
                i += 1
                continue

            name_line_1 = lines[i + 1].strip()
            name_line_2 = lines[i + 2].strip()
            name_line_3 = lines[i + 3].strip()
            price_line = lines[i + 6].strip()

            name_parts = [name_line_1, name_line_2, name_line_3]
            product_name = " ".join(name_parts).replace("...", "").strip()
            product_name = re.sub(r'\s+', ' ', product_name)

            normalized_product_name = normalize(product_name)

            price_match = re.search(r"\$([\d\.,]+)\s*/", price_line)
            if not price_match:
                i += 9
                continue

            unit_price = float(price_match.group(1).replace(",", ""))

            debug_log.append(f"✅ Block from line {i}:")
            debug_log.append(f"  SKU: {sku}")
            debug_log.append(f"  Name: {product_name}")
            debug_log.append(f"  Price Line: {price_line}")
            debug_log.append(f"  Extracted Price: {unit_price}")

            match_name, score, idx = process.extractOne(normalized_product_name, normalized_db_names, scorer=fuzz.token_set_ratio)
            actual_name = name_list[idx]
            debug_log.append(f"  🤖 Match: '{actual_name}' (Score: {score})")

            if score >= 75:
                product_id, _, old_price = db_products[idx]
                if old_price != unit_price:
                    conn = get_db_connection()
                    cur = conn.cursor()
                    cur.execute("UPDATE products SET cost_per_unit = %s WHERE id = %s", (unit_price, product_id))
                    conn.commit()
                    cur.close()
                    conn.close()
                    updates.append(f"🟢 {actual_name}: ${old_price:.2f} → ${unit_price:.2f}")
                else:
                    updates.append(f"⚪ {actual_name}: no change (${unit_price:.2f})")
            else:
                updates.append(f"🔴 No match for: {product_name}")

            i += 9  # Move to next product block

        if not updates:
            updates.append("⚠️ No matches or price changes found.")

        return render_template("upload_result.html", updates=updates, debug_log=debug_log)

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

