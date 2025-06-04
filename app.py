from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session
import psycopg2
import os
import boto3
import fitz  # PyMuPDF
import re
from werkzeug.utils import secure_filename
from datetime import datetime, date
from technician_manager import add_technician, remove_technician, get_all_technicians
from decimal import Decimal, ROUND_HALF_UP
from rapidfuzz import process, fuzz
import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("invoice")
log = logging.getLogger("scan_action")
log.setLevel(logging.INFO)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Set up S3 client using environment variables
s3 = boto3.client(
    's3',
    region_name=os.environ.get("AWS_REGION"),
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY")
)

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

    # ✅ Total inventory value
    cur.execute("SELECT SUM(stock * cost_per_unit) FROM products")
    row = cur.fetchone()
    total_value = row[0] if row and row[0] is not None else 0

    # ✅ Lawn count
    cur.execute("SELECT COUNT(*) FROM products WHERE category = 'Lawn'")
    lawn_count = cur.fetchone()[0]

    # ✅ Pest count
    cur.execute("SELECT COUNT(*) FROM products WHERE category = 'Pest'")
    pest_count = cur.fetchone()[0]

    # ✅ Wildlife count
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
    from datetime import datetime

    barcode = request.json['barcode']
    direction = request.json['direction'].lower()
    technician = request.json.get('technician', '').strip()

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch product
    cur.execute("SELECT id, stock, units_per_item, units_remaining, unit_cost FROM products WHERE barcode=%s", (barcode,))
    result = cur.fetchone()

    if not result:
        cur.close()
        conn.close()
        return jsonify({'status': 'not_found'})

    product_id, stock, units_per_item, units_remaining, unit_cost = result
    units_per_item = units_per_item or 1
    units_remaining = units_remaining or (stock * units_per_item)
    unit_cost = unit_cost or 0.0

    if direction == 'out':
        if units_remaining <= 0:
            cur.close()
            conn.close()
            return jsonify({'status': 'not_enough_units'})
        units_remaining -= 1  # ✅ Remove 1 unit
    else:
        units_remaining += units_per_item  # ✅ Add 1 full item worth of units
        stock += 1

    # 🔁 Always recalculate stock from units
    new_stock = units_remaining // units_per_item

    # ✅ Update product
    cur.execute("UPDATE products SET stock=%s, units_remaining=%s WHERE id=%s",
                (new_stock, units_remaining, product_id))

    # ✅ Log the scan
    timestamp = datetime.now().isoformat()
    logged_cost = unit_cost if direction == 'out' else round(unit_cost * units_per_item, 2)

    cur.execute(
        "INSERT INTO scan_logs (product_id, action, timestamp, technician, unit_cost) VALUES (%s, %s, %s, %s, %s)",
        (product_id, direction, timestamp, technician, logged_cost)
    )

    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/assign-technician/<int:vehicle_id>', methods=['POST'])
def assign_technician(vehicle_id):
    tech_id = request.form['technician_id']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE technicians SET vehicle_id = %s WHERE id = %s", (vehicle_id, tech_id))
    conn.commit()
    conn.close()
    return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

@app.route('/vehicle-inspection/<int:vehicle_id>', methods=['GET', 'POST'])
def vehicle_inspection(vehicle_id):
    import boto3
    from werkzeug.utils import secure_filename
    from datetime import datetime

    S3_BUCKET = 'palmcoast-inspections'

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        technician_id = request.form['technician_id']
        mileage = request.form['mileage']
        cleanliness = request.form['cleanliness']
        wrap_condition = request.form['wrap_condition']
        comments = request.form['comments']

        def save_photo(field):
            file = request.files.get(field)
            if file and file.filename:
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                filename = f"{vehicle_id}_{field}_{timestamp}_{secure_filename(file.filename)}"
                s3_key = f"inspections/{filename}"

                s3.upload_fileobj(
                    file,
                    S3_BUCKET,
                    s3_key,
                )
                return f"https://{S3_BUCKET}.s3.amazonaws.com/{s3_key}"
            return None

        photo_fields = [
            'photo_front', 'photo_back', 'photo_side_left', 'photo_side_right',
            'photo_tire_front_left', 'photo_tire_front_right',
            'photo_tire_rear_left', 'photo_tire_rear_right'
        ]
        photos = {field: save_photo(field) for field in photo_fields}

        cur.execute("""
            INSERT INTO vehicle_inspections (
                vehicle_id, technician_id, mileage, cleanliness, wrap_condition, comments,
                photo_front, photo_back, photo_side_left, photo_side_right,
                photo_tire_front_left, photo_tire_front_right,
                photo_tire_rear_left, photo_tire_rear_right
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            vehicle_id, technician_id, mileage, cleanliness, wrap_condition, comments,
            photos['photo_front'], photos['photo_back'], photos['photo_side_left'], photos['photo_side_right'],
            photos['photo_tire_front_left'], photos['photo_tire_front_right'],
            photos['photo_tire_rear_left'], photos['photo_tire_rear_right']
        ))

        cur.execute("""
            UPDATE vehicles
            SET current_mileage = %s, last_inspection_date = CURRENT_DATE
            WHERE vehicle_id = %s
        """, (mileage, vehicle_id))

        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

    # GET: show form
    cur.execute("""
        SELECT t.name, t.id
        FROM technicians t
        JOIN vehicles v ON t.id = v.technician_id
        WHERE v.vehicle_id = %s
    """, (vehicle_id,))
    tech = cur.fetchone()

    if tech:
        technician_name = tech[0]
        technician_id = tech[1]
    else:
        technician_name = "Unassigned"
        technician_id = None

    conn.close()

    return render_template(
        'vehicle_inspection.html',
        vehicle_id=vehicle_id,
        technician=technician_name,
        technician_id=technician_id
    )

@app.route('/vehicles/<int:vehicle_id>')
def vehicle_profile(vehicle_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT v.vehicle_id, v.license_plate, v.vehicle_type, t.name AS technician
        FROM vehicles v
        LEFT JOIN technicians t ON v.technician_id = t.id
        WHERE v.vehicle_id = %s
    """, (vehicle_id,))
    vehicle = cur.fetchone()

    cur.execute("""
        SELECT p.name, vi.quantity, vi.last_scanned
        FROM vehicle_inventory vi
        JOIN products p ON vi.product_id = p.id
        WHERE vi.vehicle_id = %s
        ORDER BY p.name
    """, (vehicle_id,))
    inventory = cur.fetchall()

    cur.execute("""
        SELECT
            id, date, technician_id, vehicle_id, mileage,
            cleanliness, wrap_condition, comments,
            photo_front, photo_back, photo_side_left, photo_side_right,
            photo_tire_front_left, photo_tire_front_right,
            photo_tire_rear_left, photo_tire_rear_right
        FROM vehicle_inspections
        WHERE vehicle_id = %s
        ORDER BY date DESC
        LIMIT 5
    """, (vehicle_id,))
    inspections = cur.fetchall()

    conn.close()

    return render_template('vehicle_profile.html',
                           vehicle=vehicle,
                           inventory=inventory,
                           inspections=inspections)

@app.route('/inspections') 
def inspections_list():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT v.vehicle_id, vi.date, v.license_plate, t.name AS technician,
               vi.mileage, vi.cleanliness, vi.wrap_condition, vi.id
        FROM vehicle_inspections vi
        JOIN vehicles v ON vi.vehicle_id = v.vehicle_id
        JOIN technicians t ON vi.technician_id = t.id
        ORDER BY vi.date DESC;
    """)

    inspections = cur.fetchall()
    conn.close()

    return render_template('vehicle_inspections_list.html', inspections=inspections)

@app.route('/inspection/<int:inspection_id>')
def inspection_detail(inspection_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT vi.id, vi.date, t.name AS technician, vi.mileage, vi.cleanliness, vi.wrap_condition,
               vi.comments,
               vi.photo_front, vi.photo_back, vi.photo_side_left, vi.photo_side_right,
               vi.photo_tire_front_left, vi.photo_tire_front_right,
               vi.photo_tire_rear_left, vi.photo_tire_rear_right
        FROM vehicle_inspections vi
        LEFT JOIN technicians t ON vi.technician_id = t.id
        WHERE vi.id = %s
    """, (inspection_id,))

    inspection = cur.fetchone()
    cur.close()
    conn.close()

    if not inspection:
        return "Inspection not found", 404

    return render_template("inspection_detail.html", inspection=inspection)


@app.route('/delete-inspection/<int:inspection_id>', methods=['POST'])
def delete_inspection(inspection_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("DELETE FROM vehicle_inspections WHERE id = %s", (inspection_id,))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('inspections_list'))

@app.route('/vehicles')
def vehicles_list():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT v.vehicle_id, v.license_plate, v.vehicle_type,
               COALESCE(t.name, 'Unassigned') as technician
        FROM vehicles v
        LEFT JOIN technicians t ON v.technician_id = t.id
        ORDER BY v.license_plate
    """)
    vehicles = cur.fetchall()
    conn.close()

    return render_template('vehicles_list.html', vehicles=vehicles)

@app.route('/vehicles/new', methods=['GET', 'POST'])
def create_vehicle():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        plate = request.form['license_plate']
        vehicle_type = request.form['vehicle_type']
        technician_id = request.form.get('technician_id')

        # New: insert vehicle WITH technician_id
        cur.execute("""
            INSERT INTO vehicles (license_plate, vehicle_type, technician_id)
            VALUES (%s, %s, %s)
        """, (plate, vehicle_type, technician_id or None))

        conn.commit()
        conn.close()
        return redirect(url_for('vehicles_list'))

    technicians = get_all_technicians()
    return render_template('create_vehicle.html', technicians=technicians)

@app.route('/delete-vehicle/<int:vehicle_id>', methods=['POST'])
def delete_vehicle(vehicle_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # Unassign any tech
    cur.execute("UPDATE technicians SET vehicle_id = NULL WHERE vehicle_id = %s", (vehicle_id,))

    # Clear inventory links
    cur.execute("DELETE FROM vehicle_inventory WHERE vehicle_id = %s", (vehicle_id,))

    # Delete the vehicle
    cur.execute("DELETE FROM vehicles WHERE vehicle_id = %s", (vehicle_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('vehicles_list'))

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

@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('static/uploads', filename)

@app.route('/edit-sds', methods=['GET', 'POST'])
def edit_sds():
    # Only allow admins to access this route
    if session.get('role') == 'tech':
        return redirect(url_for('sds_portal'))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        product_id = request.form['product_id']
        epa_number = request.form.get('epa_number')

        sds_file = request.files.get('sds_pdf')
        label_file = request.files.get('label_pdf')
        barcode_file = request.files.get('barcode_img')

        sds_url = label_url = barcode_img_url = None

        if sds_file and sds_file.filename != '':
            sds_filename = secure_filename(sds_file.filename)
            sds_path = os.path.join('static/uploads/sds', sds_filename)
            sds_file.save(sds_path)
            sds_url = '/' + sds_path.replace("\\", "/")

        if label_file and label_file.filename != '':
            label_filename = secure_filename(label_file.filename)
            label_path = os.path.join('static/uploads/labels', label_filename)
            label_file.save(label_path)
            label_url = '/' + label_path.replace("\\", "/")

        if barcode_file and barcode_file.filename != '':
            barcode_filename = secure_filename(barcode_file.filename)
            barcode_path = os.path.join('static/uploads/barcodes', barcode_filename)
            barcode_file.save(barcode_path)
            barcode_img_url = '/' + barcode_path.replace("\\", "/")

        updates = []
        values = []

        if epa_number:
            updates.append("epa_number = %s")
            values.append(epa_number)

        if sds_url:
            updates.append("sds_url = %s")
            values.append(sds_url)
            updates.append("sds_uploaded_on = %s")
            values.append(date.today())  # Record the date of upload

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
    cur.execute("SELECT id, name, epa_number FROM products ORDER BY name;")
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
            new_action = request.form['action']
            technician = request.form['technician']
            unit_cost = float(request.form.get('unit_cost') or 0.0)

            cur.execute("""
                UPDATE scan_logs
                SET action = %s, technician = %s, unit_cost = %s
                WHERE id = %s
            """, (new_action, technician, unit_cost, log_id))

        conn.commit()

    # Filters
    start = request.args.get('start') or datetime.now().strftime('%Y-%m-01')
    end = request.args.get('end') or datetime.now().strftime('%Y-%m-%d')
    technician_filter = request.args.get('technician') or ""

    # Query scan logs with technician name
    base_query = """
        SELECT s.id, s.timestamp, p.name AS product_name, s.action, s.technician, s.unit_cost,
               t.name AS technician_name
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        LEFT JOIN technicians t ON CAST(s.technician AS TEXT) = CAST(t.id AS TEXT)
        WHERE s.timestamp BETWEEN %s AND %s
    """
    params = [start, end + " 23:59:59"]

    if technician_filter:
        base_query += " AND (s.technician = %s OR CAST(s.technician AS TEXT) = %s)"
        params.extend([technician_filter, technician_filter])

    base_query += " ORDER BY s.timestamp DESC"
    cur.execute(base_query, tuple(params))
    logs = cur.fetchall()

    # Clean dropdown with tech ID-name mapping
    cur.execute("SELECT id, name FROM technicians ORDER BY name")
    techs = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("corrections.html",
        logs=logs,
        technicians=techs,
        selected_tech=technician_filter,
        start=start,
        end=end
    )

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

    # Technician list as (id, name)
    cur.execute("SELECT id, name FROM technicians ORDER BY name")
    tech_rows = cur.fetchall()
    technicians = [row[1] for row in tech_rows]  # Only names for dropdown

    # 🔎 Main scan log query
    base_query = """
        SELECT 
            p.name AS product_name,
            s.action,
            s.timestamp,
            COALESCE(t.name, s.technician) AS technician_name,
            s.unit_cost
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        LEFT JOIN technicians t 
          ON CASE 
               WHEN s.technician ~ '^\d+$' THEN CAST(s.technician AS INTEGER) = t.id
               ELSE FALSE
             END
        WHERE 1=1
    """
    params = []

    if selected_month:
        base_query += " AND TO_CHAR(s.timestamp::date, 'YYYY-MM') = %s"
        params.append(selected_month)

    if selected_tech:
        base_query += " AND COALESCE(t.name, s.technician) = %s"
        params.append(selected_tech.strip())

    base_query += " ORDER BY s.timestamp DESC"
    cur.execute(base_query, tuple(params))
    logs = cur.fetchall()

    # ✅ Summary query — now filtered correctly
    summary_query = """
        SELECT 
            COALESCE(t.name, s.technician) AS technician_name,
            p.name,
            COUNT(*) AS quantity,
            MAX(s.unit_cost),
            SUM(s.unit_cost)
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        LEFT JOIN technicians t 
          ON CASE 
               WHEN s.technician ~ '^\d+$' THEN CAST(s.technician AS INTEGER) = t.id
               ELSE FALSE
             END
        WHERE s.action = 'out'
    """
    summary_params = []

    if selected_month:
        summary_query += " AND TO_CHAR(s.timestamp::date, 'YYYY-MM') = %s"
        summary_params.append(selected_month)

    if selected_tech:
        summary_query += " AND COALESCE(t.name, s.technician) = %s"
        summary_params.append(selected_tech.strip())

    summary_query += " GROUP BY technician_name, p.name ORDER BY technician_name, p.name"
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

