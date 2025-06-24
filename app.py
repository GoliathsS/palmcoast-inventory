from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session, abort
import psycopg2
import os
import boto3
import fitz  # PyMuPDF
import re
import pdfplumber
import csv
import uuid
import pandas as pd
import io
from io import TextIOWrapper
from werkzeug.utils import secure_filename
from datetime import datetime, date
from technician_manager import add_technician, remove_technician, get_all_technicians
from decimal import Decimal, ROUND_HALF_UP
from rapidfuzz import process, fuzz
import logging
logging.basicConfig(level=logging.INFO)
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

@app.route('/export-products')
def export_products():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT name, category, cost_per_unit, units_remaining FROM products")
    rows = cur.fetchall()
    colnames = [desc[0] for desc in cur.description]
    df = pd.DataFrame(rows, columns=colnames)

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Products')

    output.seek(0)
    return send_file(
        output,
        download_name='products_export.xlsx',
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )

@app.route('/scan-action', methods=['POST'])
def scan_action():
    from datetime import datetime

    barcode = request.json['barcode']
    direction = request.json['direction'].lower()
    technician = request.json.get('technician', '').strip()

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Fetch product
        cur.execute("SELECT id, stock, units_per_item, units_remaining, unit_cost FROM products WHERE barcode=%s", (barcode,))
        result = cur.fetchone()

        if not result:
            log.info("❌ Product not found for barcode: %s", barcode)
            cur.close()
            conn.close()
            return jsonify({'status': 'not_found'})

        product_id, stock, units_per_item, units_remaining, unit_cost = result
        units_per_item = units_per_item or 1
        units_remaining = units_remaining or (stock * units_per_item)
        unit_cost = unit_cost or 0.0

        if direction == 'out':
            if units_remaining <= 0:
                log.info("⚠️ Not enough units for product %s", product_id)
                cur.close()
                conn.close()
                return jsonify({'status': 'not_enough_units'})
            units_remaining -= 1
        else:
            units_remaining += units_per_item
            stock += 1

        new_stock = units_remaining // units_per_item

        # Update main inventory
        cur.execute("UPDATE products SET stock=%s, units_remaining=%s WHERE id=%s",
                    (new_stock, units_remaining, product_id))

        # Log the scan
        timestamp = datetime.now().isoformat()
        logged_cost = unit_cost if direction == 'out' else round(unit_cost * units_per_item, 2)

        cur.execute(
            "INSERT INTO scan_logs (product_id, action, timestamp, technician, unit_cost) VALUES (%s, %s, %s, %s, %s)",
            (product_id, direction, timestamp, technician, logged_cost)
        )

        # 🚚 Lookup technician and vehicle by ID
        technician_id = None
        vehicle_id = None

        if technician:
            log.info("🔍 Technician passed in (ID): %s", technician)
            try:
                cur.execute("SELECT id, vehicle_id FROM technicians WHERE id = %s", (int(technician),))
                tech_row = cur.fetchone()
                log.info("👤 Technician row: %s", tech_row)
                if tech_row:
                    technician_id = tech_row[0]
                    vehicle_id = tech_row[1]
                    log.info("✅ Found technician ID: %s, vehicle ID: %s", technician_id, vehicle_id)
                else:
                    log.info("❌ Technician ID %s not found in DB", technician)
            except Exception as e:
                log.error("❌ Error fetching technician: %s", e)

        # 🚚 Update vehicle inventory only if scanning out and vehicle is assigned
        if direction == 'out' and vehicle_id:
            log.info("🚚 Updating vehicle inventory for vehicle %s and product %s", vehicle_id, product_id)
            cur.execute("""
                SELECT quantity FROM vehicle_inventory
                WHERE vehicle_id = %s AND product_id = %s
            """, (vehicle_id, product_id))
            existing = cur.fetchone()
            log.info("📦 Existing inventory row: %s", existing)

            if existing:
                cur.execute("""
                    UPDATE vehicle_inventory
                    SET quantity = %s,
                        last_updated = CURRENT_TIMESTAMP,
                        last_scanned = CURRENT_TIMESTAMP,
                        expires_on = CURRENT_DATE + INTERVAL '7 days'
                    WHERE vehicle_id = %s AND product_id = %s
                """, (1, vehicle_id, product_id))
                log.info("🔁 Replaced quantity with 1 and set expires_on to +7 days")
            else:
                cur.execute("""
                    INSERT INTO vehicle_inventory (vehicle_id, product_id, quantity, last_updated, last_scanned, expires_on)
                    VALUES (%s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_DATE + INTERVAL '7 days')
                """, (vehicle_id, product_id, 1))
                log.info("➕ Inserted product with expires_on +7 days")
        else:
            log.info("⚠️ Vehicle inventory not updated: direction=%s, vehicle_id=%s", direction, vehicle_id)

        conn.commit()
        log.info("✅ Scan and inventory update completed for product %s", product_id)
        return jsonify({'status': 'success'})

    except Exception as e:
        log.error("❌ ERROR in /scan-action: %s", e)
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)})

    finally:
        cur.close()
        conn.close()

@app.route('/assign-technician/<int:vehicle_id>', methods=['POST'])
def assign_technician(vehicle_id):
    tech_id = request.form['technician_id']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE vehicles SET technician_id = %s WHERE vehicle_id = %s", (tech_id, vehicle_id))
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
            'photo_tire_rear_left', 'photo_tire_rear_right',
            'photo_misc_1', 'photo_misc_2', 'photo_misc_3', 'photo_misc_4'
        ]
        photos = {field: save_photo(field) for field in photo_fields}

        cur.execute("""
            INSERT INTO vehicle_inspections (
                vehicle_id, technician_id, mileage, cleanliness, wrap_condition, comments,
                photo_front, photo_back, photo_side_left, photo_side_right,
                photo_tire_front_left, photo_tire_front_right,
                photo_tire_rear_left, photo_tire_rear_right,
                photo_misc_1, photo_misc_2, photo_misc_3, photo_misc_4
            ) VALUES (%s, %s, %s, %s, %s, %s,
                      %s, %s, %s, %s,
                      %s, %s, %s, %s,
                      %s, %s, %s, %s)
        """, (
            vehicle_id, technician_id, mileage, cleanliness, wrap_condition, comments,
            photos['photo_front'], photos['photo_back'], photos['photo_side_left'], photos['photo_side_right'],
            photos['photo_tire_front_left'], photos['photo_tire_front_right'],
            photos['photo_tire_rear_left'], photos['photo_tire_rear_right'],
            photos['photo_misc_1'], photos['photo_misc_2'], photos['photo_misc_3'], photos['photo_misc_4']
        ))

        cur.execute("""
            UPDATE vehicles
            SET current_mileage = %s, last_inspection_date = CURRENT_DATE
            WHERE vehicle_id = %s
        """, (mileage, vehicle_id))

        cur.execute("SELECT COUNT(*) FROM maintenance_reminders WHERE vehicle_id = %s", (vehicle_id,))
        existing_reminder_count = cur.fetchone()[0]

        if existing_reminder_count == 0:
            due_odo = int(mileage) + 5000
            cur.execute("""
                INSERT INTO maintenance_reminders (vehicle_id, service_type, odometer_due, received_at)
                VALUES 
                    (%s, 'Oil Change', %s, NULL),
                    (%s, 'Tire Rotation', %s, NULL)
            """, (vehicle_id, due_odo, vehicle_id, due_odo))

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

@app.route('/edit-inspection/<int:inspection_id>', methods=['GET', 'POST'])
def edit_inspection(inspection_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    if request.method == 'POST':
        from datetime import datetime
        from werkzeug.utils import secure_filename

        S3_BUCKET = 'palmcoast-inspections'

        photo_fields = [
            'photo_front', 'photo_back', 'photo_side_left', 'photo_side_right',
            'photo_tire_front_left', 'photo_tire_front_right',
            'photo_tire_rear_left', 'photo_tire_rear_right',
            'photo_misc_1', 'photo_misc_2', 'photo_misc_3', 'photo_misc_4'
        ]

        def save_photo(field):
            file = request.files.get(field)
            if file and file.filename:
                filename = secure_filename(file.filename)
                timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                s3_key = f"inspections/{inspection_id}_{field}_{timestamp}_{filename}"
                s3.upload_fileobj(file, S3_BUCKET, s3_key)
                return f"https://{S3_BUCKET}.s3.amazonaws.com/{s3_key}"
            return None

        updated_photos = {}
        for field in photo_fields:
            new_photo = save_photo(field)
            if new_photo:
                updated_photos[field] = new_photo

        # Update only fields that had new photos uploaded
        for field, url in updated_photos.items():
            cur.execute(f"""
                UPDATE vehicle_inspections SET {field} = %s WHERE id = %s
            """, (url, inspection_id))

        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('inspection_detail', inspection_id=inspection_id))

    # GET request
    cur.execute("SELECT * FROM vehicle_inspections WHERE id = %s", (inspection_id,))
    inspection = cur.fetchone()
    cur.close()
    conn.close()
    return render_template("edit_inspection.html", inspection=inspection)

@app.route('/vehicles/<int:vehicle_id>')
def vehicle_profile(vehicle_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Vehicle basic info
    cur.execute("""
        SELECT v.vehicle_id, v.license_plate, v.vehicle_type, t.name AS technician
        FROM vehicles v
        LEFT JOIN technicians t ON v.technician_id = t.id
        WHERE v.vehicle_id = %s
    """, (vehicle_id,))
    vehicle = cur.fetchone()

    # Truck Inventory
    cur.execute("""
        SELECT p.name, vi.quantity, vi.last_scanned, vi.expires_on
        FROM vehicle_inventory vi
        JOIN products p ON vi.product_id = p.id
        WHERE vi.vehicle_id = %s
          AND (vi.expires_on IS NULL OR vi.expires_on >= CURRENT_DATE)
        ORDER BY p.name
    """, (vehicle_id,))
    inventory = cur.fetchall()

    # Inspections (latest 5)
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

    last_mileage = inspections[0]['mileage'] if inspections else 0

    # --- Reminder Generation Logic ---
    def get_next_due(service_type_exact, interval_miles):
        # Pull the most recent completed OR upcoming reminder
        cur.execute("""
            SELECT odometer_due, received_at
            FROM maintenance_reminders
            WHERE vehicle_id = %s AND service_type = %s
            ORDER BY 
                CASE WHEN received_at IS NULL THEN 1 ELSE 0 END,  -- completed first
                received_at DESC NULLS LAST
            LIMIT 1
        """, (vehicle_id, service_type_exact))

        last = cur.fetchone()
        if not last:
            return None

        last_odo = last['odometer_due']
        due_at = last_odo
        miles_remaining = due_at - last_mileage

        if last['received_at'] is not None:
            due_at = last_odo + interval_miles
            miles_remaining = due_at - last_mileage

        if miles_remaining <= 0:
            status = "overdue"
        elif miles_remaining <= 500:
            status = "due_soon"
        else:
            status = "ok"

        return {
            "service_type": service_type_exact,
            "last_done": last['received_at'],
            "last_odometer": last_odo,
            "due_at": due_at,
            "status": status,
            "miles_remaining": miles_remaining
        }

    reminders = []
    if last_mileage:
        for service, interval in [('Oil Change', 5000), ('Tire Rotation', 5000)]:
            result = get_next_due(service, interval)
            if result:
                reminders.append(result)
            else:
                # No history yet — create default reminder using current mileage
                reminders.append({
                    "service_type": service,
                    "last_done": None,
                    "last_odometer": 0,
                    "due_at": last_mileage + interval,
                    "status": "ok",
                    "miles_remaining": interval
                })

    # Full Maintenance Log (history + generated reminders)
    cur.execute("""
        SELECT id, service_type, odometer_due, received_at, invoice_url
        FROM maintenance_reminders
        WHERE vehicle_id = %s
        ORDER BY received_at DESC NULLS LAST, odometer_due ASC
    """, (vehicle_id,))
    raw_maintenance = cur.fetchall()

    maintenance_logs = []
    for m in raw_maintenance:
        miles_remaining = m['odometer_due'] - last_mileage
        is_overdue = last_mileage >= m['odometer_due']
        is_approaching = 0 < miles_remaining <= 500

        if is_overdue:
            status = "overdue"
        elif is_approaching:
            status = "due_soon"
        else:
            status = "ok"

        maintenance_logs.append({
            **m,
            "status": status,
            "miles_remaining": miles_remaining
        })

    conn.close()

    return render_template(
        'vehicle_profile.html',
        vehicle=vehicle,
        inventory=inventory,
        inspections=inspections,
        maintenance_logs=maintenance_logs,
        last_mileage=last_mileage,
        reminders=reminders
    )

@app.route('/mark-maintenance-complete/<int:vehicle_id>', methods=['POST'])
def mark_maintenance_complete(vehicle_id):
    service_type = request.form.get('service_type')
    current_odometer = request.form.get('odometer')

    if not service_type or not current_odometer:
        return "Missing data", 400

    try:
        current_odometer = int(current_odometer)
        next_due = current_odometer + 5000

        conn = get_db_connection()
        cur = conn.cursor()

        # ✅ 1. Insert actual completed maintenance record
        cur.execute("""
            INSERT INTO maintenance_reminders (vehicle_id, service_type, odometer_due, received_at)
            VALUES (%s, %s, %s, CURRENT_DATE)
        """, (vehicle_id, service_type, current_odometer))

        # ✅ 2. Remove any existing future reminder of the same type to prevent duplicates
        cur.execute("""
            DELETE FROM maintenance_reminders
            WHERE vehicle_id = %s AND service_type = %s AND received_at IS NULL
        """, (vehicle_id, service_type))

        # ✅ 3. Insert new upcoming reminder (placeholder with no received_at)
        cur.execute("""
            INSERT INTO maintenance_reminders (vehicle_id, service_type, odometer_due, received_at)
            VALUES (%s, %s, %s, NULL)
        """, (vehicle_id, service_type, next_due))

        conn.commit()
        cur.close()
        conn.close()

        return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

    except Exception as e:
        app.logger.error(f"⛔ Failed to mark maintenance complete for vehicle {vehicle_id}: {e}")
        return f"Error: {e}", 500

@app.before_request
def check_verizon_auth():
    if request.path.startswith("/api/verizon/"):
        auth = request.authorization
        if not auth or not (auth.username == "pcpc" and auth.password == "801Maplewood!"):
            abort(401)

@app.route('/api/verizon/odometer', methods=['POST'])
def update_vehicle_mileage():
    data = request.json or {}
    vehicle_id = data.get('vehicleId')
    current_mileage = (
        data.get('odometer') or
        data.get('currentMileage') or
        data.get('mileage')  # support for different field names
    )

    app.logger.info(f"📡 Verizon Odometer Update: {data}")

    if not vehicle_id or current_mileage is None:
        return jsonify({"error": "Missing vehicleId or mileage"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE vehicles
            SET mileage = %s
            WHERE vehicle_id = %s
            """,
            (current_mileage, vehicle_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "mileage updated"}), 200
    except Exception as e:
        app.logger.exception("❌ Mileage update failed")
        return jsonify({"error": "Failed to update mileage"}), 500

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
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Get inspection record
    cur.execute("""
        SELECT vi.id, vi.date, t.name AS technician, vi.mileage, vi.cleanliness, vi.wrap_condition,
               vi.comments, vi.vehicle_id,
               vi.photo_front, vi.photo_back, vi.photo_side_left, vi.photo_side_right,
               vi.photo_tire_front_left, vi.photo_tire_front_right,
               vi.photo_tire_rear_left, vi.photo_tire_rear_right,
               vi.photo_misc_1, vi.photo_misc_2, vi.photo_misc_3, vi.photo_misc_4
        FROM vehicle_inspections vi
        LEFT JOIN technicians t ON vi.technician_id = t.id
        WHERE vi.id = %s
    """, (inspection_id,))
    inspection = cur.fetchone()

    if not inspection:
        cur.close()
        conn.close()
        return "Inspection not found", 404

    # --- Fetch last oil change and tire rotation ---
    def get_last(service_type):
        cur.execute("""
            SELECT odometer_due, received_at
            FROM maintenance_reminders
            WHERE vehicle_id = %s AND service_type = %s AND received_at IS NOT NULL
            ORDER BY received_at DESC
            LIMIT 1
        """, (inspection['vehicle_id'], service_type))
        return cur.fetchone()

    last_oil = get_last("Oil Change")
    last_rotation = get_last("Tire Rotation")

    oil_due = last_oil['odometer_due'] + 5000 if last_oil else None
    rotation_due = last_rotation['odometer_due'] + 5000 if last_rotation else None

    cur.close()
    conn.close()

    return render_template(
        "inspection_detail.html",
        inspection=inspection,
        last_oil=last_oil,
        last_rotation=last_rotation,
        oil_due=oil_due,
        rotation_due=rotation_due
    )

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
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT v.vehicle_id, v.license_plate, v.vehicle_type,
               COALESCE(t.name, 'Unassigned') as technician
        FROM vehicles v
        LEFT JOIN technicians t ON v.technician_id = t.id
        ORDER BY v.license_plate
    """)
    vehicles = cur.fetchall()

    vehicle_statuses = {}

    for v in vehicles:
        vid = v['vehicle_id']

        # Get last inspection mileage
        cur.execute("""
            SELECT mileage FROM vehicle_inspections
            WHERE vehicle_id = %s
            ORDER BY date DESC LIMIT 1
        """, (vid,))
        inspection = cur.fetchone()
        last_mileage = inspection['mileage'] if inspection else 0

        # Get last Oil Change
        cur.execute("""
            SELECT odometer_due FROM maintenance_reminders
            WHERE vehicle_id = %s AND service_type = 'Oil Change' AND received_at IS NOT NULL
            ORDER BY received_at DESC LIMIT 1
        """, (vid,))
        maint = cur.fetchone()
        last_oil = maint['odometer_due'] if maint else 0
        next_due = last_oil + 5000

        miles_remaining = next_due - last_mileage

        # Assign status based on miles remaining
        if miles_remaining <= 500:
            status = 'red'
        elif miles_remaining <= 1000:
            status = 'orange'
        elif miles_remaining <= 2000:
            status = 'yellow'
        else:
            status = 'ok'

        vehicle_statuses[vid] = status

    conn.close()

    return render_template('vehicles_list.html', vehicles=vehicles, statuses=vehicle_statuses)

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

        # Load product list from DB
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, name, cost_per_unit FROM products")
        db_products = cur.fetchall()
        cur.close()
        name_list = [p[1] for p in db_products]

        updates = []
        debug_log = []
        matched_count = 0
        updated_count = 0
        skipped_count = 0

        # Parse PDF table with pdfplumber
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages:
                table = page.extract_table()
                if not table:
                    continue
                for row in table[1:]:  # Skip header row
                    if len(row) < 9:
                        skipped_count += 1
                        updates.append(f"🔴 Skipped: incomplete row → {row}")
                        continue

                    sku = row[1].strip()
                    name = row[2].strip()
                    unit_price_raw = row[7].strip()
                    total_raw = row[8].strip()

                    # Extract unit price (e.g. '26.035 / EA')
                    price_match = re.match(r"(\d+\.\d+)\s*/\s*(EA|BG)", unit_price_raw)
                    if not price_match:
                        skipped_count += 1
                        updates.append(f"🔴 Skipped: price format error → {unit_price_raw}")
                        continue

                    try:
                        unit_price = float(price_match.group(1))
                        total_price = float(total_raw)
                    except Exception as e:
                        skipped_count += 1
                        updates.append(f"🔴 Skipped: parse error → {e}")
                        continue

                    updates.append(f"🧪 Trying to match: '{name}'")

                    match = process.extractOne(name, name_list, scorer=fuzz.token_set_ratio)
                    if match:
                        actual_name, score, idx = match
                        debug_log.append(f"🤖 Match: '{actual_name}' ({score}%)")
                    else:
                        actual_name, score, idx = "N/A", 0, -1

                    if score >= 65:
                        matched_count += 1
                        product_id, _, old_price = db_products[idx]

                        # Log current price to price_history
                        cur = conn.cursor()
                        cur.execute("INSERT INTO price_history (product_id, price) VALUES (%s, %s)", (product_id, unit_price))

                        # Update if changed
                        if round(old_price, 2) != round(unit_price, 2):
                            cur.execute("UPDATE products SET cost_per_unit = %s WHERE id = %s", (unit_price, product_id))
                            conn.commit()
                            updated_count += 1
                            updates.append(f"🟢 [{actual_name}] updated from ${old_price:.2f} → ${unit_price:.2f}")
                        else:
                            updates.append(f"⚪ [{actual_name}] no change (${unit_price:.2f})")
                        cur.close()
                    else:
                        skipped_count += 1
                        updates.append(f"🔴 No match for: '{name}' → Best: '{actual_name}' ({score}%)")

        conn.close()

        summary = f"📊 Summary: {matched_count} matched, {updated_count} updated, {skipped_count} skipped."
        updates.insert(0, summary)

        debug = request.args.get('debug') == 'true'
        return render_template("upload_result.html", updates=updates, debug_log=debug_log if debug else [])

    return render_template("upload_invoice.html")

@app.route('/inventory-analytics')
def inventory_analytics():
    selected_id = request.args.get("product_id", type=int)
    selected_name = ""
    latest_price = ""
    latest_date = ""
    price_labels = []
    price_values = []

    usage_labels = []
    start_values = []
    end_values = []
    percent_used = []

    category_labels = []
    pest_values = []
    lawn_values = []

    conn = get_db_connection()
    cur = conn.cursor()

    # Get all product names for dropdown
    cur.execute("SELECT id, name FROM products ORDER BY name ASC")
    all_products = cur.fetchall()

    # 1️⃣ Product Price History
    if selected_id:
        cur.execute("SELECT name FROM products WHERE id = %s", (selected_id,))
        row = cur.fetchone()
        if row:
            selected_name = row[0]
            cur.execute("""
                SELECT date_recorded, price
                FROM price_history
                WHERE product_id = %s
                ORDER BY date_recorded ASC
            """, (selected_id,))
            price_data = cur.fetchall()
            price_labels = [r[0].strftime('%Y-%m-%d') for r in price_data]
            price_values = [float(r[1]) for r in price_data]
            if price_data:
                latest_date = price_data[-1][0].strftime('%B %d, %Y')
                latest_price = f"${price_data[-1][1]:.2f}"

    # 2️⃣ Monthly Inventory Usage (start = scan-in, end = scan-out)
    cur.execute("""
        SELECT TO_CHAR(timestamp::timestamp, 'YYYY-MM') AS month,
               SUM(CASE WHEN action = 'in' THEN unit_cost ELSE 0 END) AS start_value,
               SUM(CASE WHEN action = 'out' THEN unit_cost ELSE 0 END) AS end_value
        FROM scan_logs
        GROUP BY month
        ORDER BY month
    """)
    usage_data = cur.fetchall()
    for row in usage_data:
        usage_labels.append(row[0])
        start_values.append(float(row[1]))
        end_values.append(float(row[2]))
        if row[1] > 0:
            percent_used.append(round((row[1] - row[2]) / row[1] * 100, 2))
        else:
            percent_used.append(0)

    # 3️⃣ Pest vs Lawn Category Monthly Totals
    cur.execute("""
        SELECT TO_CHAR(s.timestamp::timestamp, 'YYYY-MM') AS month,
               p.category,
               SUM(s.unit_cost)
        FROM scan_logs s
        JOIN products p ON s.product_id = p.id
        WHERE s.action = 'out'
        GROUP BY month, p.category
        ORDER BY month
    """)
    cat_data = cur.fetchall()
    cat_map = {}
    for row in cat_data:
        month, cat, value = row
        if month not in cat_map:
            cat_map[month] = {'Pest': 0, 'Lawn': 0}
        if cat in cat_map[month]:
            cat_map[month][cat] += float(value)

    category_labels = sorted(cat_map.keys())
    pest_values = [cat_map[m]['Pest'] for m in category_labels]
    lawn_values = [cat_map[m]['Lawn'] for m in category_labels]

    cur.close()
    conn.close()

    return render_template("inventory_analytics.html",
        all_products=all_products,
        selected_id=selected_id,
        selected_name=selected_name,
        price_labels=price_labels or [],
        price_values=price_values or [],
        latest_price=latest_price or "",
        latest_date=latest_date or "",
        usage_labels=usage_labels or [],
        start_values=start_values or [],
        end_values=end_values or [],
        percent_used=percent_used or [],
        category_labels=category_labels or [],
        pest_values=pest_values or [],
        lawn_values=lawn_values or []
    )
    
@app.route('/static/debug')
def view_debug_output():
    try:
        with open("/tmp/pdf_debug_output.txt", "r", encoding="utf-8") as f:
            return f"<pre>{f.read()}</pre>"
    except FileNotFoundError:
        return "No debug output found.", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

