from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, session, abort, send_file, flash
import psycopg2
import psycopg2.extras
import os
import boto3
import fitz  # PyMuPDF
import re
import pdfplumber
import csv
import uuid
import pandas as pd
import io
import json
from dotenv import load_dotenv
load_dotenv()
from io import TextIOWrapper
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
from datetime import datetime, date
from technician_manager import add_technician, remove_technician, get_all_technicians
from decimal import Decimal, ROUND_HALF_UP
from rapidfuzz import process, fuzz
from datetime import timedelta
from functools import wraps
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from email_utils import send_maintenance_email
import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scan_action")
log.setLevel(logging.INFO)

app = Flask(__name__)
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

CANONICAL_HOST = os.environ.get("CANONICAL_HOST")  # e.g. "palmcoast-inventory.onrender.com"

@app.before_request
def _enforce_host():
    if not CANONICAL_HOST or request.host == CANONICAL_HOST:
        return
    # Only canonicalize safe methods; let POST/PUT/PATCH/DELETE proceed
    if request.method in ("GET", "HEAD"):
        from urllib.parse import urlsplit, urlunsplit
        u = urlsplit(request.url)
        return redirect(urlunsplit((u.scheme, CANONICAL_HOST, u.path, u.query, u.fragment)), code=301)

app.config.update(
    SESSION_COOKIE_SECURE=True,        # HTTPS on Render
    SESSION_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    PREFERRED_URL_SCHEME="https",
)

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY env var is required")
app.config['SECRET_KEY'] = SECRET_KEY

# Rate limiter – used on /login only
limiter = Limiter(get_remote_address, app=app, default_limits=[])

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Set up S3 client using environment variables
s3 = boto3.client(
    's3',
    region_name=os.environ.get("AWS_REGION", "us-east-2"),
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY")
)
# ===== SDS / Label / Barcode on S3 =====
SDS_BUCKET = os.environ.get("SDS_BUCKET")
if not SDS_BUCKET:
    raise RuntimeError("SDS_BUCKET env var is required")

PDF_EXTS = {"pdf"}
IMG_EXTS = {"png", "jpg", "jpeg"}

def _allowed_ext(kind: str, filename: str) -> bool:
    ext = (filename.rsplit(".", 1)[-1] or "").lower()
    if kind == "sds":
        return ext in PDF_EXTS
    if kind == "label":
        return ext in (PDF_EXTS | IMG_EXTS)     # allow PDF or image for label
    if kind == "barcode":
        return ext in IMG_EXTS
    return False

def _key_for(product_id: int, kind: str, filename: str) -> str:
    ext = (filename.rsplit(".", 1)[-1] or "").lower()
    if kind == "sds":
        ext = "pdf"                              # SDS must be pdf
    elif kind == "label":
        if ext not in (PDF_EXTS | IMG_EXTS):
            raise ValueError("Label must be PDF/PNG/JPG")
    elif kind == "barcode":
        if ext not in IMG_EXTS:
            raise ValueError("Barcode must be PNG/JPG")
    return f"sds/{product_id}/{kind}.{ext}"      # deterministic key (overwrite old)

def _guess_content_type(kind: str, filename: str) -> str:
    ext = (filename.rsplit(".", 1)[-1] or "").lower()
    if ext == "pdf":
        return "application/pdf"
    if ext == "png":
        return "image/png"
    if ext in ("jpg", "jpeg"):
        return "image/jpeg"
    return "application/octet-stream"

MIGRATED_SDS_COLS = False

def _ensure_product_columns_once():
    """Only ALTER if columns are actually missing; run once after app init."""
    global MIGRATED_SDS_COLS
    if MIGRATED_SDS_COLS:
        return
    conn = get_db_connection()
    cur = conn.cursor()

    # include sds_uploaded_on in the check
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = 'products'
          AND column_name IN (
            'sds_key','label_key','barcode_key',
            'sds_uploaded_on','label_uploaded_on','barcode_uploaded_on'
          )
    """)
    existing = {r[0] for r in cur.fetchall()}

    missing = []
    if 'sds_key' not in existing:             missing.append("ADD COLUMN sds_key TEXT")
    if 'label_key' not in existing:           missing.append("ADD COLUMN label_key TEXT")
    if 'barcode_key' not in existing:         missing.append("ADD COLUMN barcode_key TEXT")
    if 'sds_uploaded_on' not in existing:     missing.append("ADD COLUMN sds_uploaded_on TIMESTAMPTZ")
    if 'label_uploaded_on' not in existing:   missing.append("ADD COLUMN label_uploaded_on TIMESTAMPTZ")
    if 'barcode_uploaded_on' not in existing: missing.append("ADD COLUMN barcode_uploaded_on TIMESTAMPTZ")

    if missing:
        cur.execute(f"ALTER TABLE products {', '.join(missing)};")
        conn.commit()

    cur.close(); conn.close()
    MIGRATED_SDS_COLS = True

def _handle_to_presigned(handle: str | None, kind: str, expires: int = 1800) -> str | None:
    if not handle:
        return None

    def _is_http_url(s):
        from urllib.parse import urlparse
        try:
            u = urlparse(s); return u.scheme in ("http", "https")
        except:
            return False

    def _is_s3_url(s):
        return bool(s and s.startswith("s3://"))

    if _is_http_url(handle):  # legacy URL
        return handle

    bucket = SDS_BUCKET
    key = handle
    if _is_s3_url(handle):
        from urllib.parse import urlparse
        u = urlparse(handle); bucket = u.netloc or SDS_BUCKET; key = u.path.lstrip("/")

    # Pick response type based on file extension
    ext = (key.rsplit(".", 1)[-1] or "").lower()
    params = {"Bucket": bucket, "Key": key}
    if ext == "pdf":
        params["ResponseContentType"] = "application/pdf"
        params["ResponseContentDisposition"] = f'inline; filename="{kind}.pdf"'
    elif ext == "png":
        params["ResponseContentType"] = "image/png"
    elif ext in ("jpg", "jpeg"):
        params["ResponseContentType"] = "image/jpeg"

    try:
        return s3.generate_presigned_url("get_object", Params=params, ExpiresIn=expires)
    except Exception as e:
        app.logger.error(f"Presign failed for {handle}: {e}")
        return None

def _update_product_key(product_id: int, kind: str, key: str):
    col = {"sds":"sds_key","label":"label_key","barcode":"barcode_key"}[kind]
    ts  = {"sds":"sds_uploaded_on","label":"label_uploaded_on","barcode":"barcode_uploaded_on"}[kind]
    conn = get_db_connection(); cur = conn.cursor()
    cur.execute(f"UPDATE products SET {col}=%s, {ts}=NOW() WHERE id=%s", (key, product_id))
    conn.commit(); cur.close(); conn.close()

def _upload_file_to_s3(file_storage, product_id: int, kind: str) -> str:
    filename = secure_filename(file_storage.filename or "")
    if not filename:
        raise ValueError(f"No file provided for {kind}")
    if not _allowed_ext(kind, filename):
        raise ValueError(f"Invalid file type for {kind}")

    key = _key_for(product_id, kind, filename)

    # ensure we read from the beginning even if Werkzeug wrapped it
    try:
        file_storage.stream.seek(0)
    except Exception:
        pass

    s3.upload_fileobj(
        Fileobj=file_storage.stream,
        Bucket=SDS_BUCKET,
        Key=key,
        ExtraArgs={
            "ContentType": _guess_content_type(kind, filename),
            "Metadata": {"product_id": str(product_id), "kind": kind},
            "CacheControl": "private, max-age=31536000",
        },
    )
    return key

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

# Run column guard once on import (Flask 3-safe)
try:
    with app.app_context():
        _ensure_product_columns_once()
        app.logger.info("SDS columns ensured.")
except Exception as e:
    app.logger.warning(f"SDS column ensure failed: {e}")

class LoginUser(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.email = row["email"]
        self.role = row["role"]
        self._active = row["is_active"]

    def is_active(self):
        return self._active

def get_user_by_id(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s AND is_active = TRUE", (user_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    return row

def get_user_by_email(email):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("SELECT * FROM users WHERE email = %s AND is_active = TRUE", (email,))
    row = cur.fetchone()
    cur.close(); conn.close()
    return row

def create_user(email, password, role):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (email, password_hash, role)
        VALUES (%s, %s, %s) RETURNING id
    """, (email.strip().lower(), generate_password_hash(password), role))
    uid = cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return uid

@login_manager.user_loader
def load_user(user_id):
    row = get_user_by_id(user_id)
    return LoginUser(row) if row else None

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role.upper() not in (r.upper() for r in roles):
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def tech_can_access_vehicle(vehicle_id:int) -> bool:
    if current_user.role == "ADMIN":
        return True
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT 1
        FROM vehicles v
        JOIN technicians t ON v.technician_id = t.id
        JOIN users u ON t.user_id = u.id
        WHERE v.vehicle_id = %s AND u.id = %s
        LIMIT 1
    """, (vehicle_id, current_user.id))
    ok = cur.fetchone() is not None
    cur.close(); conn.close()
    return ok

def require_vehicle_access(fn):
    @wraps(fn)
    def wrapper(vehicle_id, *args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not tech_can_access_vehicle(vehicle_id):
            abort(403)
        return fn(vehicle_id, *args, **kwargs)
    return wrapper

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

DEC = lambda x: Decimal(str(x))
def to_dec(x):
    if x is None: return Decimal("0")
    return x if isinstance(x, Decimal) else Decimal(str(x))
def fmt2(x):  # pretty print 2dp
    return f"{to_dec(x):.2f}"

# ---- header + parsing helpers ----
HEADER_ALIASES = {
    "sku": {"sku","item #","item#","item no.","item no","product #","code","item id","id"},
    "name": {"description","item description","product","item name"},
    "qty_ordered": {"qty ordered","ordered"},
    "qty_shipped": {"qty shipped","shipped"},
    "qty": {"qty","quantity"},
    "unit_price": {"unit price","price/unit","price ea","unit cost","price each","unit cost ($)","net price"},
    "amount": {"amount","line total","extended","ext price","extended price","ext. price","total"}
}
NON_PRODUCT_ROWS = {"subtotal","sales tax","freight","delivery","shipping","fuel surcharge","order total","amount due","tax"}

def norm_header(h: str) -> str:
    h = (h or "").strip().lower()
    for canon, aliases in HEADER_ALIASES.items():
        if h in aliases:
            return canon
    return h

def coerce_decimal(s: str) -> Decimal | None:
    if s is None: return None
    s = str(s).strip()
    if not s: return None
    s = s.replace("$","").replace(",","")
    if "/" in s:  # e.g., "38.781 / PK"
        s = s.split("/")[0].strip()
    m = re.search(r"[-+]?\d+(\.\d+)?", s)
    if not m: return None
    try:
        return DEC(m.group(0))
    except Exception:
        return None

def best_tables(page):
    tables = page.extract_tables({
        "vertical_strategy": "lines",
        "horizontal_strategy": "lines",
        "snap_tolerance": 3,
        "intersection_tolerance": 3
    }) or []
    tables += page.extract_tables({
        "vertical_strategy": "text",
        "horizontal_strategy": "text",
        "snap_tolerance": 3,
        "join_tolerance": 3,
        "intersection_tolerance": 3,
        "min_words_vertical": 1,
        "text_tolerance": 2
    }) or []
    return tables

def parse_pdf_lines(pdf_path: str):
    """Yield dicts: {sku,name,qty,unit_price,amount,unit_price_raw,amount_raw}."""
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            for table in best_tables(page):
                if not table or len(table) < 2:
                    continue
                header = [norm_header(x) for x in table[0]]
                idx = {col:i for i,col in enumerate(header)}
                if "name" not in idx:
                    continue

                for raw in table[1:]:
                    def col(c):
                        i = idx.get(c)
                        return (raw[i].strip() if (i is not None and i < len(raw) and raw[i]) else "")

                    # prefer Shipped, then Qty, then Ordered
                    qty_val = None
                    if "qty_shipped" in idx: qty_val = coerce_decimal(col("qty_shipped"))
                    if qty_val is None and "qty" in idx: qty_val = coerce_decimal(col("qty"))
                    if qty_val is None and "qty_ordered" in idx: qty_val = coerce_decimal(col("qty_ordered"))

                    name = col("name")
                    if name and name.strip().lower() in NON_PRODUCT_ROWS:
                        continue

                    data = {
                        "sku": col("sku"),
                        "name": name,
                        "qty": qty_val,
                        "unit_price_raw": col("unit_price"),
                        "amount_raw": col("amount"),
                        "unit_price": coerce_decimal(col("unit_price")),
                        "amount": coerce_decimal(col("amount")),
                    }

                    # derive unit price if missing but have qty & amount
                    if data["unit_price"] is None and data["qty"] not in (None, Decimal(0)) and data["amount"] is not None:
                        try:
                            data["unit_price"] = (data["amount"] / data["qty"])
                        except Exception:
                            pass

                    if not any([data["sku"], data["name"], data["qty"], data["unit_price"], data["amount"]]):
                        continue

                    yield data

def merge_wrapped_rows(rows):
    """Attach name-only rows to the previous row with a SKU (handles wrapped descriptions)."""
    merged = []
    for r in rows:
        if r["sku"] or not merged:
            merged.append(r)
        else:
            merged[-1]["name"] = (merged[-1]["name"] + " " + (r["name"] or "")).strip()
    return merged

def norm_id(s: str) -> str:
    """Normalize SKU: uppercase alphanum only."""
    if not s: return ""
    return re.sub(r"[^A-Z0-9]", "", s.upper())

@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("auth_login.html")

@app.post("/login")
@limiter.limit("10 per minute")
def login_post():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    user_row = get_user_by_email(email)
    if not user_row or not check_password_hash(user_row["password_hash"], password):
        return render_template("auth_login.html", error="Invalid email or password"), 401
    login_user(LoginUser(user_row), remember=True, duration=timedelta(days=14))
    return redirect(url_for("index"))

@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.get("/api/dashboard-stats")
@login_required
def api_dashboard_stats():
    conn = get_db_connection()
    cur = conn.cursor()

    # ---------- Totals & category counts (unit-aware, ignore archived) ----------
    total_value = 0.0
    lawn_count = pest_count = wildlife_count = 0
    try:
        # total inventory value
        cur.execute("""
            SELECT COALESCE(
                     SUM(
                       COALESCE(units_remaining,
                                stock * COALESCE(NULLIF(units_per_item,0),1)
                       )::numeric
                       *
                       COALESCE(unit_cost,
                                CASE WHEN COALESCE(NULLIF(units_per_item,0),1) > 0
                                     THEN cost_per_unit / COALESCE(NULLIF(units_per_item,0),1)
                                     ELSE cost_per_unit
                                END
                       )::numeric
                     ),
                     0
                   )
            FROM products
            WHERE is_archived = FALSE
        """)
        tv = cur.fetchone()[0]
        total_value = float(tv or 0)

        # category counts (case-insensitive, ignore archived)
        cur.execute("""
            SELECT
              SUM(CASE WHEN LOWER(COALESCE(category,''))='lawn'     THEN 1 ELSE 0 END),
              SUM(CASE WHEN LOWER(COALESCE(category,''))='pest'     THEN 1 ELSE 0 END),
              SUM(CASE WHEN LOWER(COALESCE(category,''))='wildlife' THEN 1 ELSE 0 END)
            FROM products
            WHERE is_archived = FALSE
        """)
        lc, pc, wc = cur.fetchone()
        lawn_count = int(lc or 0)
        pest_count = int(pc or 0)
        wildlife_count = int(wc or 0)
    except Exception as e:
        app.logger.exception("dashboard-stats totals failed: %s", e)

    # ---------- Vehicle due buckets (Oil Change only; FUTURE pending else last+5000) ----------
    red_vehicle_count = orange_vehicle_count = yellow_vehicle_count = due_vehicles_count = 0
    try:
        cur.execute("""
            WITH v AS (
              SELECT vehicle_id, COALESCE(current_mileage, mileage, 0) AS miles
              FROM vehicles
              WHERE status = 'active'
            ),
            calc AS (
              SELECT
                v.vehicle_id,
                v.miles,
                /* first FUTURE pending oil change (>= current miles) */
                (
                  SELECT MIN(mr.odometer_due)
                  FROM maintenance_reminders mr
                  WHERE mr.vehicle_id = v.vehicle_id
                    AND mr.received_at IS NULL
                    AND TRIM(LOWER(mr.service_type)) IN ('oil change','oil_change','oilchange')
                    AND mr.odometer_due >= v.miles
                ) AS next_pending_oil,
                /* last completed oil change */
                (
                  SELECT MAX(mr.odometer_due)
                  FROM maintenance_reminders mr
                  WHERE mr.vehicle_id = v.vehicle_id
                    AND mr.received_at IS NOT NULL
                    AND TRIM(LOWER(mr.service_type)) IN ('oil change','oil_change','oilchange')
                ) AS last_completed_oil
              FROM v
            ),
            final AS (
              SELECT
                COALESCE(next_pending_oil,
                         last_completed_oil + 5000,
                         miles + 5000) AS due_at,
                miles
              FROM calc
            )
            SELECT
              COUNT(*) FILTER (WHERE (due_at - miles) <  500),
              COUNT(*) FILTER (WHERE (due_at - miles) >= 500  AND (due_at - miles) < 1000),
              COUNT(*) FILTER (WHERE (due_at - miles) >= 1000 AND (due_at - miles) < 2000)
            FROM final
        """)
        r = cur.fetchone()
        red_vehicle_count, orange_vehicle_count, yellow_vehicle_count = [int(x or 0) for x in r]
        due_vehicles_count = red_vehicle_count + orange_vehicle_count + yellow_vehicle_count
    except Exception as e:
        app.logger.exception("dashboard-stats vehicle buckets failed: %s", e)

    # ---------- Open tech requests ----------
    open_requests_count = 0
    try:
        cur.execute("SELECT COUNT(*) FROM tech_requests WHERE status='open'")
        open_requests_count = int(cur.fetchone()[0] or 0)
    except Exception as e:
        app.logger.exception("dashboard-stats tech requests failed: %s", e)

    cur.close(); conn.close()

    resp = jsonify({
        "total_value": total_value,
        "lawn_count": lawn_count,
        "pest_count": pest_count,
        "wildlife_count": wildlife_count,
        "open_requests_count": open_requests_count,
        "red_vehicle_count": red_vehicle_count,
        "orange_vehicle_count": orange_vehicle_count,
        "yellow_vehicle_count": yellow_vehicle_count,
        "due_vehicles_count": due_vehicles_count,
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp

@app.get("/api/products")
@login_required
@role_required("ADMIN")
def api_products():
    category = request.args.get("category", "All")
    conn = get_db_connection()
    cur = conn.cursor()

    base_select = """
        SELECT
            id,                 -- [0]
            name,               -- [1]
            barcode,            -- [2]
            stock,              -- [3]  (you use this in the table)
            min_stock,          -- [4]
            cost_per_unit,      -- [5]
            siteone_sku,        -- [6]
            category,           -- [7]
            units_per_item,     -- [8]
            unit_cost,          -- [9]
            units_remaining     -- [10]
        FROM products
    """

    if category and category != "All":
        cur.execute(base_select + " WHERE category = %s AND is_archived = FALSE ORDER BY name", (category,))
    else:
        cur.execute(base_select + " WHERE is_archived = FALSE ORDER BY name")

    rows = cur.fetchall()
    cur.close(); conn.close()
    return jsonify(rows)

@app.get("/my")
@login_required
@role_required("TECH","ADMIN")
def tech_home():
    # keep your existing "assigned vehicle" lookup, but we’ll expand the data pulled
    vehicle_id = None
    if current_user.role == "TECH":
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT v.vehicle_id
              FROM vehicles v
              JOIN technicians t ON v.technician_id = t.id
             WHERE t.user_id = %s
             LIMIT 1
        """, (current_user.id,))
        row = cur.fetchone()
        vehicle_id = row[0] if row else None
        cur.close(); conn.close()

    # open a DictCursor for the rest of the page data
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # --- who is the current tech? (id) ---
    tech_id = None
    if current_user.role == "TECH":
        cur.execute("SELECT id FROM technicians WHERE user_id = %s", (current_user.id,))
        trow = cur.fetchone()
        tech_id = trow["id"] if trow else None

    # --- notifications (tech-specific or global) ---
    cur.execute("""
        SELECT id, title, body, severity, due_at, is_read, created_at
          FROM notifications
         WHERE (%s IS NOT NULL AND tech_id = %s) OR tech_id IS NULL
         ORDER BY
              CASE WHEN severity='critical' THEN 0
                   WHEN severity='high'     THEN 1
                   WHEN severity='normal'   THEN 2
                   ELSE 3 END,
              COALESCE(due_at, created_at) ASC
    """, (tech_id, tech_id))
    notifications = cur.fetchall()

    # --- checklist (per tech) ---
    cur.execute("""
        SELECT id, label, is_done, due_at
          FROM tech_checklist_items
         WHERE tech_id = %s
         ORDER BY COALESCE(due_at, now()) ASC, id ASC
    """, (tech_id,))
    checklist = cur.fetchall()

    # --- requests (tech sees their own; admin sees queue) ---
    if current_user.role == "ADMIN":
        # Show the whole queue with tech names
        cur.execute("""
            SELECT
                r.id,
                r.technician_id AS tech_id,
                t.name          AS tech_name,
                r.request_type,
                COALESCE(r.description, r.details, r.title) AS description,
                r.status,
                r.created_at,
                r.closed_at
            FROM tech_requests r
            LEFT JOIN technicians t ON t.id = r.technician_id
            ORDER BY (r.status = 'open') DESC, r.created_at DESC
        """)
    else:
        # Show only this tech's requests
        cur.execute("""
            SELECT
                r.id,
                r.technician_id AS tech_id,
                r.request_type,
                COALESCE(r.description, r.details, r.title) AS description,
                r.status,
                r.created_at,
                r.closed_at
            FROM tech_requests r
            WHERE r.technician_id = %s
            ORDER BY (r.status = 'open') DESC, r.created_at DESC
        """, (tech_id,))
    requests_rows = cur.fetchall()

    # --- training / CEU (global or tech-specific) ---
    cur.execute("""
        SELECT id, title, url, ceu_hours, expires_on
          FROM training_records
         WHERE (tech_id = %s OR tech_id IS NULL)
         ORDER BY COALESCE(expires_on, now()) ASC, title
    """, (tech_id,))
    training = cur.fetchall()

    # --- emergency contacts (global) ---
    cur.execute("""
        SELECT id, name, phone, kind, notes
          FROM emergency_contacts
         ORDER BY kind, name
    """)
    emergency = cur.fetchall()

    # --- vehicle(s) for this tech (you currently assign 1; we still structure as a list) ---
    vehicles = []
    if vehicle_id:
        cur.execute("""
            SELECT vehicle_id, license_plate, vehicle_type,
                   COALESCE(mileage, current_mileage, 0) AS vehicle_miles
              FROM vehicles
             WHERE vehicle_id = %s
        """, (vehicle_id,))
        v = cur.fetchone()
        if v:
            vehicles = [v]

    # --- build maintenance status per vehicle (derive status from odometer_due vs current miles) ---
    maint_by_vehicle = {}
    for v in vehicles:
        vid = v["vehicle_id"]
        current_miles = int(v["vehicle_miles"] or 0)

        cur.execute("""
            SELECT service_type, odometer_due, received_at
              FROM maintenance_reminders
             WHERE vehicle_id = %s
             ORDER BY received_at DESC NULLS LAST, odometer_due ASC
        """, (vid,))
        rows = cur.fetchall()

        # derive a compact status list (group by service_type → next due)
        by_service = {}
        for r in rows:
            s = r["service_type"].strip() if r["service_type"] else ""
            due = int(r["odometer_due"] or 0)
            # keep the nearest future/pending or latest record per service
            if s not in by_service:
                by_service[s] = due
            else:
                # prefer the larger due if it's in the future; otherwise keep max
                by_service[s] = max(by_service[s], due)

        summary = []
        for s, due in by_service.items():
            miles_remaining = due - current_miles
            if miles_remaining <= 0:
                status = "overdue"
            elif miles_remaining <= 500:
                status = "due_soon"
            else:
                status = "ok"
            summary.append({
                "service_type": s,
                "due_at": due,
                "miles_remaining": miles_remaining,
                "status": status
            })

        maint_by_vehicle[vid] = summary

    cur.close(); conn.close()

    return render_template(
        "tech_home.html",
        vehicle_id=vehicle_id,
        notifications=notifications,
        checklist=checklist,
        requests_rows=requests_rows,
        training=training,
        emergency=emergency,
        vehicles=vehicles,
        maint_by_vehicle=maint_by_vehicle,
        current_year=date.today().year
    )

@app.post("/my/notification/<int:nid>/ack")
@login_required
@role_required("TECH","ADMIN")
def ack_notification(nid):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE notifications SET is_read = TRUE WHERE id = %s", (nid,))
    conn.commit()
    cur.close(); conn.close()
    return redirect(url_for("tech_home"))

@app.post("/my/checklist/add")
@login_required
@role_required("TECH","ADMIN")
def checklist_add():
    label = (request.form.get("label") or "").strip()
    due_at = request.form.get("due_at") or None
    if not label:
        return redirect(url_for("tech_home"))
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # resolve current tech_id
    cur.execute("SELECT id FROM technicians WHERE user_id = %s", (current_user.id,))
    trow = cur.fetchone()
    tech_id = trow["id"] if trow else None
    cur.execute("""
        INSERT INTO tech_checklist_items (tech_id, label, is_done, due_at)
        VALUES (%s, %s, FALSE, %s)
    """, (tech_id, label, due_at))
    conn.commit(); cur.close(); conn.close()
    return redirect(url_for("tech_home"))

@app.post("/my/checklist/<int:item_id>/toggle")
@login_required
@role_required("TECH","ADMIN")
def checklist_toggle(item_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE tech_checklist_items SET is_done = NOT is_done WHERE id = %s", (item_id,))
    conn.commit(); cur.close(); conn.close()
    return redirect(url_for("tech_home"))

@app.post("/my/request/new")
@login_required
@role_required("TECH", "ADMIN")
def tech_request_new():
    # --- sanitize inputs ---
    req_type = (request.form.get("request_type") or "other").strip().lower()
    desc = (request.form.get("description") or "").strip()
    if not desc:
        return redirect(url_for("tech_home"))

    # only allow values your enum supports
    allowed = {"new_chemical", "equipment", "other"}
    if req_type not in allowed:
        req_type = "other"

    # build a human title (DB column is NOT NULL)
    type_titles = {
        "new_chemical": "Request to Try New Chemical",
        "equipment": "Equipment Request",
        "other": "Technician Request",
    }
    base_title = type_titles.get(req_type, "Technician Request")
    # add a short suffix from the description
    suffix = (desc[:60] + "…" if len(desc) > 60 else desc)
    title = (f"{base_title}: {suffix}").strip()[:120]  # keep titles short

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        # find this user's technician_id
        cur.execute("SELECT id FROM technicians WHERE user_id = %s", (current_user.id,))
        trow = cur.fetchone()
        if not trow:
            cur.close(); conn.close()
            return redirect(url_for("tech_home"))

        technician_id = trow["id"]

        # Insert — note: request_type is ENUM, status is TEXT in your DB
        cur.execute("""
            INSERT INTO tech_requests (
                technician_id, request_type, title, description, status, created_at, updated_at
            ) VALUES (
                %s, %s::request_type, %s, %s, 'open', NOW(), NOW()
            )
        """, (technician_id, req_type, title, desc))

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close(); conn.close()

    return redirect(url_for("tech_home"))

@app.post("/my/request/<int:req_id>/close")
@login_required
@role_required("ADMIN")
def tech_request_close(req_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        UPDATE tech_requests
           SET status = 'closed', closed_at = NOW()
         WHERE id = %s AND status = 'open'
    """, (req_id,))
    conn.commit(); cur.close(); conn.close()
    return redirect(url_for("tech_home"))

@app.route('/')
@login_required
def index():
    if current_user.role == 'TECH':
        return redirect(url_for('tech_home'))

    conn = get_db_connection()
    cur = conn.cursor()

    category_filter = request.args.get('category', 'All')
    if category_filter == 'All':
        cur.execute("""
            SELECT * FROM products
            WHERE is_archived = FALSE
            ORDER BY id
        """)
    else:
        cur.execute("""
            SELECT * FROM products
            WHERE category = %s AND is_archived = FALSE
            ORDER BY id
        """, (category_filter,))
    products = cur.fetchall()

    # ✅ Total inventory value (correct columns + ignore archived)
    cur.execute("""
        SELECT COALESCE(
                 SUM(
                   COALESCE(units_remaining,
                            stock * COALESCE(NULLIF(units_per_item,0),1)
                   )::numeric
                   *
                   COALESCE(unit_cost,
                            CASE WHEN COALESCE(NULLIF(units_per_item,0),1) > 0
                                 THEN cost_per_unit / COALESCE(NULLIF(units_per_item,0),1)
                                 ELSE cost_per_unit
                            END
                   )::numeric
                 ),
                 0
               )
        FROM products
        WHERE is_archived = FALSE
    """)
    inventory_total = float(cur.fetchone()[0] or 0)

    cur.execute("SELECT COUNT(*) FROM products WHERE category='Lawn'     AND is_archived=FALSE")
    lawn_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM products WHERE category='Pest'     AND is_archived=FALSE")
    pest_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM products WHERE category='Wildlife' AND is_archived=FALSE")
    wildlife_count = cur.fetchone()[0]

    cur.close(); conn.close()

    technicians = get_all_technicians()
    return render_template(
        'index.html',
        products=products,
        technicians=technicians,
        total_value=inventory_total,
        category_filter=category_filter,
        lawn_count=lawn_count,
        pest_count=pest_count,
        wildlife_count=wildlife_count
    )

@app.route("/test-email")
@login_required
@role_required('ADMIN')
def test_email():
    send_maintenance_email("Test Vehicle", 500)
    return "✅ Test email sent!"

# ----------------------
# Admin: Manage Users
# ----------------------

@app.route("/admin/users")
@login_required
@role_required("ADMIN")
def admin_users_list():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("""
        SELECT u.id, u.email, u.role, u.is_active, u.created_at,
               t.id AS tech_id, t.name AS tech_name, v.vehicle_id
          FROM users u
     LEFT JOIN technicians t ON t.user_id = u.id
     LEFT JOIN vehicles v ON v.technician_id = t.id
      ORDER BY u.created_at DESC, u.id DESC
    """)
    users = cur.fetchall()

    # for quick create modal: list technicians without a linked user
    cur.execute("""
        SELECT t.id, t.name
          FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
         WHERE t.user_id IS NULL
      ORDER BY t.name
    """)
    free_techs = cur.fetchall()

    conn.close()
    return render_template("admin_users_list.html", users=users, free_techs=free_techs)


@app.route("/admin/users/new", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def admin_users_new():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # technicians for dropdown (unlinked only)
    cur.execute("""
        SELECT t.id, t.name
          FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
         WHERE t.user_id IS NULL
      ORDER BY t.name
    """)
    technicians = cur.fetchall()

    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "TECH").upper()
        tech_id = request.form.get("technician_id")  # optional; only for TECH role

        if not email or not password or role not in ("ADMIN", "TECH"):
            cur.close(); conn.close()
            return render_template("admin_user_form.html", technicians=technicians,
                                   error="Email, password, and role are required.", user=None)

        # create user
        uid = None
        try:
            # unique by LOWER(email) enforced app-side (you can add a DB unique index on lower(email) later)
            existing = None
            cur.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(%s)", (email,))
            existing = cur.fetchone()
            if existing:
                raise ValueError("A user with that email already exists.")

            cur.execute("""
                INSERT INTO users (email, password_hash, role, is_active)
                VALUES (%s, %s, %s, TRUE) RETURNING id
            """, (email, generate_password_hash(password), role))
            uid = cur.fetchone()["id"]

            # link to technician if TECH + tech selected
            if role == "TECH" and tech_id:
                cur.execute("UPDATE technicians SET user_id = %s WHERE id = %s AND user_id IS NULL", (uid, tech_id))

            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close(); conn.close()
            return render_template("admin_user_form.html", technicians=technicians,
                                   error=f"Error: {e}", user=None)

        cur.close(); conn.close()
        return redirect(url_for("admin_users_list"))

    # GET
    cur.close(); conn.close()
    return render_template("admin_user_form.html", technicians=technicians, user=None)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@role_required("ADMIN")
def admin_users_edit(user_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # load user
    cur.execute("SELECT id, email, role, is_active FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return "User not found", 404

    # which tech is currently linked?
    cur.execute("""
        SELECT t.id, t.name FROM technicians t WHERE t.user_id = %s
    """, (user_id,))
    linked = cur.fetchone()

    # technicians available for selection: either unlinked, or the currently linked one
    cur.execute("""
        SELECT t.id, t.name
          FROM technicians t
     LEFT JOIN users u ON u.id = t.user_id
         WHERE t.user_id IS NULL OR t.user_id = %s
      ORDER BY t.name
    """, (user_id,))
    technicians = cur.fetchall()

    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        role = (request.form.get("role") or "TECH").upper()
        is_active = True if request.form.get("is_active") == "on" else False
        tech_id = request.form.get("technician_id")  # may be empty

        if not email or role not in ("ADMIN", "TECH"):
            cur.close(); conn.close()
            return render_template("admin_user_form.html", user=user, technicians=technicians, linked=linked,
                                   error="Email and valid role are required.")

        try:
            # ensure email uniqueness (excluding myself)
            cur.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(%s) AND id<>%s", (email, user_id))
            if cur.fetchone():
                raise ValueError("Another user already has that email.")

            # update base fields
            cur.execute("""
                UPDATE users SET email=%s, role=%s, is_active=%s WHERE id=%s
            """, (email, role, is_active, user_id))

            # manage tech link
            if role == "TECH":
                if tech_id:
                    # unlink any tech currently pointing to this user (if changing links)
                    cur.execute("UPDATE technicians SET user_id = NULL WHERE user_id = %s AND id <> %s", (user_id, tech_id))
                    # link selected tech
                    cur.execute("UPDATE technicians SET user_id = %s WHERE id = %s", (user_id, tech_id))
                else:
                    # tech role but no tech selected: leave as-is (or unlink if you prefer)
                    pass
            else:
                # role changed to ADMIN → unlink any tech
                cur.execute("UPDATE technicians SET user_id = NULL WHERE user_id = %s", (user_id,))

            conn.commit()
        except Exception as e:
            conn.rollback()
            cur.close(); conn.close()
            return render_template("admin_user_form.html", user=user, technicians=technicians, linked=linked,
                                   error=f"Error: {e}")

        cur.close(); conn.close()
        return redirect(url_for("admin_users_list"))

    # GET
    cur.close(); conn.close()
    return render_template("admin_user_form.html", user=user, technicians=technicians, linked=linked)


@app.route("/admin/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@role_required("ADMIN")
def admin_users_reset_password(user_id):
    new_pw = request.form.get("new_password") or ""
    if len(new_pw) < 8:
        return "Password must be at least 8 characters.", 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                    (generate_password_hash(new_pw), user_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close(); conn.close()
        return f"Error: {e}", 500
    cur.close(); conn.close()
    return redirect(url_for("admin_users_list"))


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@role_required("ADMIN")
def admin_users_toggle_active(user_id):
    to_state = request.form.get("to_state", "off") == "on"
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET is_active=%s WHERE id=%s", (to_state, user_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        cur.close(); conn.close()
        return f"Error: {e}", 500
    cur.close(); conn.close()
    return redirect(url_for("admin_users_list"))

@app.get("/tech-requests")
@login_required
@role_required("ADMIN")
def tech_requests_queue():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute("""
        SELECT
            r.id,
            r.technician_id   AS tech_id,
            t.name            AS tech_name,
            r.vehicle_id,
            r.request_type,
            COALESCE(r.description, r.details, r.title) AS description,
            r.status,
            r.created_at,
            r.closed_at
        FROM tech_requests r
        LEFT JOIN technicians t ON t.id = r.technician_id
        ORDER BY (r.status = 'open') DESC, r.created_at DESC
    """)
    requests_rows = cur.fetchall()
    cur.close(); conn.close()
    return render_template("admin_requests.html", requests_rows=requests_rows)

@app.route("/scan")
@login_required
@role_required('ADMIN')
def scan():
    technicians = get_all_technicians()
    return render_template("scanner.html", technicians=technicians)

@app.route("/add-product", methods=["POST"])
@login_required
@role_required('ADMIN')
def add_product():
    name = request.form["name"]
    barcode = request.form["barcode"]
    min_stock = int(request.form["min_stock"])
    cost_per_unit = float(request.form.get("cost_per_unit", 0))
    siteone_sku = request.form.get("siteone_sku", "").strip()
    category = request.form.get("category", "Pest")

    # defaults for partials math
    units_per_item = 1
    unit_cost = cost_per_unit
    in_stock = 0
    units_remaining = 0

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO products (
            name, barcode, stock, min_stock, cost_per_unit,
            siteone_sku, category, units_per_item, unit_cost, units_remaining, is_archived
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, FALSE)
    """, (name, barcode, in_stock, min_stock, cost_per_unit,
          siteone_sku, category, units_per_item, unit_cost, units_remaining))
    conn.commit()
    cur.close(); conn.close()
    return redirect("/")

@app.route('/edit-product/<int:product_id>', methods=['POST'])
@login_required
@role_required('ADMIN')
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
@login_required
@role_required('ADMIN')
def delete_product(product_id):
    conn = get_db_connection(); cur = conn.cursor()
    try:
        # Soft-delete
        cur.execute("UPDATE products SET is_archived = TRUE WHERE id=%s", (product_id,))
        conn.commit()
        flash("Product archived. It will no longer appear in lists or inventory add forms.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Could not archive product: {e}", "danger")
    finally:
        cur.close(); conn.close()
    return redirect(url_for('index'))

@app.route('/export-products')
@login_required
@role_required('ADMIN')
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
@login_required
@role_required('ADMIN')
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
@login_required
@role_required('ADMIN')
def assign_technician(vehicle_id):
    tech_id = request.form['technician_id']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE vehicles SET technician_id = %s WHERE vehicle_id = %s", (tech_id, vehicle_id))
    conn.commit()
    conn.close()
    return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

@app.route('/vehicle-inspection/<int:vehicle_id>', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
def vehicle_inspection(vehicle_id):
    import json
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

        # Collect all checklist fields
        checklist_fields = [
            # Vehicle Items
            "headlights_working", "turn_signals_working", "brake_lights_working", "windshield_wipers",
            "brakes_ok_(per_driver)", "any_brake_noise", "tie_down_straps", "chemical_box_locked",
            "windows/windshield_cracked", "horn_working_properly", "seat_belts_in_good_condition",
            "chemical_labels_secured", "equipment_inventory_list", "vehicle_registration",
            "vehicle_insurance_card", "dacs_id_card", "updated_phone/pp_app",

            # Safety Items
            "soak_up/spill_kit", "first_aid_kit", "respirator_clean", "flares/triangles",
            "fire_extinguisher", "safety_glasses/goggles", "protective_gloves", "booties_present",
            "long_sleeve_shirt", "poison_control_center_number", "chemical_sensitive_list",
            "label/msds_binder"
        ]

        checklist_data = {
            field.replace('/', '_').replace(' ', '_').lower(): request.form.get(field.replace('/', '_').replace(' ', '_').lower())
            for field in checklist_fields
        }

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
                photo_misc_1, photo_misc_2, photo_misc_3, photo_misc_4,
                checklist_data
            ) VALUES (%s, %s, %s, %s, %s, %s,
                      %s, %s, %s, %s,
                      %s, %s, %s, %s,
                      %s, %s, %s, %s,
                      %s)
        """, (
            vehicle_id, technician_id, mileage, cleanliness, wrap_condition, comments,
            photos['photo_front'], photos['photo_back'], photos['photo_side_left'], photos['photo_side_right'],
            photos['photo_tire_front_left'], photos['photo_tire_front_right'],
            photos['photo_tire_rear_left'], photos['photo_tire_rear_right'],
            photos['photo_misc_1'], photos['photo_misc_2'], photos['photo_misc_3'], photos['photo_misc_4'],
            json.dumps(checklist_data)
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
@login_required
@role_required('ADMIN')
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

# Single-row equipment update (status + notes)
@app.route("/vehicles/<int:vehicle_id>/equipment/<int:equipment_id>/update", methods=["POST"])
@login_required
@role_required('ADMIN')
def update_single_equipment(vehicle_id, equipment_id):
    status = request.form.get("status")
    notes = (request.form.get("notes") or "").strip()

    if not status:
        return "Missing status", 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Adjust table/column names if yours differ
        cur.execute("""
            UPDATE vehicle_equipment
               SET status = %s,
                   notes = %s,
                   last_verified = NOW()
             WHERE id = %s AND vehicle_id = %s
        """, (status, notes, equipment_id, vehicle_id))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    # Optional flash if you’re using messages
    # flash("Equipment updated", "success")
    return redirect(url_for("vehicle_profile", vehicle_id=vehicle_id))

@app.route('/vehicles/<int:vehicle_id>')
@login_required
@require_vehicle_access
def vehicle_profile(vehicle_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Vehicle basic info
    cur.execute("""
        SELECT v.vehicle_id, v.license_plate, v.vehicle_type, t.name AS technician,
               COALESCE(v.mileage, v.current_mileage, 0) AS vehicle_miles
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

    # Inspections (latest 5) – purely for display, not logic
    cur.execute("""
        SELECT
            id, date, technician_id, vehicle_id, mileage,
            cleanliness, wrap_condition, comments,
            photo_front, photo_back, photo_side_left, photo_side_right,
            photo_tire_front_left, photo_tire_front_right,
            photo_tire_rear_left, photo_tire_rear_right
        FROM vehicle_inspections
        WHERE vehicle_id = %s
        ORDER BY date DESC, id DESC
        LIMIT 5
    """, (vehicle_id,))
    inspections = cur.fetchall()

    # --- Current mileage basis comes ONLY from vehicles table ---
    current_mileage = int(vehicle['vehicle_miles'] or 0)

    # ---------- SELF-HEAL: normalize & seed missing service types ----------
    # 1) Normalize service_type for this vehicle (trailing spaces/variants)
    cur.execute("""
        UPDATE maintenance_reminders
           SET service_type = TRIM(service_type)
         WHERE vehicle_id = %s
           AND service_type <> TRIM(service_type)
    """, (vehicle_id,))

    # 2) Ensure each service exists at least once for this vehicle
    def ensure_service_exists(service_type: str, interval_miles: int = 5000):
        # Any row for this service?
        cur.execute("""
            SELECT COUNT(*)
              FROM maintenance_reminders
             WHERE vehicle_id = %s AND service_type = %s
        """, (vehicle_id, service_type))
        have = cur.fetchone()[0]

        if have and have > 0:
            return  # already have history/pending for this service

        # Try last completed to base the next due
        cur.execute("""
            SELECT odometer_due
              FROM maintenance_reminders
             WHERE vehicle_id = %s
               AND service_type = %s
               AND received_at IS NOT NULL
             ORDER BY received_at DESC
             LIMIT 1
        """, (vehicle_id, service_type))
        last_done = cur.fetchone()

        if last_done:
            due_at = int(last_done['odometer_due']) + interval_miles
        else:
            due_at = current_mileage + interval_miles

        # Insert a pending reminder so Upcoming will show it
        cur.execute("""
            INSERT INTO maintenance_reminders (vehicle_id, service_type, odometer_due, received_at)
            VALUES (%s, %s, %s, NULL)
        """, (vehicle_id, service_type, due_at))

    # Ensure both services exist
    ensure_service_exists('Oil Change', 5000)
    ensure_service_exists('Tire Rotation', 5000)
    conn.commit()
    # ---------- end self-heal ----------

    # --- Reminder Generation Logic (history-driven only) ---
    def get_next_due(service_type_exact, interval_miles):
        """
        Prefer newest pending reminder (received_at IS NULL) with highest odometer_due.
        If none pending, fall back to last completed and add interval.
        """
        # 1) Pending
        cur.execute("""
            SELECT odometer_due, received_at
            FROM maintenance_reminders
            WHERE vehicle_id = %s AND service_type = %s AND received_at IS NULL
            ORDER BY odometer_due DESC
            LIMIT 1
        """, (vehicle_id, service_type_exact))
        row = cur.fetchone()

        if row:
            due_at = row['odometer_due']
            miles_remaining = due_at - current_mileage
            status = "overdue" if miles_remaining <= 0 else ("due_soon" if miles_remaining <= 500 else "ok")
            return {
                "service_type": service_type_exact,
                "last_done": row['received_at'],   # None
                "last_odometer": row['odometer_due'],
                "due_at": due_at,
                "status": status,
                "miles_remaining": miles_remaining,
                "is_pending": True
            }

        # 2) Last completed
        cur.execute("""
            SELECT odometer_due, received_at
            FROM maintenance_reminders
            WHERE vehicle_id = %s AND service_type = %s AND received_at IS NOT NULL
            ORDER BY received_at DESC
            LIMIT 1
        """, (vehicle_id, service_type_exact))
        row = cur.fetchone()

        if not row:
            return None  # 🔒 No history -> do NOT fabricate a default

        last_odo = row['odometer_due']
        due_at = last_odo + interval_miles
        miles_remaining = due_at - current_mileage
        status = "overdue" if miles_remaining <= 0 else ("due_soon" if miles_remaining <= 500 else "ok")

        return {
            "service_type": service_type_exact,
            "last_done": row['received_at'],
            "last_odometer": last_odo,
            "due_at": due_at,
            "status": status,
            "miles_remaining": miles_remaining,
            "is_pending": False
        }

    reminders = []
    for service, interval in [('Oil Change', 5000), ('Tire Rotation', 5000)]:
        result = get_next_due(service, interval)
        if result:
            reminders.append(result)

            # Email alerts only for a real pending reminder row
            if service == 'Oil Change' and result.get('is_pending'):
                cur.execute("""
                    SELECT emailed_1000, emailed_500
                    FROM maintenance_reminders
                    WHERE vehicle_id = %s AND service_type = %s AND odometer_due = %s
                    ORDER BY received_at DESC NULLS LAST
                    LIMIT 1
                """, (vehicle_id, service, result['due_at']))
                email_flags = cur.fetchone()

                if email_flags:
                    emailed_1000, emailed_500 = email_flags['emailed_1000'], email_flags['emailed_500']

                    if result['miles_remaining'] <= 1000 and not emailed_1000:
                        from email_utils import send_maintenance_email
                        vehicle_name = f"{vehicle['vehicle_type']} {vehicle['license_plate']}"
                        send_maintenance_email(
                            vehicle_id, vehicle_name, result['due_at'], current_mileage, vehicle['license_plate']
                        )
                        cur.execute("""
                            UPDATE maintenance_reminders
                               SET emailed_1000 = TRUE
                             WHERE vehicle_id = %s AND service_type = %s AND odometer_due = %s
                        """, (vehicle_id, service, result['due_at']))
                        conn.commit()

                    if result['miles_remaining'] <= 500 and not emailed_500:
                        from email_utils import send_maintenance_email
                        vehicle_name = f"{vehicle['vehicle_type']} {vehicle['license_plate']}"
                        send_maintenance_email(
                            vehicle_id, vehicle_name, result['due_at'], current_mileage, vehicle['license_plate']
                        )
                        cur.execute("""
                            UPDATE maintenance_reminders
                               SET emailed_500 = TRUE
                             WHERE vehicle_id = %s AND service_type = %s AND odometer_due = %s
                        """, (vehicle_id, service, result['due_at']))
                        conn.commit()

    # Full Maintenance Log (history + pending)
    cur.execute("""
        SELECT id, service_type, odometer_due, received_at, invoice_url
        FROM maintenance_reminders
        WHERE vehicle_id = %s
        ORDER BY received_at DESC NULLS LAST, odometer_due ASC
    """, (vehicle_id,))
    raw_maintenance = cur.fetchall()

    maintenance_logs = []
    for m in raw_maintenance:
        miles_remaining = m['odometer_due'] - current_mileage
        is_overdue = current_mileage >= m['odometer_due']
        is_approaching = 0 < miles_remaining <= 500
        status = "overdue" if is_overdue else ("due_soon" if is_approaching else "ok")
        maintenance_logs.append({**m, "status": status, "miles_remaining": miles_remaining})

    # General Service Logs from vehicle_services
    cur.execute("""
        SELECT id, service_type, odometer, logged_on, invoice_url, notes
        FROM vehicle_services
        WHERE vehicle_id = %s
        ORDER BY logged_on DESC
    """, (vehicle_id,))
    service_logs = cur.fetchall()

    # Equipment
    cur.execute("""
        SELECT * FROM vehicle_equipment
        WHERE vehicle_id = %s
        ORDER BY item_name
    """, (vehicle_id,))
    equipment = cur.fetchall()

    conn.close()

    return render_template(
        'vehicle_profile.html',
        vehicle=vehicle,
        inventory=inventory,
        inspections=inspections,
        maintenance_logs=maintenance_logs,
        last_mileage=current_mileage,
        reminders=reminders,
        vehicle_services=service_logs,
        equipment=equipment
    )
    
@app.route("/add-vehicle-service", methods=["POST"])
@login_required
@role_required('ADMIN')
def add_vehicle_service():
    vehicle_id = request.form["vehicle_id"]
    service_type = request.form["service_type"]
    odometer = request.form["odometer"]
    notes = request.form.get("notes", "")

    file = request.files.get("invoice_file")
    invoice_url = ""

    if file and file.filename:
        filename = secure_filename(file.filename)
        key = f"invoices/{uuid.uuid4()}_{filename}"   # IMPORTANT: invoices/ prefix
        s3 = boto3.client(
            "s3",
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
            region_name="us-east-2",
        )
        file.seek(0)
        s3.upload_fileobj(
            file,
            "palmcoast-invoices",
            key,
            ExtraArgs={"ContentType": file.content_type or "application/pdf"}
        )
        # Public URL works because of your bucket policy on invoices/*
        invoice_url = f"https://palmcoast-invoices.s3.us-east-2.amazonaws.com/{key}"

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vehicle_services (vehicle_id, service_type, odometer, notes, invoice_url)
        VALUES (%s, %s, %s, %s, %s)
    """, (vehicle_id, service_type, odometer, notes, invoice_url))
    conn.commit()
    conn.close()

    return redirect(f"/vehicles/{vehicle_id}")

@app.route('/upload-invoice/<int:maintenance_id>', methods=['POST'])
@login_required
@role_required('ADMIN')
def upload_vehicle_invoice(maintenance_id):
    import boto3
    from datetime import datetime
    from werkzeug.utils import secure_filename

    S3_BUCKET = 'palmcoast-invoices'  # Make sure this matches your actual bucket name
    s3 = boto3.client('s3')

    file = request.files.get('invoice')
    if not file or not file.filename.lower().endswith('.pdf'):
        return "Invalid file", 400

    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    filename = f"invoice_{maintenance_id}_{timestamp}_{secure_filename(file.filename)}"
    s3_key = f"invoices/{filename}"

    # Upload to S3
    s3.upload_fileobj(file, S3_BUCKET, s3_key)

    invoice_url = f"https://{S3_BUCKET}.s3.amazonaws.com/{s3_key}"

    # Update the database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE maintenance_reminders SET invoice_url = %s WHERE id = %s", (invoice_url, maintenance_id))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(request.referrer or '/vehicles')

@app.route('/mark-maintenance-complete/<int:vehicle_id>', methods=['POST'])
@login_required
@role_required('ADMIN')
def mark_maintenance_complete(vehicle_id):
    # Pull and sanitize form data
    raw_service_type = request.form.get('service_type', '')
    current_odometer = request.form.get('odometer', '').strip()

    service_type = (raw_service_type or '').strip()   # remove leading/trailing spaces
    if not service_type or not current_odometer:
        return "Missing data", 400

    try:
        # ensure numeric miles (reject commas etc.)
        current_odometer = int(str(current_odometer).replace(',', '').strip())
        next_due = current_odometer + 5000

        conn = get_db_connection()
        cur = conn.cursor()

        # 1) Delete only FUTURE, pending reminders of this type
        cur.execute(
            """
            DELETE FROM maintenance_reminders
            WHERE vehicle_id = %s
              AND service_type = %s
              AND odometer_due > %s
              AND received_at IS NULL
            """,
            (vehicle_id, service_type, current_odometer)  # <-- explicit tuple
        )

        # 2) Insert the completed record
        cur.execute(
            """
            INSERT INTO maintenance_reminders (vehicle_id, service_type, odometer_due, received_at)
            VALUES (%s, %s, %s, CURRENT_DATE)
            """,
            (vehicle_id, service_type, current_odometer)
        )

        # 3) Insert the next pending reminder
        cur.execute(
            """
            INSERT INTO maintenance_reminders (vehicle_id, service_type, odometer_due, received_at)
            VALUES (%s, %s, %s, NULL)
            """,
            (vehicle_id, service_type, next_due)
        )

        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

    except Exception as e:
        # helpful diagnostics in logs
        app.logger.exception(
            "Failed to complete maintenance: vehicle_id=%s, service_type=%r, odometer=%r",
            vehicle_id, raw_service_type, current_odometer
        )
        return f"Error: {e}", 500

@app.route('/inspections') 
@login_required
@role_required('ADMIN')
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
@login_required
@role_required('ADMIN')
def inspection_detail(inspection_id):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Updated: Include checklist_data in SELECT
    cur.execute("""
        SELECT vi.id, vi.date, t.name AS technician, vi.mileage, vi.cleanliness, vi.wrap_condition,
               vi.comments, vi.vehicle_id, vi.checklist_data,  -- ✅ this line gets the checklist JSON
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

    import json  # make sure this is at the top of the file
    if inspection['checklist_data'] and isinstance(inspection['checklist_data'], str):
        try:
            inspection['checklist_data'] = json.loads(inspection['checklist_data'])
        except json.JSONDecodeError:
            inspection['checklist_data'] = {}
    elif not inspection['checklist_data']:
        inspection['checklist_data'] = {}

    # Split checklist into categories for display
    vehicle_keys = [
        "headlights_working", "turn_signals_working", "brake_lights_working", "windshield_wipers",
        "brakes_ok_per_driver", "any_brake_noise", "tie_down_straps", "chemical_box_locked",
        "windows_windshield_cracked", "horn_working_properly", "seat_belts_in_good_condition",
        "chemical_labels_secured", "equipment_inventory_list", "vehicle_registration",
        "vehicle_insurance_card", "dacs_id_card", "updated_phone_pp_app"
    ]

    safety_keys = [
        "soak_up_spill_kit", "first_aid_kit", "respirator_clean", "flares_triangles",
        "fire_extinguisher", "safety_glasses_goggles", "protective_gloves", "booties_present",
        "long_sleeve_shirt", "poison_control_center_number", "chemical_sensitive_list",
        "label_msds_binder"
    ]

    checklist_raw = inspection['checklist_data']
    checklist_structured = {
        "vehicle_items": {k: checklist_raw[k] for k in vehicle_keys if k in checklist_raw},
        "safety_items": {k: checklist_raw[k] for k in safety_keys if k in checklist_raw}
    }

    return render_template(
        "inspection_detail.html",
        inspection=inspection,
        last_oil=last_oil,
        last_rotation=last_rotation,
        oil_due=oil_due,
        rotation_due=rotation_due,
        checklist_data=checklist_structured  # ✅ structured by category
    )

@app.route('/delete-inspection/<int:inspection_id>', methods=['POST'])
@login_required
@role_required('ADMIN')
def delete_inspection(inspection_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("DELETE FROM vehicle_inspections WHERE id = %s", (inspection_id,))
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('inspections_list'))

@app.route('/vehicles')
@login_required
@role_required('ADMIN')
def vehicles_list():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cur.execute("""
        SELECT v.vehicle_id, v.license_plate, v.vehicle_type,
               COALESCE(t.name, 'Unassigned') as technician
        FROM vehicles v
        LEFT JOIN technicians t ON v.technician_id = t.id
        WHERE v.status = 'active'
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
@login_required
@role_required('ADMIN')
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
@login_required
@role_required('ADMIN')
def delete_vehicle(vehicle_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # Unassign any tech
    cur.execute("UPDATE technicians SET vehicle_id = NULL WHERE vehicle_id = %s", (vehicle_id,))

    # Clear inventory links
    cur.execute("DELETE FROM vehicle_inventory WHERE vehicle_id = %s", (vehicle_id,))

    # Soft delete instead of full delete
    cur.execute("UPDATE vehicles SET status = 'inactive' WHERE vehicle_id = %s", (vehicle_id,))

    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('vehicles_list'))

@app.route('/vehicles/<int:vehicle_id>/update-equipment', methods=['POST'])
@login_required
@role_required('ADMIN')
def update_equipment(vehicle_id):
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch all equipment for this vehicle
    cur.execute(
        'SELECT id FROM vehicle_equipment WHERE vehicle_id = %s', (vehicle_id,)
    )
    equipment_items = cur.fetchall()

    for item in equipment_items:
        item_id = item[0]  # since fetchall() returns a list of tuples
        status = request.form.get(f'status_{item_id}')
        notes = request.form.get(f'notes_{item_id}')

        cur.execute(
            'UPDATE vehicle_equipment SET status = %s, notes = %s, last_verified = CURRENT_DATE WHERE id = %s',
            (status, notes, item_id)
        )

    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

@app.route('/vehicles/<int:vehicle_id>/add-equipment', methods=['POST'])
@login_required
@role_required('ADMIN')
def add_equipment(vehicle_id):
    item_name = request.form['item_name']
    status = request.form.get('status', 'Assigned')
    notes = request.form.get('notes', '')

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vehicle_equipment (vehicle_id, item_name, status, notes, last_verified)
        VALUES (%s, %s, %s, %s, CURRENT_DATE)
    """, (vehicle_id, item_name, status, notes))
    conn.commit()
    conn.close()

    return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

@app.route('/vehicles/<int:vehicle_id>/delete-equipment/<int:equipment_id>', methods=['POST'])
@login_required
@role_required('ADMIN')
def delete_equipment(vehicle_id, equipment_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM vehicle_equipment WHERE id = %s AND vehicle_id = %s", (equipment_id, vehicle_id))
    conn.commit()
    conn.close()
    return redirect(url_for('vehicle_profile', vehicle_id=vehicle_id))

@app.route('/sds')
@login_required
@role_required('TECH','ADMIN')
def sds_portal():
    filter_type = request.args.get('filter', '')
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    where = "WHERE p.sds_key IS NOT NULL OR p.sds_url IS NOT NULL" if filter_type == 'has_sds' else ""
    cur.execute(f"""
        SELECT
            p.id, p.name, p.epa_number,
            p.sds_key, p.label_key, p.barcode_key,
            p.sds_url, p.label_url, p.barcode_img_url,
            p.sds_uploaded_on
        FROM products p
        {where}
        ORDER BY p.name;
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()

    products = []
    for r in rows:
        sds_link = _handle_to_presigned(r["sds_key"], "sds") or _handle_to_presigned(r["sds_url"], "sds")
        label_link = _handle_to_presigned(r["label_key"], "label") or _handle_to_presigned(r["label_url"], "label")
        barcode_link = _handle_to_presigned(r["barcode_key"], "barcode") or _handle_to_presigned(r["barcode_img_url"], "barcode")
        products.append({
            "id": r["id"], "name": r["name"], "epa_number": r["epa_number"],
            "sds_url": sds_link, "label_url": label_link, "barcode_img_url": barcode_link,
            "sds_uploaded_on": r["sds_uploaded_on"],
        })

    return render_template('sds_view.html', products=products, today=date.today())

@app.get("/sds/<int:product_id>/<kind>")
@login_required
def sds_open(product_id, kind):
    assert kind in ("sds", "label", "barcode")

    conn = get_db_connection(); cur = conn.cursor()
    cur.execute("""
        SELECT sds_key, label_key, barcode_key,
               COALESCE(sds_url, '')  AS legacy_sds,
               COALESCE(label_url, '') AS legacy_label,
               COALESCE(barcode_img_url, '') AS legacy_barcode
        FROM products WHERE id=%s
    """, (product_id,))
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        abort(404)

    # Prefer S3 key, fall back to legacy absolute URL
    idx = {"sds": 0, "label": 1, "barcode": 2}[kind]
    handle = row[idx]
    if not handle:
        legacy = [row[3], row[4], row[5]][idx]
        if not legacy:
            abort(404)
        return redirect(legacy)

    # Already a full URL?
    if isinstance(handle, str) and handle.startswith(("http://", "https://")):
        return redirect(handle)

    # Support plain "key" or "s3://bucket/key"
    bucket = SDS_BUCKET
    key = handle
    if isinstance(handle, str) and handle.startswith("s3://"):
        from urllib.parse import urlparse
        u = urlparse(handle)
        bucket = u.netloc or SDS_BUCKET
        key = u.path.lstrip("/")

    ext = (key.rsplit(".", 1)[-1] or "").lower()
    params = {"Bucket": bucket, "Key": key}
    if ext == "pdf":
        params["ResponseContentType"] = "application/pdf"
        params["ResponseContentDisposition"] = f'inline; filename="{kind}.pdf"'
    elif ext == "png":
        params["ResponseContentType"] = "image/png"
    elif ext in ("jpg", "jpeg"):
        params["ResponseContentType"] = "image/jpeg"

    try:
        url = s3.generate_presigned_url("get_object", Params=params, ExpiresIn=300)
    except Exception:
        abort(404)
    return redirect(url)

@app.route('/static/uploads/<path:filename>')
@login_required
@role_required('ADMIN')
def uploaded_file(filename):
    return send_from_directory('static/uploads', filename)

@app.route('/edit-sds', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
def edit_sds():
    # GET: render form
    if request.method == 'GET':
        conn = get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT id, name, epa_number FROM products ORDER BY name;")
        products = cur.fetchall()
        cur.close(); conn.close()
        return render_template('edit_sds.html', products=products)

    # POST: process upload/update
    product_id_raw = request.form.get('product_id', '').strip()
    if not product_id_raw.isdigit():
        flash("Please select a product.", "danger")
        return redirect(url_for('edit_sds'))

    product_id = int(product_id_raw)
    epa_number = (request.form.get('epa_number') or "").strip()

    sds_file     = request.files.get('sds_pdf')
    label_file   = request.files.get('label_pdf')
    barcode_file = request.files.get('barcode_img')

    # nothing to do? don't 400 — just flash and return
    if not any([
        epa_number,
        (sds_file and sds_file.filename),
        (label_file and label_file.filename),
        (barcode_file and barcode_file.filename),
    ]):
        flash("Nothing to update. Choose a file or enter EPA #.", "warning")
        return redirect(url_for('edit_sds'))

    conn = get_db_connection(); cur = conn.cursor()
    saved = []
    try:
        if epa_number:
            cur.execute("UPDATE products SET epa_number=%s WHERE id=%s", (epa_number, product_id))
            saved.append("EPA #")

        if sds_file and sds_file.filename:
            key = _upload_file_to_s3(sds_file, product_id, "sds")
            _update_product_key(product_id, "sds", key)
            saved.append("SDS")

        if label_file and label_file.filename:
            key = _upload_file_to_s3(label_file, product_id, "label")
            _update_product_key(product_id, "label", key)
            saved.append("Label")

        if barcode_file and barcode_file.filename:
            key = _upload_file_to_s3(barcode_file, product_id, "barcode")
            _update_product_key(product_id, "barcode", key)
            saved.append("Barcode")

        conn.commit()
        flash(f"Saved: {', '.join(saved)}", "success")

    except Exception as e:
        conn.rollback()
        app.logger.exception("SDS/Label upload failed")
        flash(f"Upload failed: {e}", "danger")
    finally:
        cur.close(); conn.close()

    return redirect(url_for('edit_sds'))

@app.route('/corrections', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
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
@login_required
@role_required('ADMIN')
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
        selected_tech = selected_tech.strip()
        base_query += """
            AND (
                (s.technician ~ '^\d+$' AND t.name = %s)
                OR
                (s.technician !~ '^\d+$' AND s.technician = %s)
            )
        """
        params.extend([selected_tech, selected_tech])

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
        selected_tech = selected_tech.strip()
        summary_query += """
            AND (
                (s.technician ~ '^\d+$' AND t.name = %s)
                OR
                (s.technician !~ '^\d+$' AND s.technician = %s)
            )
        """
        summary_params.extend([selected_tech, selected_tech])

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
@login_required
@role_required('ADMIN')
def settings():
    technicians = get_all_technicians()
    return render_template("settings.html", technicians=technicians)

@app.route("/add-technician", methods=["POST"])
@login_required
@role_required('ADMIN')
def add_technician_route():
    name = request.form.get("tech_name")
    if name:
        add_technician(name.strip())
    return redirect("/")

@app.route("/remove-technician", methods=["POST"])
@login_required
@role_required('ADMIN')
def remove_technician_route():
    name = request.form.get("tech_name")
    if name:
        remove_technician(name.strip())
    return redirect("/")

@app.route('/static/manifest.json')
@login_required
@role_required('ADMIN')
def manifest():
    return send_from_directory('static', 'manifest.json', mimetype='application/manifest+json')

@app.route("/print-report")
@login_required
@role_required('ADMIN')
def print_report():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM products ORDER BY category, name")
    products = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("print_report.html", products=products, now=datetime.now())

@app.route('/upload-invoice', methods=['GET', 'POST'])
@login_required
@role_required('ADMIN')
def upload_invoice():
    if request.method == 'POST':
        file = request.files.get('pdf')
        if not file or not file.filename.lower().endswith('.pdf'):
            return "Invalid file format", 400

        filename = secure_filename(file.filename)
        filepath = os.path.join('/tmp', filename)
        file.save(filepath)

        # optional safety switch
        dry_run = str(request.args.get("dry_run", "0")).lower() in ("1","true","yes")

        conn = get_db_connection()
        cur = conn.cursor()

        # Cast cost_per_unit to numeric so psycopg2 returns Decimal (not float)
        cur.execute("""
            SELECT id, name, cost_per_unit::numeric, COALESCE(siteone_sku,'')
            FROM products
        """)
        products = cur.fetchall()
        names = [p[1] for p in products]

        # exact SKU map
        by_sku = {}
        for i, (pid, pname, pcost, psku) in enumerate(products):
            if psku:
                by_sku[norm_id(psku)] = i

        updates, debug_log = [], []
        matched_count = updated_count = skipped_count = 0

        MIN_ABS_DELTA = Decimal("0.01")   # ≥ 1¢
        MIN_PCT_DELTA = Decimal("0.005")  # ≥ 0.5%

        try:
            parsed_rows = list(parse_pdf_lines(filepath))
            rows = merge_wrapped_rows(parsed_rows) if parsed_rows else []

            if not rows:
                updates.append("⚠️ No usable tables found in the PDF (try OCR if scanned).")

            for line in rows:
                sku_raw = (line["sku"] or "").strip()
                sku_norm = norm_id(sku_raw)
                name = (line["name"] or "").strip()
                unit_price = to_dec(line["unit_price"])  # ensure Decimal

                if not name:
                    skipped_count += 1
                    updates.append(f"🔴 Skipped: empty name (sku: {sku_raw or '—'})")
                    continue
                if unit_price is None:
                    skipped_count += 1
                    up_raw = line.get("unit_price_raw") or line.get("amount_raw")
                    updates.append(f"🔴 Skipped: no unit price for '{name}' (raw: {up_raw})")
                    continue

                # 1) exact SKU
                idx = by_sku.get(sku_norm) if sku_norm else None
                if idx is not None:
                    debug_log.append(f"🔎 Exact SKU match: '{products[idx][1]}' ← '{sku_raw}'")

                # 2) fuzzy by name
                if idx is None:
                    match = process.extractOne(name, names, scorer=fuzz.token_set_ratio)
                    if match:
                        best_name, score, idx = match
                        debug_log.append(f"🤖 Fuzzy: '{name}' → '{best_name}' ({score}%)")
                        if score < 70:
                            idx = None

                if idx is None:
                    skipped_count += 1
                    updates.append(f"🔴 No match: '{name}' (sku: {sku_raw or '—'})")
                    continue

                product_id, actual_name, old_price_db, _sku = products[idx]
                old_price = to_dec(old_price_db)

                # history
                if not dry_run:
                    cur.execute("INSERT INTO price_history (product_id, price) VALUES (%s, %s)",
                                (product_id, unit_price))

                # update if meaningful delta
                delta = (unit_price - old_price).copy_abs()
                pct = (delta / old_price) if old_price > 0 else Decimal("1")
                if delta >= MIN_ABS_DELTA and pct >= MIN_PCT_DELTA:
                    if not dry_run:
                        cur.execute("UPDATE products SET cost_per_unit = %s WHERE id = %s",
                                    (unit_price, product_id))
                    matched_count += 1
                    updated_count += 1
                    updates.append(f"🟢 [{actual_name}] {fmt2(old_price)} → {fmt2(unit_price)}")
                else:
                    matched_count += 1
                    updates.append(f"⚪ [{actual_name}] no meaningful change ({fmt2(unit_price)})")

            if dry_run:
                conn.rollback()
                updates.insert(0, "🧪 Dry-run mode: no DB changes saved.")
            else:
                conn.commit()

        except Exception as e:
            conn.rollback()
            updates.append(f"💥 Error: {e}")
        finally:
            cur.close(); conn.close()

        summary = f"📊 Summary: {matched_count} matched, {updated_count} updated, {skipped_count} skipped."
        updates.insert(0, summary)

        debug = request.args.get('debug') == 'true'
        return render_template("upload_result.html",
                               updates=updates,
                               debug_log=debug_log if debug else [])

    # GET
    return render_template("upload_invoice.html")

@app.route('/update-production', methods=['POST'])
@login_required
@role_required('ADMIN')
def update_production():
    technician_id = int(request.form['technician_id'])
    month = request.form['month']
    production = float(request.form['production'])

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO tech_production (technician_id, month, production)
        VALUES (%s, %s, %s)
        ON CONFLICT (technician_id, month)
        DO UPDATE SET production = EXCLUDED.production
    """, (technician_id, month, production))
    conn.commit()
    conn.close()
    return redirect('/inventory-analytics')

@app.route('/inventory-analytics')
@login_required
@role_required('ADMIN')
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

    # 🧪 Get all product names for dropdown
    cur.execute("SELECT id, name FROM products ORDER BY name ASC")
    all_products = cur.fetchall()

    # 🧑‍🔧 Get all technicians for dropdown/form
    cur.execute("SELECT id, name FROM technicians ORDER BY name")
    technicians = cur.fetchall()

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

    # 4️⃣ Tech Chemical % vs Production
    # -- Load production data
    cur.execute("""
        SELECT tp.technician_id, t.name, tp.month, tp.production
        FROM tech_production tp
        JOIN technicians t ON tp.technician_id = t.id
    """)
    productions = cur.fetchall()
    production_map = {(p[0], p[2]): {"tech_name": p[1], "production": float(p[3])} for p in productions}

    # -- Load chemical usage from scan_logs
    cur.execute("""
        SELECT 
            technician,
            TO_CHAR(timestamp::timestamp, 'YYYY-MM') AS month,
            SUM(unit_cost)
        FROM scan_logs
        WHERE action = 'out'
        GROUP BY technician, TO_CHAR(timestamp::timestamp, 'YYYY-MM')
    """)
    scan_costs = cur.fetchall()

    tech_chemical_table = []
    for row in scan_costs:
        tech_id_raw, month, chem_used = row
        try:
            tech_id = int(tech_id_raw)
        except:
            continue  # skip entries where technician isn't an integer ID

        key = (tech_id, month)
        if key in production_map:
            production = production_map[key]["production"]
            tech_name = production_map[key]["tech_name"]
            percent = (float(chem_used) / float(production) * 100) if production > 0 else 0

            tech_chemical_table.append({
                "tech_name": tech_name,
                "month": month,
                "production": production,
                "chemical_used": chem_used,
                "percent_used": percent
            })

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
        lawn_values=lawn_values or [],
        technicians=technicians,
        tech_chemical_table=tech_chemical_table
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
    
