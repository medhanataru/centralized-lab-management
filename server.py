"""
server.py - Central server for the Lab Computer Health Monitoring System.

What this program does (in simple words):
  1. Listens on a TCP port and speaks HTTP (using Flask).
  2. Receives health reports (CPU / RAM / disk) from lab computers as JSON.
  3. Checks the data is valid, decides if the computer is HEALTHY or WARNING.
  4. Stores every report in an SQLite database file.
  5. Lets the administrator read reports (admin key needed).
  6. Lets authorised clients download approved sample packages.

Run it:   python server.py
Stop it:  press Ctrl + C

This is an academic prototype. It uses plain HTTP and simple API keys.
It is NOT production-grade security (see the report's limitations section).
"""

import hashlib
import hmac
import json
import os
import re
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory

# ---------------------------------------------------------------------------
# 1. Load configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
PACKAGE_DIR = os.path.join(BASE_DIR, "packages")


def load_config():
    """Read config.json and return it as a Python dictionary."""
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


CONFIG = load_config()
DB_PATH = os.path.join(BASE_DIR, CONFIG["database_file"])

app = Flask(__name__)
# Reject huge request bodies (a health report is only a few hundred bytes).
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB


# ---------------------------------------------------------------------------
# 2. Database helpers (SQLite)
# ---------------------------------------------------------------------------
# SQLite stores the whole database in ONE file (lab_management.db).
# Data stays in that file after the program stops, so reports persist.

def get_db():
    """Open a database connection for the current request (one per request)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row  # lets us read columns by name
    return g.db


@app.teardown_appcontext
def close_db(_error):
    """Flask calls this automatically at the end of every request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the reports table if it does not exist yet."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname     TEXT    NOT NULL,
            source_ip    TEXT    NOT NULL,
            cpu_percent  REAL    NOT NULL,
            ram_percent  REAL    NOT NULL,
            disk_percent REAL    NOT NULL,
            status       TEXT    NOT NULL,
            issues       TEXT    NOT NULL,
            received_at  TEXT    NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_reports_host ON reports (hostname, id)"
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# 3. Authentication (API keys sent in the X-API-Key HTTP header)
# ---------------------------------------------------------------------------

def key_matches(provided, expected):
    """Compare two keys safely (constant-time comparison)."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode(), expected.encode())


def require_key(role):
    """
    Decorator that protects an endpoint.
      role = "client" -> client key OR admin key is accepted
      role = "admin"  -> only the admin key is accepted
    A missing or wrong key gives HTTP 401 (Unauthorized).
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            provided = request.headers.get("X-API-Key", "")
            is_admin = key_matches(provided, CONFIG["admin_api_key"])
            is_client = key_matches(provided, CONFIG["client_api_key"])
            allowed = is_admin if role == "admin" else (is_admin or is_client)
            if not allowed:
                return jsonify({"error": "unauthorized"}), 401
            return func(*args, **kwargs)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# 4. Validation and status logic
# ---------------------------------------------------------------------------
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def is_percentage(value):
    """True if value is a real number between 0 and 100.
    Note: in Python, True/False count as numbers, so we reject them."""
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False
    return 0 <= value <= 100


def validate_report(data):
    """
    Check an incoming report. Returns (ok, error_message).
    Never trust data that arrives over a network.
    """
    if not isinstance(data, dict):
        return False, "report must be a JSON object"

    hostname = data.get("hostname")
    if not isinstance(hostname, str) or not HOSTNAME_PATTERN.match(hostname):
        return False, "hostname missing or invalid (1-64 chars: letters, digits, . _ -)"

    for field in ("cpu_percent", "ram_percent", "disk_percent"):
        if field not in data:
            return False, f"missing field: {field}"
        if not is_percentage(data[field]):
            return False, f"{field} must be a number from 0 to 100"

    return True, ""


def evaluate_status(cpu, ram, disk):
    """
    Compare readings with the thresholds in config.json.
    Returns (status, list_of_issues). The SERVER decides this, not the client.
    """
    limits = CONFIG["thresholds"]
    issues = []
    if cpu >= limits["cpu_percent"]:
        issues.append("HIGH_CPU")
    if ram >= limits["ram_percent"]:
        issues.append("HIGH_RAM")
    if disk >= limits["disk_percent"]:
        issues.append("LOW_DISK_SPACE")
    status = "WARNING" if issues else "HEALTHY"
    return status, issues


def row_to_dict(row):
    """Turn a database row into a dictionary that can be sent as JSON."""
    return {
        "id": row["id"],
        "hostname": row["hostname"],
        "source_ip": row["source_ip"],
        "cpu_percent": row["cpu_percent"],
        "ram_percent": row["ram_percent"],
        "disk_percent": row["disk_percent"],
        "status": row["status"],
        "issues": [i for i in row["issues"].split(",") if i],
        "received_at": row["received_at"],
    }


# ---------------------------------------------------------------------------
# 5. API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """No key needed. Lets anyone check if the server is up."""
    return jsonify({"service": "lab-monitor-server", "status": "up"})


@app.route("/api/report", methods=["POST"])
@require_key("client")
def receive_report():
    """A client sends its health report here (HTTP POST with a JSON body)."""
    data = request.get_json(silent=True)  # None if the body is not valid JSON
    if data is None:
        return jsonify({"error": "body must be valid JSON"}), 400

    ok, message = validate_report(data)
    if not ok:
        return jsonify({"error": message}), 400

    cpu = float(data["cpu_percent"])
    ram = float(data["ram_percent"])
    disk = float(data["disk_percent"])
    status, issues = evaluate_status(cpu, ram, disk)

    # The SERVER sets the timestamp and records where the report came from.
    received_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_ip = request.remote_addr

    db = get_db()
    # "?" placeholders = parameterized query. This prevents SQL injection.
    db.execute(
        """
        INSERT INTO reports
            (hostname, source_ip, cpu_percent, ram_percent, disk_percent,
             status, issues, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (data["hostname"], source_ip, cpu, ram, disk, status,
         ",".join(issues), received_at),
    )
    db.commit()

    print(f"[{received_at}] report from {data['hostname']} ({source_ip}) "
          f"CPU={cpu} RAM={ram} DISK={disk} -> {status} {issues}")

    return jsonify({"result": "stored", "status": status, "issues": issues}), 200


@app.route("/api/reports", methods=["GET"])
@require_key("admin")
def list_reports():
    """Admin only: most recent reports, newest first. ?limit=20 (max 200)."""
    try:
        limit = int(request.args.get("limit", 20))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    limit = max(1, min(limit, 200))

    rows = get_db().execute(
        "SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return jsonify([row_to_dict(r) for r in rows])


@app.route("/api/status", methods=["GET"])
@require_key("admin")
def latest_status():
    """Admin only: the latest report of EACH computer."""
    rows = get_db().execute(
        """
        SELECT r.* FROM reports r
        JOIN (SELECT hostname, MAX(id) AS max_id
              FROM reports GROUP BY hostname) latest
          ON r.id = latest.max_id
        ORDER BY r.hostname
        """
    ).fetchall()
    return jsonify([row_to_dict(r) for r in rows])


def sha256_of_file(path):
    """Calculate the SHA-256 checksum (a fingerprint) of a file."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.route("/api/packages", methods=["GET"])
@require_key("client")
def list_packages():
    """List approved packages with their checksums."""
    result = []
    for name, info in CONFIG["packages"].items():
        path = os.path.join(PACKAGE_DIR, name)
        if os.path.isfile(path):
            result.append({
                "name": name,
                "description": info.get("description", ""),
                "size_bytes": os.path.getsize(path),
                "sha256": sha256_of_file(path),
            })
    return jsonify(result)


@app.route("/api/download/<name>", methods=["GET"])
@require_key("client")
def download_package(name):
    """
    Send an approved package. Only names listed in config.json are allowed,
    so a client cannot ask for other files (this blocks path traversal such
    as ../../secret).
    """
    if name not in CONFIG["packages"]:
        return jsonify({"error": "package not approved"}), 404
    if not os.path.isfile(os.path.join(PACKAGE_DIR, name)):
        return jsonify({"error": "package file missing on server"}), 404
    return send_from_directory(PACKAGE_DIR, name, as_attachment=True)


# ---------------------------------------------------------------------------
# 6. Friendly JSON errors for other mistakes
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "not found"}), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify({"error": "method not allowed"}), 405


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "request too large"}), 413


# ---------------------------------------------------------------------------
# 7. Start the server
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    host = CONFIG["server_host"]
    port = CONFIG["server_port"]
    print(f"Lab server starting on http://{host}:{port}  (Ctrl+C to stop)")
    print(f"Database file: {DB_PATH}")
    # debug=False is important: Flask debug mode can allow remote code execution.
    app.run(host=host, port=port, debug=False)
