import eventlet
eventlet.monkey_patch()

import sys
import os
import json
import psycopg2
import psycopg2.extras
import csv
import io
from datetime import datetime, timedelta, timezone as UTC
from functools import wraps
import jwt
import requests
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit

import threading
import time


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

app = Flask(__name__)
DATABASE_URL = config.get_config("DATABASE_URL")
SECRET_KEY = config.get_config("SECRET_KEY")
ALGORITHM = config.get_config("ALGORITHM", "HS256")
AUTH_SERVICE_URL = config.get_config("AUTH_URL")

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

COMPLIANCE_MAP = {
    "SSH - Successful Login": {"ISO 27001": "A.12.4.1", "SEBI": "Annex A: 6.1.2"},
    "SSH - Failed Login": {"ISO 27001": "A.12.4.1", "SEBI": "Annex A: 6.1.2"},
    "Brute Force Threshold Exceeded": {"ISO 27001": "A.12.1.2", "SEBI": "Annex A: 6.2.3"},
    "Sudo Command Execution": {"ISO 27001": "A.9.4.4", "SEBI": "Annex A: 6.1.3"},
    "User Session Opened (su)": {"ISO 27001": "A.9.2.3", "SEBI": "Annex A: 6.1.3"},
    "USB Device Plugged In": {"ISO 27001": "A.7.10.1", "SEBI": "Annex A: 8.2.1"},
    "SOAR: IP Blocked by Firewall": {"ISO 27001": "A.12.6.1", "SEBI": "Annex A: 10.2.1"},
    "Agent Login": {"ISO 27001": "A.12.4.1", "SEBI": "Annex A: 4.1.1"},
    "Threat Intel Match: Malicious IP": {"ISO 27001": "A.12.6.1", "SEBI": "Annex A: 10.1.1"},
}

COMPLIANCE_DEFINITIONS = {
    "ISO 27001": {
        "A.12.4.1": "Event Logging: Produce, keep, and regularly review event logs recording user activities, exceptions, faults, and information security events.",
        "A.12.1.2": "Protection against Malware: Implement detection, prevention, and recovery controls to protect against malware, combined with user awareness.",
        "A.9.4.4": "Use of Privileged Utility Programs: Restrict and tightly control the use of utility programs that might be capable of overriding system and application controls.",
        "A.9.2.3": "User Session Management: Ensure secure management of user sessions.",
        "A.7.10.1": "Information Handling Procedures: Establish and implement procedures for the handling of information to protect it from unauthorized disclosure or misuse.",
        "A.12.6.1": "Management of Technical Vulnerabilities: Obtain timely information about technical vulnerabilities of information systems being used, evaluate the organization's exposure to such vulnerabilities, and take appropriate measures to address the associated risk."
    },
    "SEBI": {
        "Annex A: 6.1.2": "User Access Management: Ensure that only authorized users have access to information systems and that their access is restricted based on business requirements.",
        "Annex A: 6.2.3": "Password Management System: Implement a secure password management system to ensure the quality of passwords.",
        "Annex A: 6.1.3": "Privileged Access Management: Control and monitor access to privileged user accounts.",
        "Annex A: 8.2.1": "Removable Media: Manage removable media to prevent unauthorized access, use, or data leakage.",
        "Annex A: 10.2.1": "Network Controls: Implement controls to secure the network infrastructure, including firewalls and intrusion detection/prevention systems.",
        "Annex A: 4.1.1": "Information Security Policies: Management shall define and approve a policy for information security.",
        "Annex A: 10.1.1": "Threat Intelligence: Subscribe to and utilize threat intelligence feeds to stay informed about the latest cyber threats and vulnerabilities."
    }
}

# ---------------- DATABASE ----------------
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                system TEXT,
                timestamp TEXT,
                received_at TEXT,
                type TEXT,
                severity TEXT,
                name TEXT,
                description TEXT,
                "user" TEXT,
                ip TEXT,
                processed BOOLEAN DEFAULT NULL
            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS devices (
                system_id TEXT PRIMARY KEY,
                last_seen TEXT,
                ip_address TEXT
            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
                username TEXT PRIMARY KEY,
                employee_id TEXT,
                role TEXT,
                last_seen_ip TEXT,
                last_login_utc TEXT,
                system_id TEXT
            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL,
                "user" TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT
            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS firewall_blocks (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL DEFAULT now(),
                system_id TEXT,
                blocked_ip TEXT,
                UNIQUE(system_id, blocked_ip)
            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS systems (
                system_id TEXT PRIMARY KEY,
                ip TEXT,
                os TEXT,
                last_seen TEXT,
                registered_by TEXT
            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                role TEXT,
                last_seen_ip TEXT,
                last_login TIMESTAMP
            )''')
        conn.commit()

init_db()

# ---------------- LOGGING & AUTH ----------------
def log_admin_action(user, action, details=""):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO audit_log (timestamp, \"user\", action, details) VALUES (%s, %s, %s, %s)",
                (datetime.now(UTC).isoformat(), user, action, details)
            )

def role_required(roles: list):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            token = auth_header.split(" ")[1] if auth_header and auth_header.startswith('Bearer ') else None
            if not token: 
                return jsonify({'message': 'Authentication token is missing!'}), 401
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                user_role = data.get('role')
                if user_role not in roles: 
                    return jsonify({'message': 'Access denied for this role.'}), 403
                kwargs['user_data'] = data
                log_admin_action(data.get('sub'), f"API_ACCESS:{f.__name__}", f"Role: {user_role}")
            except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                return jsonify({'message': 'Invalid or expired token!'}), 401
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---------------- USB BLOCKING ----------------
@app.route('/api/usb/block', methods=['POST'])
@role_required(['admin'])
def block_usb_on_system(user_data=None):
    data = request.json
    system_id = data.get("system_id")
    if not system_id:
        return jsonify({"error": "system_id is required"}), 400

    # Find the system's last known IP
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT ip_address FROM devices WHERE system_id = %s", (system_id,))
            row = cursor.fetchone()
            if not row:
                return jsonify({"error": "System not found"}), 404
            system_ip = row[0]

    # Send the block command to the agent on that system
    try:
        response = requests.post(f"http://{system_ip}:9000/block_usb", timeout=5)
        if response.status_code == 200:
            return jsonify({"status": "success", "message": f"USB block sent to {system_id}"})
        else:
            return jsonify({"status": "error", "message": f"Failed to block USB on {system_id}"}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Automatic USB blocking thread
def usb_auto_block_job():
    while True:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT system, id FROM alerts WHERE name='USB Device Plugged In' AND processed IS NULL")
                alerts = cursor.fetchall()
                for system_id, alert_id in alerts:
                    try:
                        requests.post(f"http://localhost:5000/api/usb/block", json={"system_id": system_id})
                        cursor.execute("UPDATE alerts SET processed = TRUE WHERE id = %s", (alert_id,))
                    except Exception as e:
                        print(f"[USB BLOCK] Failed to block USB on {system_id}: {e}")
            conn.commit()
        time.sleep(10)

threading.Thread(target=usb_auto_block_job, daemon=True).start()

# ---------------- REST OF EXISTING API ----------------
@app.route('/api/report', methods=['POST'])
def report_event():
    data = request.json
    if not data: return jsonify({"status": "error"}), 400
    received_time = datetime.now(UTC).isoformat()
    system_id = data.get("system", request.remote_addr)
    event_type = data.get("type")
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute('INSERT INTO devices (system_id, last_seen, ip_address) VALUES (%s, %s, %s) ON CONFLICT (system_id) DO UPDATE SET last_seen = EXCLUDED.last_seen, ip_address = EXCLUDED.ip_address', (system_id, received_time, request.remote_addr))
            if event_type == "alert":
                cursor.execute('INSERT INTO alerts (system, timestamp, received_at, type, severity, name, description, "user", ip) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                               (system_id, data.get("timestamp"), received_time, data.get("type"), data.get("severity"), data.get("name"), data.get("description"), data.get("user"), data.get("ip")))
                socketio.emit('new_alert', {
                    "system": system_id,
                    "timestamp": data.get("timestamp"),
                    "received_at": received_time,
                    "type": data.get("type"),
                    "severity": data.get("severity"),
                    "name": data.get("name"),
                    "description": data.get("description"),
                    "user": data.get("user"),
                    "ip": data.get("ip")
                }, broadcast=True)
            elif event_type == "login":
                cursor.execute('INSERT INTO user_sessions (username, employee_id, role, last_seen_ip, last_login_utc, system_id) VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (username) DO UPDATE SET last_seen_ip = EXCLUDED.last_seen_ip, last_login_utc = EXCLUDED.last_login_utc, system_id = EXCLUDED.system_id',
                               (data.get("user"), data.get("employee_id"), data.get("role"), request.remote_addr, received_time, system_id))
    return jsonify({"status": "ok"}), 200

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    try:
        response = requests.post(f"{AUTH_SERVICE_URL}/token", data=request.form, headers={"Content-Type": "application/x-www-form-urlencoded"}, verify=False)
        try: response_data = response.json()
        except json.JSONDecodeError: return jsonify({"message": "Auth service returned an invalid response."}), 502
        if response.status_code == 200:
            token_data = jwt.decode(response_data['access_token'], SECRET_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})
            if token_data.get('role') in ['admin', 'analyst']: log_admin_action(token_data.get('sub'), "LOGIN_SUCCESS")
        return jsonify(response_data), response.status_code
    except requests.exceptions.RequestException: return jsonify({"message": "Auth service is unreachable"}), 503

@app.route('/api/logs')
@role_required(roles=['admin', 'analyst'])
def get_logs(user_data=None):
    search_term = request.args.get('search', '')
    severity_filter = request.args.get('severity', '')
    query = "SELECT * FROM alerts"
    where_clauses, params = [], []
    if search_term:
        where_clauses.append("(name ILIKE %s OR description ILIKE %s OR system ILIKE %s OR ip ILIKE %s)")
        search_like = f"%{search_term}%"
        params.extend([search_like, search_like, search_like, search_like])
    if severity_filter and severity_filter.lower() != 'all':
        where_clauses.append("severity = %s")
        params.append(severity_filter)
    if where_clauses: query += " WHERE " + " AND ".join(where_clauses)
    query += " ORDER BY id DESC LIMIT 100"
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute(query, tuple(params))
            logs = cursor.fetchall()
    return jsonify(logs)

@app.route('/api/compliance/report')
@role_required(roles=['admin', 'analyst'])
def get_compliance_report(user_data=None):
    report_data = []
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT name, description, severity, received_at FROM alerts ORDER BY id DESC")
            alerts = cursor.fetchall()
    for alert in alerts:
        controls = COMPLIANCE_MAP.get(alert['name'], {"ISO 27001": "N/A", "SEBI": "N/A"})
        report_data.append({**alert, "controls": controls})
    return jsonify(report_data)

@app.route('/api/compliance/info/<standard>/<path:control_id>')
@role_required(roles=['admin', 'analyst'])
def get_compliance_info(standard, control_id, user_data=None):
    definition = COMPLIANCE_DEFINITIONS.get(standard, {}).get(control_id, "No definition found for this control.")
    return jsonify({"standard": standard, "control_id": control_id, "definition": definition})

@app.route('/api/compliance/report/download')
@role_required(roles=['admin', 'analyst'])
def download_compliance_report(user_data=None):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("SELECT name, description, severity, received_at FROM alerts ORDER BY id DESC")
            alerts = cursor.fetchall()
    output = io.StringIO()
    if not alerts:
        output.write("No alerts to report.")
    else:
        fieldnames = ['Timestamp (UTC)', 'Alert Name', 'Severity', 'ISO 27001 Control', 'SEBI Control']
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            controls = COMPLIANCE_MAP.get(alert['name'], {"ISO 27001": "N/A", "SEBI": "N/A"})
            writer.writerow({
                'Timestamp (UTC)': alert['received_at'],
                'Alert Name': alert['name'],
                'Severity': alert['severity'],
                'ISO 27001 Control': controls['ISO 27001'],
                'SEBI Control': controls['SEBI']
            })
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=splint_compliance_report.csv"}
    )

@app.route('/api/devices', methods=['GET'])
@role_required(["admin"])  
def get_devices(user_data=None):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
            cursor.execute("SELECT system_id, ip_address, last_seen FROM devices ORDER BY last_seen DESC")
            rows = cursor.fetchall()
            devices = []
            for row in rows:
                devices.append({
                    "system": row["system_id"],
                    "ip": row["ip_address"],
                    "status": "Online" if (datetime.now(UTC) - datetime.fromisoformat(row["last_seen"])) < timedelta(minutes=5) else "Offline",
                    "last_seen": row["last_seen"]
                })
    return jsonify(devices)

@app.route('/api/alerts/summary', methods=['GET'])
@role_required(["admin", "analyst"])
def alerts_summary(user_data=None):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'high'")
            high_alerts = cursor.fetchone()[0]
            cursor.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.execute("SELECT COUNT(*) FROM devices")
            total_systems = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM devices WHERE last_seen >= %s",
                           ((datetime.now(UTC) - timedelta(minutes=5)).isoformat(),))
            online_systems = cursor.fetchone()[0]
    return jsonify({
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "severity_counts": severity_counts,
        "systems_online": online_systems,
        "systems_total": total_systems
    })

@app.route('/api/risk_summary', methods=['GET'])
@role_required(["admin"])
def risk_summary(user_data=None):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT system AS system_id, COUNT(*) AS risk_score
                FROM alerts
                GROUP BY system
                ORDER BY risk_score DESC
                LIMIT 10
            """)
            rows = cursor.fetchall()
            risk_data = {row[0]: row[1] for row in rows}
    return jsonify(risk_data)

@app.route('/api/firewall/blocks', methods=['GET'])
@role_required(["admin"])
def firewall_blocks(user_data=None):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, blocked_ip FROM firewall_blocks ORDER BY id DESC")
            rows = cursor.fetchall()
            blocks = [{"id": row[0], "ip": row[1]} for row in rows]
    return jsonify(blocks)

@app.route('/api/firewall/block', methods=['POST'])
@role_required(["admin"])
def firewall_block_add(user_data=None):
    data = request.json
    ip_address = data.get("ip")
    if not ip_address: return jsonify({"error": "IP address is required"}), 400
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO firewall_blocks (blocked_ip) VALUES (%s) RETURNING id", (ip_address,))
            block_id = cursor.fetchone()[0]
            conn.commit()
    return jsonify({"id": block_id, "ip": ip_address})

@app.route('/api/firewall/unblock/<int:block_id>', methods=['DELETE'])
@role_required(["admin"])
def firewall_block_remove(block_id, user_data=None):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM firewall_blocks WHERE id = %s RETURNING id", (block_id,))
            deleted = cursor.fetchone()
            conn.commit()
    if not deleted: return jsonify({"error": "Block not found"}), 404
    return jsonify({"message": "Firewall block removed", "id": block_id})

def proxy_to_auth_service(endpoint, method='GET', json_data=None):
    try:
        headers = {'Authorization': request.headers.get('Authorization')}
        if method.upper() == 'GET':
            response = requests.get(endpoint, headers=headers, verify=False, timeout=5)
        else:
            response = requests.post(endpoint, json=json_data, headers=headers, verify=False, timeout=5)
        try: return jsonify(response.json()), response.status_code
        except json.JSONDecodeError: return jsonify({"status": "error", "message": "Auth service returned a non-JSON response.", "auth_service_status": response.status_code, "auth_service_response": response.text[:500]}), 502
    except requests.exceptions.RequestException as e: return jsonify({"status": "error", "message": f"Could not connect to auth service: {e}"}), 503

@app.route('/api/users', methods=['GET'])
@role_required(["admin"])
def get_users(user_data=None):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, role, last_seen_ip, last_login FROM users ORDER BY username ASC")
            rows = cursor.fetchall()
            users = [{"username": row[0], "role": row[1], "last_seen_ip": row[2], "last_login_utc": row[3].isoformat() if row[3] else None} for row in rows]
    return jsonify(users)
# ---------------- WEB PAGES ----------------
@app.route('/')
def dashboard(): return render_template('dashboard.html')
@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/devices')
def devices_page():
    return render_template('devices.html')

@app.route('/users')
def users_page():
    return render_template('users.html')

@app.route('/manage-users')
def manage_users_page():
    return render_template('manage_users.html')

@app.route('/compliance')
def compliance_page():
    return render_template('compliance.html')

@app.route('/risk')
def risk_page():
    return render_template('risk.html')

@app.route('/firewall')
def firewall_page():
    return render_template('firewall.html')

# ---------------- MAIN ----------------
if __name__ == '__main__':
    init_db()
    ssl_context = ('../cert.pem', '../key.pem')
    socketio.run(app, debug=True, port=5000, ssl_context=ssl_context)
