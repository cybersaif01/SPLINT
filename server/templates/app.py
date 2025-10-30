from flask import Flask, jsonify, render_template
from functools import wraps

import os
import psycopg2

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "db"),  # service name from docker-compose.yml
        database=os.getenv("POSTGRES_DB", "splintdb"),
        user=os.getenv("POSTGRES_USER", "splint"),
        password=os.getenv("POSTGRES_PASSWORD", "splintpassword2025")
    )


app = Flask(__name__)

# Mock admin token check (replace with real auth)
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

# Example compliance definitions (expand with real details)
COMPLIANCE_DEFINITIONS = {
    "ISO27001": {
        "A.9.2.3": {
            "title": "Management of privileged access rights",
            "description": "The allocation and use of privileged access rights should be restricted and controlled."
        },
        "A.12.4.1": {
            "title": "Event logging",
            "description": "Event logs recording user activities, exceptions, faults, and information security events shall be produced, kept and regularly reviewed."
        }
    },
    "SEBI": {
        "Annex A: 6.1.3": {
            "title": "User session management",
            "description": "Controls to ensure secure user session initiation, monitoring, and termination."
        },
        "Annex A: 4.1.1": {
            "title": "Access control policy",
            "description": "Policy to ensure access rights are aligned with business requirements and security obligations."
        }
    }
}

@app.route('/api/compliance/control/<framework>/<control_id>', methods=['GET'])
@require_admin
def get_control_details(framework, control_id):
    framework = framework.upper()
    definitions = COMPLIANCE_DEFINITIONS.get(framework, {})
    details = definitions.get(control_id)

    if not details:
        return jsonify({"error": "Control not found"}), 404

    return jsonify({
        "control_id": control_id,
        "framework": framework,
        "details": details
    })


# ✅ New endpoint for dashboard summary cards
@app.route('/api/stats', methods=['GET'])
def stats():
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            # total alerts
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            # high severity alerts
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'high'")
            high_severity_alerts = cursor.fetchone()[0]

            # systems online / total devices
            cursor.execute("SELECT COUNT(*) FROM devices")
            total_devices = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'")
            online_devices = cursor.fetchone()[0]

    return jsonify({
        "total_alerts": total_alerts,
        "high_severity_alerts": high_severity_alerts,
        "online_devices": online_devices,
        "total_devices": total_devices
    })


# ✅ Fix severity stats endpoint so frontend chart works
@app.route('/api/alerts/by_severity', methods=['GET'])
def alerts_by_severity():
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT severity, COUNT(*) 
                FROM alerts 
                GROUP BY severity
            """)
            rows = cursor.fetchall()

    stats = {"info": 0, "low": 0, "medium": 0, "high": 0}
    for severity, count in rows:
        stats[severity.lower()] = count

    return jsonify(stats)


# Routes for pages
@app.route('/compliance')
def compliance_page():
    return render_template('compliance.html')


if __name__ == '__main__':
    app.run(debug=True)
