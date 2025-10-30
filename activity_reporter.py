import requests
import config
import os
import urllib3

# Suppress the InsecureRequestWarning for self-signed certificates, which is expected in this setup.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get the server URL from the configuration (e.g., https://localhost:5000)
SERVER_REPORT_URL = f"{config.get_config('SERVER_URL')}/api/report"

# Get the system's hostname to uniquely identify this agent
SYSTEM_ID = os.uname().nodename

def report_activity(payload: dict):
    """
    Sends an event payload (like an alert or login) to the central server's 
    /api/report endpoint. It automatically adds the system_id to the payload.
    """
    # Ensure the payload always includes which system it's from
    payload['system'] = SYSTEM_ID

    try:
        # --- CRITICAL FIX: Increased timeout to 15 seconds ---
        # This makes the connection more resilient, especially when the server is starting up.
        response = requests.post(
            SERVER_REPORT_URL, 
            json=payload, 
            verify=False, # Necessary for self-signed certificates
            timeout=15
        )

        # Check for any errors from the server
        if response.status_code != 200:
            print(f"[Activity Reporter] Error: Server responded with status {response.status_code}")
            print(f"[Activity Reporter] Response: {response.text}")

    except requests.exceptions.RequestException as e:
        # This catches network errors like "Connection refused" or timeouts
        print(f"[Activity Reporter] CRITICAL: Could not send report to server at {SERVER_REPORT_URL}")
        print(f"[Activity Reporter]  └── Error: {e}")

