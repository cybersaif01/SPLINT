import socketserver
import re
import requests
import json
from datetime import datetime, UTC

# --- Configuration ---
# The address of your main admin panel server
ADMIN_SERVER_URL = "https://localhost:5000/api/report"
HOST, PORT = "0.0.0.0", 514 # Listen on all network interfaces on port 514

# A simple regex to parse standard syslog messages
# Example: <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
SYSLOG_REGEX = re.compile(r"<(\d+)>([^ ]+ +\d+ +\d{2}:\d{2}:\d{2}) ([^:]+): (.*)")

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """
    This handler is activated once for each syslog message received.
    """
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        
        try:
            message = data.decode('utf-8')
            source_ip = self.client_address[0]
            print(f"[Syslog] Received message from {source_ip}: {message}")

            # --- Create a standardized JSON payload ---
            # We classify this as a generic "log" event for now.
            # A future parsing engine will turn these into specific "alerts".
            payload = {
                "system": source_ip, # The source IP is the "system" for now
                "timestamp": datetime.now(UTC).isoformat(),
                "type": "log", # Generic log type
                "severity": "info", # Default severity
                "name": "Syslog Event",
                "description": message,
                "user": "N/A",
                "ip": source_ip
            }
            
            # --- Forward the processed log to the main server ---
            try:
                # Use verify=False for development with self-signed certs
                requests.post(ADMIN_SERVER_URL, json=payload, timeout=5, verify=False)
            except requests.exceptions.RequestException as e:
                print(f"[Syslog ERROR] Could not forward log to admin server: {e}")

        except UnicodeDecodeError:
            print(f"[Syslog WARN] Received non-UTF8 message from {self.client_address[0]}")
        except Exception as e:
            print(f"[Syslog ERROR] An unexpected error occurred: {e}")


if __name__ == "__main__":
    try:
        print(f"[*] Starting Syslog listener on port {PORT}...")
        # Create a UDP server that listens on port 514
        server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)
        # Start the server. It will run forever until you press Ctrl+C.
        server.serve_forever()
    except PermissionError:
        print("\n[FATAL ERROR] Permission denied to bind to port 514.")
        print("Please run this script with 'sudo'.")
    except Exception as e:
        print(f"\n[FATAL ERROR] Could not start syslog server: {e}")
