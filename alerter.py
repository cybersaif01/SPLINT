import csv
import os
from datetime import datetime
import requests
import socket


CSV_FILE = "alerts.csv"

def send_alert(rule, user="N/A", ip="N/A", line=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Neat terminal alert
    print("\n" + "┌" + "─" * 50 + "┐")
    print(f"│ ALERT: [{rule['mitre_id']}] {rule['name']} ({rule['severity'].upper()})".ljust(51) + "│")
    print("├" + "─" * 50 + "┤")
    print(f"│ Description : {rule['description']}".ljust(51) + "│")
    print(f"│ User        : {user}".ljust(51) + "│")
    print(f"│ IP Address  : {ip}".ljust(51) + "│")
    print(f"│ Timestamp   : {timestamp}".ljust(51) + "│")
    print(f"│ Log Line    : {line.strip()}".ljust(51) + "│")
    print("└" + "─" * 50 + "┘")

    # CSV Logging
    csv_header = ["Timestamp", "MITRE ID", "Rule Name", "Severity", "User", "IP Address", "Log Line"]
    csv_data = [
        timestamp,
        rule["mitre_id"],
        rule["name"],
        rule["severity"].upper(),
        user.strip(),
        ip.strip(),
        line.strip().replace("\n", " ")
    ]

    file_exists = os.path.isfile(CSV_FILE)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        if not file_exists:
            writer.writerow(csv_header)
        writer.writerow(csv_data)

    # Discord Alert (optional)
    webhook_url = "https://discord.com/api/webhooks/1397290819475607685/YttRMtI1i-gKha_nFVrK2bjBqMmmuQ_vXHO3LLTmBb8WvbQEZYUm1jHNkoPxt0siffXe"  # paste your Discord webhook here
    if webhook_url:
        discord_alert(rule, user, ip, line, timestamp, webhook_url)

def discord_alert(rule, user, ip, line, timestamp, webhook_url):
    message = (
        f"🚨 **[{rule['mitre_id']}] {rule['name']} ({rule['severity'].upper()})**\n"
        f"> **Description:** {rule['description']}\n"
        f"> **User:** `{user}` | **IP:** `{ip}`\n"
        f"> **Time:** {timestamp}\n"
        f"> **Log:** `{line.strip()}`"
    )
    payload = {"content": message}
    try:
        requests.post(webhook_url, json=payload)
    except Exception as e:
        print(f"[!] Failed to send Discord alert: {e}")


def is_online():
    try:
        socket.setdefaulttimeout(2)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except:
        return False

def send_pending_usb_alerts():
    log_file = "usb_events.log"
    if not os.path.exists(log_file):
        return

    if not is_online():
        return

    with open(log_file, "r") as f:
        lines = f.readlines()

    if not lines:
        return

    for line in lines:
        send_alert({
            "name": "Offline USB Detection",
            "description": line.strip(),
            "mitre_id": "T1200",
            "severity": "medium"
        }, user="SYSTEM", ip="127.0.0.1", line="usb_monitor")

    # Clear log file after sending
    with open(log_file, "w") as f:
        pass
