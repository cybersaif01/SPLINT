import time
import threading
import win32evtlog
import win32evtlogutil
import win32con
import re
import requests
from rules_windows import rules_windows
from datetime import datetime, timezone

# URL of your admin panel API
API_URL = "https://localhost:5000/api/report"
SYSTEM_ID = "WINDOWS_HOST_01"

# =====================================================================
def report_activity(payload):
    """
    Send the alert to the admin panel API.
    """
    try:
        requests.post(API_URL, json=payload, verify=False)
    except Exception as e:
        print(f"[Reporter] Failed to send alert: {e}")

# =====================================================================
def check_event_against_rules(event_msg):
    """
    Matches a Windows Event Log message against rules_windows and reports alerts.
    """
    for rule in rules_windows:
        pattern = rule.get("pattern")
        if pattern and re.search(pattern, event_msg):
            alert_payload = {
                "type": "alert",
                "mitre_id": rule.get("mitre_id", ""),
                "name": rule.get("name"),
                "severity": rule.get("severity"),
                "description": rule.get("description"),
                "user": "N/A",
                "ip": "localhost",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "system": SYSTEM_ID
            }
            print(f"[ALERT] {rule.get('name')} - Severity: {rule.get('severity')}")
            report_activity(alert_payload)

# =====================================================================
def windows_event_monitor(log_type="Security"):
    """
    Streams Windows Event Logs in real-time and checks them against rules_windows.
    """
    server = "localhost"
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        print(f"[Windows Monitor] Streaming {log_type} logs... Total records: {total}")

        seen_record_ids = set()
        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                for event in events:
                    if event.RecordNumber in seen_record_ids:
                        continue
                    seen_record_ids.add(event.RecordNumber)
                    event_msg = win32evtlogutil.SafeFormatMessage(event, log_type)
                    check_event_against_rules(event_msg)
            time.sleep(1)
    except Exception as e:
        print(f"[Windows Monitor] Error: {e}")

def tail_event_logs():
    import win32evtlog

    server = 'localhost'  # Always localhost because logs are centralized
    log_type = 'ForwardedEvents'

    hand = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                yield {
                    "system": event.ComputerName,
                    "event_id": event.EventID,
                    "source": event.SourceName,
                    "time": event.TimeGenerated.isoformat(),
                    "message": str(event.StringInserts)
                }


# =====================================================================
def start_windows_monitor():
    monitor_thread = threading.Thread(target=windows_event_monitor, daemon=True)
    monitor_thread.start()
    print("[Windows Monitor] Monitoring started.")

if __name__ == "__main__":
    start_windows_monitor()
    while True: time.sleep(1)
