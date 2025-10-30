import os
import sys
import time
import threading
import re
import socket
import psutil
import platform
import pyperclip
import requests
from datetime import datetime, timezone
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---
API_URL = "https://localhost:5000/api/report"  # SPLINT endpoint
SYSTEM_ID = platform.node()
CHECK_INTERVAL = 10  # seconds
WATCH_DIRS = ["/home/user/sensitive_data", "C:\\SensitiveData"]  # adjust for your OS
MAIL_DIRS = ["/home/user/Mail/Attachments", "C:\\Users\\User\\MailAttachments"]
UNAUTHORIZED_APPS = ["dropbox", "nextcloud", "onedrive", "skype", "teams"]
CLIPBOARD_PATTERNS = [r"\b\d{3}-\d{2}-\d{4}\b", r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"]  # SSN, email

# --- Helper Functions ---
def send_alert(name, severity, description, user=None, ip=None):
    data = {
        "system": SYSTEM_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "alert",
        "severity": severity,
        "name": name,
        "description": description,
        "user": user or os.getlogin(),
        "ip": ip or get_local_ip()
    }
    try:
        requests.post(API_URL, json=data, verify=False, timeout=5)
    except Exception as e:
        print(f"[!] Failed to send alert: {e}")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"

# --- File Copy / Modification Monitoring ---
class SensitiveFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory: return
        send_alert("Sensitive File Copied/Created", "high", f"File: {event.src_path}")

def monitor_files():
    observers = []
    for dir_path in WATCH_DIRS:
        if os.path.exists(dir_path):
            handler = SensitiveFileHandler()
            observer = Observer()
            observer.schedule(handler, dir_path, recursive=True)
            observer.start()
            observers.append(observer)
    try:
        while True:
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        for obs in observers: obs.stop()
        for obs in observers: obs.join()

# --- USB / Removable Drive Detection ---
def monitor_usb():
    if platform.system() == "Windows":
        from win32file import GetLogicalDriveStrings, GetDriveType, DRIVE_REMOVABLE
        known_drives = set()
        while True:
            drives = GetLogicalDriveStrings().split('\000')[:-1]
            current_drives = set(d for d in drives if GetDriveType(d) == DRIVE_REMOVABLE)
            added = current_drives - known_drives
            removed = known_drives - current_drives
            for d in added: send_alert("USB Connected", "medium", f"Drive {d} connected")
            for d in removed: send_alert("USB Removed", "medium", f"Drive {d} removed")
            known_drives = current_drives
            time.sleep(CHECK_INTERVAL)
    else:  # Linux
        import pyudev
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem='block', device_type='disk')
        for device in iter(monitor.poll, None):
            if device.action == 'add':
                send_alert("USB Connected", "medium", f"Device {device.device_node} connected")
            elif device.action == 'remove':
                send_alert("USB Removed", "medium", f"Device {device.device_node} removed")

# --- Clipboard Monitoring ---
def monitor_clipboard():
    last_text = ""
    while True:
        try:
            text = pyperclip.paste()
            if text != last_text:
                for pattern in CLIPBOARD_PATTERNS:
                    if re.search(pattern, text, re.I):
                        send_alert("Sensitive Data Copied to Clipboard", "high", f"Data: {text[:50]}...")
                last_text = text
        except Exception as e:
            pass
        time.sleep(CHECK_INTERVAL)

# --- Network Exfiltration Detection ---
def monitor_network():
    last_bytes = psutil.net_io_counters().bytes_sent
    while True:
        time.sleep(CHECK_INTERVAL)
        current_bytes = psutil.net_io_counters().bytes_sent
        if current_bytes - last_bytes > 10*1024*1024:  # >10 MB in interval
            send_alert("Potential Data Exfiltration", "high", f"Sent {current_bytes - last_bytes} bytes in last {CHECK_INTERVAL}s")
        last_bytes = current_bytes

# --- Unauthorized Application Usage ---
def monitor_apps():
    while True:
        running = [p.name().lower() for p in psutil.process_iter()]
        for app in UNAUTHORIZED_APPS:
            if app.lower() in running:
                send_alert("Unauthorized App Running", "medium", f"Detected: {app}")
        time.sleep(CHECK_INTERVAL)

# --- Main ---
if __name__ == "__main__":
    threads = [
        threading.Thread(target=monitor_files, daemon=True),
        threading.Thread(target=monitor_usb, daemon=True),
        threading.Thread(target=monitor_clipboard, daemon=True),
        threading.Thread(target=monitor_network, daemon=True),
        threading.Thread(target=monitor_apps, daemon=True)
    ]
    for t in threads: t.start()
    print("[*] SPLINT agent running...")
    while True: time.sleep(1)
