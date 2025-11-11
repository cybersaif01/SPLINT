import os
import time
import json
import re
import win32evtlog
import win32evtlogutil
from colorama import Fore, Style, init
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime
from config import get_config

# Initialize colorama
init(autoreset=True)

# Load environment variables
load_dotenv()

# === Supabase Setup ===
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print(Fore.RED + "[x] Supabase credentials not found. Check your .env file!")
    exit(1)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# === Insert Log into Supabase ===
def insert_log(event_id, source, message, username=None):
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_id": event_id,
        "source": source,
        "message": message,
        "username": username or "SYSTEM"
    }
    try:
        res = supabase.table("logs").insert(data).execute()
        if res.data:
            print(Fore.GREEN + f"[+] Log inserted successfully: Event ID {event_id}")
        else:
            print(Fore.RED + f"[x] Failed to insert log: {res}")
    except Exception as e:
        print(Fore.RED + f"[x] Supabase insert failed: {e}")

# === Windows Event Log Monitor ===
def monitor_windows_events():
    print(Fore.CYAN + "[Windows Monitor] Monitoring started successfully.")
    server = "localhost"
    logtype = "Security"

    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        print(Fore.CYAN + f"[Windows Monitor] Streaming '{logtype}' logs... Total: {total}")

        # Keep track of last record to avoid duplicates
        last_record_number = total

        while True:
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, last_record_number)

            if events:
                for event in events:
                    # Only process new logs
                    if event.RecordNumber <= last_record_number:
                        continue

                    last_record_number = event.RecordNumber

                    try:
                        event_msg = win32evtlogutil.SafeFormatMessage(event, logtype)
                    except Exception:
                        event_msg = str(event.StringInserts) or "No message"

                    source = event.SourceName
                    event_id = event.EventID
                    message = event_msg.strip()
                    username = None

                    # Extract username if present
                    user_match = re.search(r"Account Name:\s+([^\s]+)", message)
                    if user_match:
                        username = user_match.group(1)

                    # Show colorful output
                    print(Fore.YELLOW + "\n[ALERT] Windows Event Detected")
                    print(Fore.MAGENTA + f"├── Event ID: {event_id}")
                    print(Fore.CYAN + f"├── Source: {source}")
                    print(Fore.WHITE + f"└── User: {username or 'SYSTEM'}")

                    insert_log(event_id, source, message, username)

            time.sleep(3)  # Poll interval (seconds)

    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Windows event monitor stopped by user.")
    except Exception as e:
        print(Fore.RED + f"[!] Windows event monitor stopped: {e}")


# === Main Entry ===
def start_windows_monitor():
    monitor_windows_events()
