"""
SPLINT Agent - Dashboard-ready
Features:
 - Auto-register / heartbeat to Supabase
 - Windows Event Log monitor (deduplicated)
 - USB monitor
 - Persist last processed Windows event record
 - Insert events into `logs` table for dashboard
"""

import os, time, socket, getpass, platform, threading, traceback, json
from datetime import datetime, timezone
from typing import Optional

try:
    from supabase import create_client, Client
except Exception:
    create_client = None
    Client = None

from colorama import Fore, Style, init as colorama_init
import config

colorama_init(autoreset=True)

AGENT_VERSION = "1.0.0"
SYSTEM_ID = platform.node()
OS_TYPE = platform.system()

STATE_DIR = os.path.join(os.path.expanduser("~"), ".splint_agent")
os.makedirs(STATE_DIR, exist_ok=True)
STATE_FILE = os.path.join(STATE_DIR, "state.json")

SUPABASE_URL = config.get_config("SUPABASE_URL") or os.getenv("SUPABASE_URL")
SUPABASE_KEY = config.get_config("SUPABASE_KEY") or config.get_config("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")

# Fallback keys if config missing
FALLBACK_SUPABASE_URL = "https://pzbjmfylqtkmcxocrjhq.supabase.co"
FALLBACK_SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB6YmptZnlscXRrbWN4b2NyamhxIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjE5MjUxNjYsImV4cCI6MjA3NzUwMTE2Nn0.566DfNXGPNDItuneFc66ED1yQhHIm6MgIpZ_-0SwDSg"

if not SUPABASE_URL:
    SUPABASE_URL = FALLBACK_SUPABASE_URL
if not SUPABASE_KEY:
    SUPABASE_KEY = FALLBACK_SUPABASE_KEY

supabase: Optional[Client] = None
if create_client:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        print(f"{Fore.CYAN}[+] Supabase client initialized ({SUPABASE_URL}){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Supabase init failed: {e}{Style.RESET_ALL}")
        supabase = None
else:
    print(f"{Fore.YELLOW}[!] supabase-py not installed. Supabase features disabled.{Style.RESET_ALL}")

# ---------------------------
# Helpers
# ---------------------------
def log(msg: str, color=Fore.GREEN):
    print(f"{color}[{datetime.now(timezone.utc).isoformat()}] {msg}{Style.RESET_ALL}")

def safe_json_load(path: str, default: dict = None):
    default = default or {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def safe_json_save(path: str, data: dict):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        log(f"Failed to save state: {e}", Fore.YELLOW)

# ---------------------------
# System info
# ---------------------------
def get_system_info():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "unknown"
    return {
        "hostname": hostname,
        "username": getpass.getuser(),
        "os": OS_TYPE,
        "os_version": platform.version(),
        "ip_address": ip,
        "agent_version": AGENT_VERSION
    }

# ---------------------------
# Supabase helpers
# ---------------------------
def upsert_agent_record(supabase_client: Client, info: dict):
    if not supabase_client:
        log("Supabase client not configured, skipping agent upsert.", Fore.YELLOW)
        return
    try:
        payload = {
            "hostname": info["hostname"],
            "username": info["username"],
            "os": info["os"],
            "os_version": info["os_version"],
            "ip_address": info["ip_address"],
            "agent_version": info["agent_version"],
            "last_seen": datetime.utcnow().isoformat(),
            "status": "active"
        }
        supabase_client.table("agents").upsert(payload, on_conflict="hostname").execute()
        log(f"Agent record upserted for {info['hostname']}", Fore.CYAN)
    except Exception as e:
        log(f"Failed to upsert agent record: {e}", Fore.YELLOW)

def agent_heartbeat_loop(supabase_client: Client, info: dict, interval: int = 60):
    while True:
        try:
            upsert_agent_record(supabase_client, info)
        except Exception as e:
            log(f"Heartbeat error: {e}", Fore.YELLOW)
        time.sleep(interval)

# ---------------------------
# State persistence
# ---------------------------
def load_state():
    return safe_json_load(STATE_FILE, {"last_record_number": 0})

def save_state(state: dict):
    safe_json_save(STATE_FILE, state)

# ---------------------------
# Windows / USB collectors
# ---------------------------
def import_windows_collector():
    try:
        import collector_windows as cw
        if hasattr(cw, "start_windows_monitor"):
            return cw.start_windows_monitor
        if hasattr(cw, "monitor_windows_events"):
            return cw.monitor_windows_events
    except Exception as e:
        log(f"collector_windows import failed: {e}", Fore.YELLOW)
    return None

def import_usb_monitor():
    try:
        import usb_monitor as um
        if hasattr(um, "monitor_usb"):
            return um.monitor_usb
    except Exception as e:
        log(f"usb_monitor import failed: {e}", Fore.YELLOW)
    return None

def run_collector_in_thread(target_func, name: str, supabase_client: Optional[Client], sys_info: dict, restart_delay: int = 5):
    def worker():
        while True:
            try:
                log(f"Starting collector: {name}", Fore.MAGENTA)
                try:
                    target_func(supabase_client, sys_info)
                except TypeError:
                    target_func()
            except Exception as e:
                log(f"Collector {name} crashed: {e}\n{traceback.format_exc()}", Fore.RED)
            time.sleep(restart_delay)
    t = threading.Thread(target=worker, name=f"collector-{name}", daemon=True)
    t.start()
    return t

# ---------------------------
# Main agent
# ---------------------------
def main_agent():
    log("Starting SPLINT Agent...", Fore.CYAN)
    sys_info = get_system_info()
    log(f"System info: {sys_info}", Fore.WHITE)

    upsert_agent_record(supabase, sys_info)

    if supabase:
        threading.Thread(target=agent_heartbeat_loop, args=(supabase, sys_info, 60), daemon=True).start()
    else:
        log("Supabase not configured; heartbeat disabled.", Fore.YELLOW)

    state = load_state()
    last_record_number = state.get("last_record_number", 0)
    log(f"Last processed Windows event record: {last_record_number}", Fore.WHITE)

    windows_collector = import_windows_collector()
    usb_collector = import_usb_monitor()

    # Windows collector wrapper
    if windows_collector:
        def windows_wrapper(supabase_client, sys_info):
            for event in windows_collector():
                record_number = getattr(event, "RecordNumber", 0)
                if record_number <= state.get("last_record_number", 0):
                    continue
                supabase_client.table("logs").insert({
                    "system": sys_info["hostname"],
                    "received_at": datetime.utcnow().isoformat(),
                    "description": getattr(event, "Message", str(event)),
                    "severity": "info",  # can add mapping based on EventID
                    "username": getattr(event, "User", sys_info["username"]),
                    "eventid": getattr(event, "EventID", None),
                    "source": getattr(event, "SourceName", "Windows Event"),
                    "message": getattr(event, "Message", str(event))
                }).execute()
                log(f"[+] Windows Event inserted: EventID {getattr(event,'EventID','?')}", Fore.CYAN)
                state["last_record_number"] = record_number
                save_state(state)
        run_collector_in_thread(windows_wrapper, "windows_event", supabase, sys_info)
    else:
        log("No Windows collector available. Skipping.", Fore.YELLOW)

    # USB collector wrapper
    if usb_collector:
        def usb_wrapper(supabase_client, sys_info):
            for event in usb_collector():
                supabase_client.table("logs").insert({
                    "system": sys_info["hostname"],
                    "received_at": datetime.utcnow().isoformat(),
                    "description": f"USB {event.get('event')} - {event.get('device')}",
                    "severity": "info",
                    "username": sys_info["username"],
                    "eventid": None,
                    "source": "USB Device",
                    "message": f"USB {event.get('event')} - {event.get('device')}"
                }).execute()
                log(f"[+] USB Event inserted: {event}", Fore.CYAN)
        run_collector_in_thread(usb_wrapper, "usb_monitor", supabase, sys_info)
    else:
        log("No USB monitor available. Skipping.", Fore.YELLOW)

    # Keep alive
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        log("SPLINT Agent shutting down.", Fore.YELLOW)
        if supabase:
            supabase.table("agents").update({
                "status": "inactive",
                "last_seen": datetime.utcnow().isoformat()
            }).eq("hostname", sys_info["hostname"]).execute()

if __name__ == "__main__":
    main_agent()
