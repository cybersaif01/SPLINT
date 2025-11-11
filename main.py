# main.py
"""
SPLINT Agent - production-ready main agent
Features:
 - Auto-register / heartbeat to Supabase (agents table)
 - Start Windows Event Log monitor (collector_windows) and USB monitor (usb_monitor)
 - Persist last processed Windows event record number to avoid duplicates
 - Auto-start on Windows (registry Run key)
 - Resilient threads that auto-restart collectors if they crash
 - Colorized logging
"""

import os
import time
import socket
import getpass
import platform
import threading
import traceback
import json
import sys
from datetime import datetime, timezone
from typing import Optional

# 3rd-party
try:
    from supabase import create_client, Client
except Exception:
    create_client = None
    Client = None

from colorama import Fore, Style, init as colorama_init

# local config helper
import config

# Initialize colorama
colorama_init(autoreset=True)

# ---------------------------
# Configuration & Globals
# ---------------------------
AGENT_VERSION = "1.0.0"
SYSTEM_ID = platform.node()
OS_TYPE = platform.system()
STATE_DIR = os.path.join(os.path.expanduser("~"), ".splint_agent")
os.makedirs(STATE_DIR, exist_ok=True)
STATE_FILE = os.path.join(STATE_DIR, "state.json")

# Supabase config via config.get_config (reads from .env)
SUPABASE_URL = config.get_config("SUPABASE_URL") or os.getenv("SUPABASE_URL")
SUPABASE_KEY = config.get_config("SUPABASE_KEY") or config.get_config("SUPABASE_SERVICE_KEY") or os.getenv("SUPABASE_KEY")

# Fallback anon (your project anon key) - only used if nothing else provided
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
# Agent System Info
# ---------------------------
def get_system_info():
    hostname = socket.gethostname()
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = None
        # fallback: iterate interfaces if psutil available
        try:
            import psutil
            for ni, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    if getattr(a, "family", None) == socket.AF_INET and not a.address.startswith("127."):
                        ip = a.address
                        break
                if ip: break
        except Exception:
            pass

    return {
        "hostname": hostname,
        "username": getpass.getuser(),
        "os": OS_TYPE,
        "os_version": platform.version(),
        "ip_address": ip or "unknown",
        "agent_version": AGENT_VERSION
    }

# ---------------------------
# Supabase helpers
# ---------------------------
def upsert_agent_record(supabase_client: Client, info: dict):
    """
    Upsert agent registration into 'agents' table.
    Expects columns: hostname (primary key or unique), username, os, os_version, ip_address, agent_version, last_seen, status
    """
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
        # Try upsert - works if unique constraint on hostname exists
        supabase_client.table("agents").upsert(payload, on_conflict="hostname").execute()
        log(f"Agent record upserted for {info['hostname']}", Fore.CYAN)
    except Exception as e:
        log(f"Failed to upsert agent record: {e}", Fore.YELLOW)

def agent_heartbeat_loop(supabase_client: Client, info: dict, interval: int = 60):
    """
    Periodically update the agents.last_seen field.
    """
    while True:
        try:
            upsert_agent_record(supabase_client, info)
        except Exception as e:
            log(f"Heartbeat error: {e}", Fore.YELLOW)
        time.sleep(interval)

# ---------------------------
# Windows autostart helper
# ---------------------------
def enable_windows_autostart(app_name: str = "SPLINT Agent"):
    """
    Adds a registry Run key to auto-start this script at user login.
    Only for Windows. Should be used carefully.
    """
    if OS_TYPE != "Windows":
        return False
    try:
        import winreg
        exe = sys.executable  # python exe
        script = os.path.abspath(__file__)
        # command to run the script in background: use pythonw to avoid console if available
        pythonw = exe.replace("python.exe", "pythonw.exe") if exe.lower().endswith("python.exe") else exe
        cmd = f'"{pythonw}" "{script}"' if os.path.exists(pythonw) else f'"{exe}" "{script}"'
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, cmd)
        winreg.CloseKey(key)
        log("Windows autostart (Run key) added.", Fore.CYAN)
        return True
    except Exception as e:
        log(f"Failed to enable autostart: {e}", Fore.YELLOW)
        return False

# ---------------------------
# Collector start helpers (resilient threads)
# ---------------------------
# We will try to import collectors in a flexible way to support multiple versions the user may have.
def import_windows_collector():
    """
    Tries to import start_windows_monitor or monitor_windows_events from collector_windows.py
    Returns a callable that starts the monitor (blocking) or None.
    """
    try:
        import collector_windows as cw
        # Prefer start_windows_monitor if available
        if hasattr(cw, "start_windows_monitor"):
            return cw.start_windows_monitor
        if hasattr(cw, "monitor_windows_events"):
            # wrap into a function to match expected callable signature (no args)
            return cw.monitor_windows_events
    except Exception as e:
        log(f"collector_windows import failed: {e}", Fore.YELLOW)
    return None

def import_usb_monitor():
    """
    Tries to import monitor_usb from usb_monitor.py
    Returns a callable that yields events (generator) or a function that runs blocking.
    """
    try:
        import usb_monitor as um
        if hasattr(um, "monitor_usb"):
            return um.monitor_usb
    except Exception as e:
        log(f"usb_monitor import failed: {e}", Fore.YELLOW)
    return None

def run_collector_in_thread(target_func, name: str, supabase_client: Optional[Client], sys_info: dict, restart_delay: int = 5):
    """
    Runs a blocking collector function in a resilient thread. If it raises, logs and restarts after delay.
    target_func: callable - either a function that blocks (no args) or accepts (supabase, sys_info)
    """
    def worker():
        while True:
            try:
                log(f"Starting collector: {name}", Fore.MAGENTA)
                # attempt to call with (supabase, sys_info) if accepted, otherwise call without args
                try:
                    target_func(supabase_client, sys_info)
                except TypeError:
                    # try calling without args
                    target_func()
                log(f"Collector {name} exited normally.", Fore.YELLOW)
                # If it returns, wait and restart
            except Exception as e:
                log(f"Collector {name} crashed: {e}\n{traceback.format_exc()}", Fore.RED)
            time.sleep(restart_delay)
    t = threading.Thread(target=worker, name=f"collector-{name}", daemon=True)
    t.start()
    return t

# ---------------------------
# Windows event record persistence (to avoid duplicates)
# ---------------------------
def load_state():
    return safe_json_load(STATE_FILE, {"last_record_number": 0})

def save_state(state: dict):
    safe_json_save(STATE_FILE, state)

# ---------------------------
# Main agent orchestration
# ---------------------------
def main_agent():
    log("Starting SPLINT Agent...", Fore.CYAN)
    sys_info = get_system_info()
    log(f"System info: {sys_info}", Fore.WHITE)

    # Upsert/register agent immediately
    upsert_agent_record(supabase, sys_info)

    # Enable startup (only once)
    try:
        enabled = config.get_config("ENABLE_AUTOSTART", "true").lower() in ("1", "true", "yes")
    except Exception:
        enabled = True
    if enabled and OS_TYPE == "Windows":
        try:
            enable_windows_autostart()
        except Exception:
            pass

    # Start heartbeat thread to update last_seen
    if supabase:
        hb_thread = threading.Thread(target=agent_heartbeat_loop, args=(supabase, sys_info, int(config.get_config("HEARTBEAT_INTERVAL", 60))), daemon=True)
        hb_thread.start()
    else:
        log("Supabase not configured; heartbeat disabled.", Fore.YELLOW)

    # Load last state
    state = load_state()
    last_record_number = state.get("last_record_number", 0)
    log(f"Last processed Windows event record: {last_record_number}", Fore.WHITE)

    # Import collectors dynamically
    windows_collector = import_windows_collector()
    usb_collector = import_usb_monitor()

    # If we have a windows collector, run it in its own resilient thread
    if windows_collector:
        # Many collector implementations expect no args; some accept (supabase, sys_info)
        run_collector_in_thread(windows_collector, "windows_event", supabase, sys_info)
    else:
        log("No Windows event collector available. Skipping.", Fore.YELLOW)

    # If we have a usb collector, run it in a thread. usb monitor may be generator or blocking function.
    if usb_collector:
        # Wrap USB monitor to accept (supabase, sys_info) signature if necessary
        def usb_wrapper(supabase_client, sys_info):
            # If usb_monitor.monitor_usb is a generator that yields events:
            try:
                gen = usb_collector(supabase_client, sys_info)
            except TypeError:
                # older signature: monitor_usb() with internal supabase usage
                gen = usb_collector()
            # If the returned object is a generator, iterate it
            if gen is None:
                # maybe the monitor is blocking and handled internally
                return
            try:
                for event in gen:
                    # If event is a dict like {'event':'connected','device':name}
                    if isinstance(event, dict):
                        # insert into logs table (supabase)
                        try:
                            if supabase_client := supabase:
                                # build record
                                record = {
                                    "hostname": sys_info["hostname"],
                                    "event_id": 9999,
                                    "source": "USB Monitor",
                                    "message": f"USB {event.get('event')} - {event.get('device')}",
                                    "username": sys_info.get("username", "SYSTEM"),
                                    "timestamp": datetime.utcnow().isoformat()
                                }
                                supabase_client.table("logs").insert(record).execute()
                                log(f"Inserted USB event into logs: {record['message']}", Fore.CYAN)
                        except Exception as e:
                            log(f"Failed to insert USB event to Supabase: {e}", Fore.YELLOW)
                    else:
                        # if monitor yields plain strings, just log
                        log(f"USB monitor event: {event}", Fore.CYAN)
            except Exception as e:
                log(f"USB monitor wrapper error: {e}\n{traceback.format_exc()}", Fore.RED)

        run_collector_in_thread(usb_wrapper, "usb_monitor", supabase, sys_info)
    else:
        log("No USB monitor available. Skipping.", Fore.YELLOW)

    # Keep main thread alive; child threads run daemonized
    try:
        while True:
            time.sleep(10)
            # periodically save state if modified (the collector should update state itself if needed)
            # For now we persist nothing here; individual collectors may call save_state as needed.
    except KeyboardInterrupt:
        log("SPLINT Agent shutting down (KeyboardInterrupt).", Fore.YELLOW)
        # update status to inactive
        try:
            if supabase:
                supabase.table("agents").update({"status": "inactive", "last_seen": datetime.utcnow().isoformat()}).eq("hostname", sys_info["hostname"]).execute()
        except Exception:
            pass

# ---------------------------
# Entry point
# ---------------------------
if __name__ == "__main__":
    main_agent()
