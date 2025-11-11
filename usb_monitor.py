import os
import time
import platform
from datetime import datetime
from colorama import Fore, Style, init
from supabase import create_client, Client
from dotenv import load_dotenv

# Initialize Colorama
init(autoreset=True)

# === Load environment variables ===
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print(Fore.RED + "[x] Supabase credentials not found. Please check your .env file.")
    exit(1)

# === Create Supabase client ===
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# === Insert Log into Supabase ===
def insert_usb_log(event_type, device_name):
    """Insert USB event into Supabase logs table."""
    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_id": 9999,  # Unique ID to identify USB logs
        "source": "USB Monitor",
        "message": f"USB device {event_type}: {device_name}",
        "username": os.getenv("COMPUTERNAME") or "SYSTEM"
    }
    try:
        res = supabase.table("logs").insert(data).execute()
        if res.data:
            print(Fore.GREEN + f"[+] USB event inserted successfully → {event_type}: {device_name}")
        else:
            print(Fore.RED + f"[x] Failed to insert USB log: {res}")
    except Exception as e:
        print(Fore.RED + f"[x] Supabase insert failed: {e}")

# === Monitor Function ===
def monitor_usb():
    """
    Cross-platform USB monitor:
    - Linux: Uses pyudev
    - Windows: Uses wmi
    Logs all detected USB events to Supabase
    """
    system = platform.system()

    # 🐧 Linux version (pyudev)
    if system == "Linux":
        try:
            import pyudev
            context = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(context)
            monitor.filter_by(subsystem="usb")

            print(Fore.CYAN + "[USB Monitor] Started on Linux using pyudev.")

            for device in iter(monitor.poll, None):
                if "ID_MODEL" not in device:
                    continue

                action = device.action
                device_name = f"{device.get('ID_VENDOR', 'Unknown')} {device.get('ID_MODEL', 'USB Device')}"

                if action == "add":
                    print(Fore.YELLOW + f"[USB Connected] {device_name}")
                    insert_usb_log("connected", device_name)

                elif action == "remove":
                    print(Fore.YELLOW + f"[USB Disconnected] {device_name}")
                    insert_usb_log("disconnected", device_name)

        except Exception as e:
            print(Fore.RED + f"[USB Monitor] Linux error: {e}")

    # 🪟 Windows version (WMI)
    elif system == "Windows":
        try:
            import wmi
            c = wmi.WMI()
            print(Fore.CYAN + "[USB Monitor] Started on Windows using WMI.")

            watcher_insert = c.watch_for(
                notification_type="Creation",
                wmi_class="Win32_USBControllerDevice"
            )
            watcher_remove = c.watch_for(
                notification_type="Deletion",
                wmi_class="Win32_USBControllerDevice"
            )

            while True:
                try:
                    inserted = watcher_insert(timeout_ms=500)
                    if inserted:
                        print(Fore.YELLOW + "[USB Connected] A USB device was connected.")
                        insert_usb_log("connected", "USB Device")
                except wmi.x_wmi_timed_out:
                    pass

                try:
                    removed = watcher_remove(timeout_ms=500)
                    if removed:
                        print(Fore.YELLOW + "[USB Disconnected] A USB device was removed.")
                        insert_usb_log("disconnected", "USB Device")
                except wmi.x_wmi_timed_out:
                    pass

                time.sleep(0.5)

        except ImportError:
            print(Fore.RED + "[USB Monitor] Missing dependency: 'wmi'")
            print(Fore.YELLOW + "Run this command: pip install wmi")
        except Exception as e:
            print(Fore.RED + f"[USB Monitor] Windows error: {e}")

    else:
        print(Fore.RED + f"[USB Monitor] Unsupported OS: {system}")

# === Main entry point ===
if __name__ == "__main__":
    monitor_usb()
