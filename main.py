import config
import getpass
import os
import threading
import time
import re
import shutil
import requests
import jwt
import subprocess
import platform
import socket
from collections import defaultdict
from datetime import datetime
from colorama import Fore, Style, init

# ==========================================================
#                  CORE MODULE IMPORTS
# ==========================================================
from activity_reporter import report_activity
from fim import run_fim
from usb_monitor import monitor_usb

# OS-dependent imports
system_type = platform.system()
if system_type == "Linux":
    from collector import tail_file
    from rules import rules as rules_list
elif system_type == "Windows":
    from collector_windows import start_windows_monitor
    from rules_windows import rules_windows as rules_list
else:
    print(f"{Fore.RED}[!] Unsupported OS: {system_type}")
    exit(1)

# ==========================================================
init(autoreset=True)

# ───────────────────────────────
# Config
SECRET_KEY = config.get_config("SECRET_KEY")
AUTH_URL   = "https://localhost:8000"
SERVER_URL = config.get_config("SERVER_URL")
LOG_FILES  = config.get_log_files()
ALGORITHM  = config.get_config("ALGORITHM")
ABUSEIPDB_API_KEY = config.get_config("ABUSEIPDB_API_KEY")
ABUSEIPDB_CONFIDENCE_SCORE = 75
checked_ips = set()
blocked_ips = set()
SYSTEM_ID = platform.node()

# --- Function to report blocked IPs to the server ---
def report_blocked_ip(ip: str):
    try:
        payload = {"system_id": SYSTEM_ID, "blocked_ip": ip}
        report_url = f"{SERVER_URL}/api/report/block"
        requests.post(report_url, json=payload, verify=False, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[SOAR] Failed to report blocked IP to server: {e}")

# --- Register system with server ---
def register_system(token):
    try:
        system_id = platform.node()
        ip_address = socket.gethostbyname(socket.gethostname())
        payload = {
            "system_id": system_id,
            "ip": ip_address,
            "os": system_type,
            "timestamp": datetime.now().isoformat()
        }
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{SERVER_URL}/api/systems/register"
        resp = requests.post(url, json=payload, headers=headers, verify=False, timeout=10)
        if resp.status_code == 200:
            print(f"{Fore.GREEN}[✓] Registered system {system_id} ({ip_address}) with server")
        else:
            print(f"{Fore.RED}[!] Failed to register system: {resp.text}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error while registering system: {e}")

# ───────────────────────────────
# Alerter & UI
def send_alert(rule, user="N/A", ip="N/A", line=""):
    print(f"\n{Fore.RED}🚨 [ALERT] {rule.get('name')} (Severity: {rule.get('severity')})")
    print(f"{Fore.YELLOW}  ├── User: {user}, IP: {ip}")
    print(f"{Fore.WHITE}  └── Triggered by: {line.strip()}")
    event_payload = {
        "type": "alert", "mitre_id": rule.get("mitre_id", ""), "name": rule.get("name", ""),
        "severity": rule.get("severity", ""), "description": rule.get("description", ""),
        "user": user, "ip": ip, "timestamp": datetime.now().isoformat()
    }
    report_activity(event_payload)

def print_banner():
    terminal_width = shutil.get_terminal_size((80, 20)).columns
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
   ███████╗██████╗ ██╗     ██╗███╗   ██╗████████╗
   ██╔════╝██╔══██╗██║     ██║████╗  ██║╚══██╔══╝
   ███████║███████║██║     ██║██╔██╗ ██║   ██║
   ╚════██║██╔═══╝ ██║     ██║██║╚██╗██║   ██║
   ███████║██║     ███████╗██║██║ ╚████║   ██║
   ╚══════╝╚═╝     ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
{Style.RESET_ALL}
      Security Protection & Log Intelligence Network Tool
    """.center(terminal_width)
    print(banner)
    print(f"{Fore.YELLOW}[+] Welcome to SPLINT Security Monitor\n")

def authenticate():
    username = input(f"{Fore.CYAN}Enter your username: {Style.RESET_ALL}").strip()
    password = getpass.getpass(f"{Fore.CYAN}Enter your password: {Style.RESET_ALL}").strip()
    try:
        response = requests.post(
            f"{AUTH_URL}/token",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
            verify=False
        )
        if response.status_code != 200:
            print(f"{Fore.RED}[!] Authentication failed: {response.text}")
            return None, None
        token = response.json()["access_token"]
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return token, decoded
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Cannot connect to the authentication service. Is it running?")
        print(f"{Fore.RED}  └── Error: {e}")
        return None, None
    except Exception as e:
        print(f"{Fore.RED}[!] An unexpected error occurred during authentication: {e}")
        return None, None

# --- Threat Intelligence & SOAR ---
def check_ip_reputation(ip: str):
    if not ABUSEIPDB_API_KEY or ip in checked_ips: return
    print(f"{Fore.BLUE}[Threat Intel] Checking IP: {ip}")
    checked_ips.add(ip)
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip, 'maxAgeInDays': '90'},
            headers={'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
        )
        if response.status_code == 200 and response.json().get('data', {}).get('abuseConfidenceScore', 0) >= ABUSEIPDB_CONFIDENCE_SCORE:
            send_alert({
                "name": "Threat Intel Match: Malicious IP",
                "severity": "high",
                "mitre_id": "T1105",
                "description": f"IP {ip} has a high abuse score of {response.json()['data']['abuseConfidenceScore']}."
            }, ip=ip, line="AbuseIPDB Reputation Check")
    except Exception: pass

def block_ip_with_firewall(ip: str):
    if ip in blocked_ips or system_type != "Linux": return
    print(f"{Fore.MAGENTA}[SOAR] Attempting to block IP {ip} with UFW firewall...")
    try:
        status_result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True, timeout=5)
        if "inactive" in status_result.stdout:
            print(f"{Fore.YELLOW}[SOAR Warning] UFW is inactive. Cannot block IP.")
            return
        result = subprocess.run(['sudo', 'ufw', 'deny', 'from', ip, 'to', 'any'], capture_output=True, text=True, check=True, timeout=5)
        if "Rule added" in result.stdout:
            blocked_ips.add(ip)
            print(f"{Fore.GREEN}[SOAR Success] Successfully blocked IP {ip}.")
            report_blocked_ip(ip)
            send_alert({
                "name": "SOAR: IP Blocked by Firewall",
                "severity": "high",
                "mitre_id": "T1562.004",
                "description": f"Automated response: Blocked IP {ip} due to suspicious activity."
            }, ip=ip, line="UFW firewall rule added")
        else:
            print(f"{Fore.RED}[SOAR Failure] Failed to block IP {ip}. UFW output: {result.stdout}")
    except Exception as e:
        print(f"{Fore.RED}[SOAR Error] An unexpected error occurred: {e}")

# --- Log Monitoring Logic ---
def log_monitor_worker(log_file):
    print(f"{Fore.CYAN}[+] Starting log monitor for: {log_file}{Style.RESET_ALL}")
    failed_attempts = defaultdict(list)
    try:
        if system_type == "Linux":
            from collector import tail_file
            log_source = tail_file(log_file)
        else:
            from collector_windows import windows_event_monitor
            log_source = windows_event_monitor()

        for line in log_source:
            for rule in rules_list:
                if "fim" in rule.get("type", "") or not isinstance(rule.get("pattern"), re.Pattern): continue
                match = re.search(rule["pattern"], line)
                if match:
                    ip = match.groupdict().get("ip", "N/A")
                    user = match.groupdict().get("user", "N/A")
                    send_alert(rule, user=user, ip=ip, line=line)
                    if ip != "N/A": check_ip_reputation(ip)
                    if "Failed Login" in rule.get("name", ""):
                        now = time.time()
                        failed_attempts[ip].append(now)
                        failed_attempts[ip] = [ts for ts in failed_attempts[ip] if now - ts <= 60]
                        if len(failed_attempts[ip]) >= 5:
                            brute_force_rule = { "name": "Brute Force Threshold Exceeded", "severity": "critical", "description": f"5+ failures in 60s from {ip}"}
                            send_alert(brute_force_rule, user="N/A", ip=ip, line="Multiple failed logins")
                            block_ip_with_firewall(ip)
                            failed_attempts[ip].clear()
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error in monitor for {log_file}: {e}")

# --- USB & FIM ---
def handle_usb_events(username):
    print(f"{Fore.CYAN}[+] USB hardware monitoring service started.{Style.RESET_ALL}")
    for event in monitor_usb():
        device_info = event.get("device", "Unknown Device")
        event_type = event.get("event", "unknown")
        rule, line_trigger = {}, ""
        if event_type == 'connected':
            rule = {"name": "USB Device Plugged In", "severity": "medium", "mitre_id": "T1200", "description": f"A USB device was connected: {device_info}"}
            line_trigger = f"USB Connected: {device_info}"
        elif event_type == 'disconnected':
            rule = {"name": "USB Device Unplugged", "severity": "low", "mitre_id": "T1200", "description": f"A USB device was disconnected: {device_info}"}
            line_trigger = f"USB Disconnected: {device_info}"
        if rule and line_trigger:
            send_alert(rule, user=username, ip="localhost", line=line_trigger)

def start_all_log_monitors():
    if not isinstance(LOG_FILES, list) or not LOG_FILES:
        print(f"{Fore.RED}[!] Config Error: LOG_FILES in your .env file is not a valid list. Please check the format (e.g., /var/log/auth.log,/var/log/syslog).")
        return
    for log_file_path in LOG_FILES:
        thread = threading.Thread(target=log_monitor_worker, args=(log_file_path,), daemon=True)
        thread.start()

# --- Main Execution ---
if __name__ == "__main__":
    print_banner()
    token, decoded = authenticate()
    if not token: exit(1)

    # Register system after authentication
    register_system(token)

    role, username = decoded.get("role"), decoded.get("sub")
    print(f"{Fore.GREEN}[✓] Authenticated as {username} ({role})")

    if role == "employee":
        print("[+] Initializing SPLINT Monitoring Agent...")
        report_activity({
            "type": "login",
            "name": "User Logged In",
            "severity": "info",
            "description": f"User '{username}' logged in.",
            "user": username,
            "role": role
        })
        send_alert({
            "name": "Agent Login",
            "severity": "info",
            "description": f"Monitoring agent started for user '{username}'."
        }, user=username, ip="localhost", line="Agent Initialized")
        
        threading.Thread(target=handle_usb_events, args=(username,), daemon=True).start()
        threading.Thread(target=run_fim, daemon=True).start()
        
        if system_type == "Linux":
            start_all_log_monitors()
        elif system_type == "Windows":
            start_windows_monitor()
        
        print(f"{Fore.GREEN}[✓] SPLINT monitoring services are running in the background.")
        print(f"{Fore.YELLOW}[i] Press Ctrl+C to stop the agent.")
        try:
            while True: time.sleep(10)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Stopping SPLINT agent.")
            exit()
    elif role in ["admin", "analyst"]:
        print(f"{Fore.YELLOW}[i] {role.capitalize()} '{username}' authenticated successfully.")
        print(f"{Fore.YELLOW}  └── Please use the web dashboard at {SERVER_URL} for all administrative tasks.")
    else:
        print(f"{Fore.RED}[!] Unknown role: {role}")
