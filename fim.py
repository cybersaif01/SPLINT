import os
import hashlib
import json
import csv
from datetime import datetime
from alerter import send_alert
from rules import rules
import re

# Constants
WATCHED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    os.path.expanduser("~/.bashrc"),
    os.path.expanduser("~/test_watch.txt"),
    os.path.expanduser("~/home/cybersaif/Documents/summa.txt")
]

HASH_DB = "hashes.json"
FIM_ALERT_CSV = "fim_alerts.csv"

# ─────────────────────────────────────────────
def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        return "PERMISSION_DENIED"

# ─────────────────────────────────────────────
def load_hashes():
    if not os.path.exists(HASH_DB):
        return {}
    with open(HASH_DB, "r") as f:
        return json.load(f)

# ─────────────────────────────────────────────
def save_hashes(hash_dict):
    with open(HASH_DB, "w") as f:
        json.dump(hash_dict, f, indent=4)

# ─────────────────────────────────────────────
def write_fim_csv(timestamp, rule, file_path, old_hash, new_hash):
    new_file = not os.path.exists(FIM_ALERT_CSV)
    with open(FIM_ALERT_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["Timestamp", "Alert Name", "Severity", "File", "Old Hash", "New Hash"])
        writer.writerow([
            timestamp,
            rule["name"],
            rule["severity"],
            file_path,
            old_hash,
            new_hash
        ])

# ─────────────────────────────────────────────
def scan_file_contents(path):
    try:
        with open(path, "r") as f:
            content = f.read()
            print(f"[DEBUG] Scanning: {path}")
            print(f"[DEBUG] Content: {content}")
            for rule in rules:
                if rule.get("type") != "fim-content":
                    continue
                pattern = rule.get("pattern")
                if isinstance(pattern, (str, re.Pattern)) and re.search(pattern, content):
                    print(f"[DEBUG] Matched rule: {rule['name']}")
                    return rule
    except Exception as e:
        print(f"[DEBUG] scan_file_contents error: {e}")
    return None

# ─────────────────────────────────────────────
def run_fim():
    print(f"[+] FIM Check: {datetime.now()}")
    stored_hashes = load_hashes()
    current_hashes = {}

    fim_rules = [r for r in rules if r.get("type") == "fim"]

    for path in WATCHED_FILES:
        current = calculate_hash(path)
        current_hashes[path] = current
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if path not in stored_hashes:
            print(f"[NEW] Monitoring started for {path}")
            continue

        if current == stored_hashes[path]:
            continue

        # Content scan first
        matched_rule = scan_file_contents(path)
        if matched_rule:
            send_alert(matched_rule, user="SYSTEM", ip="127.0.0.1", line=path)
            write_fim_csv(timestamp, matched_rule, path, stored_hashes.get(path, "N/A"), current)
            print(f"[FIM-ALERT] Content Rule Match: {matched_rule['name']} - {path}")
        else:
            # Pick file-based rule
            if current == "PERMISSION_DENIED":
                rule = next(r for r in fim_rules if r["name"] == "Permission Denied")
            elif current is None:
                rule = next(r for r in fim_rules if r["name"] == "File Deleted")
            else:
                rule = next(r for r in fim_rules if r["name"] == "File Modified")

            send_alert(rule, user="SYSTEM", ip="127.0.0.1", line=path)
            write_fim_csv(timestamp, rule, path, stored_hashes.get(path, "N/A"), current)
            print(f"[FIM-ALERT] {rule['name']} - {path}")

        # ─────── YARA SCAN ───────
        if current not in (None, "PERMISSION_DENIED"):
            try:
                from yara_scanner import yara_rules, scan_files
                matches = scan_files(path, yara_rules)
                if matches:
                    for match in matches:
                        send_alert({
                            "mitre_id": "T1204",
                            "name": f"YARA Match: {match.rule}",
                            "description": f"YARA rule '{match.rule}' matched file {path}",
                            "severity": "high"
                        }, user="SYSTEM", ip="127.0.0.1", line=f"{path}")
                        print(f"[YARA ALERT] Rule: {match.rule} matched {path}")
            except Exception as e:
                print(f"[!] YARA scan failed for {path}: {e}")

    save_hashes(current_hashes)

# ─────────────────────────────────────────────
if __name__ == "__main__":
    run_fim()
