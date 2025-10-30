import json
import getpass
import subprocess
import os

def get_user_role(username):
    try:
        with open("users.json", "r") as f:
            users = json.load(f)
        return users.get(username, "employee")  # default to employee
    except Exception as e:
        print(f"[ERROR] Could not read users.json: {e}")
        return "employee"

def start_splint():
    print("[+] Starting SPLINT monitor for employee...")
    subprocess.Popen(["python3", "main.py"])

def start_admin_dashboard():
    print("[+] Starting Admin Dashboard...")
    subprocess.run(["python3", "admin_panel.py"])

if __name__ == "__main__":
    username = getpass.getuser()
    role = get_user_role(username)

    print(f"[LOGIN] User: {username} | Role: {role}")

    if role == "admin":
        start_admin_dashboard()
    else:
        start_splint()
