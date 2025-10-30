import hashlib
import json

USERS_FILE = "users.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, password, role="employee"):
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

    users[username] = {
        "password": hash_password(password),
        "role": role
    }

    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

    print(f"[+] User '{username}' added successfully with role '{role}'.")

if __name__ == "__main__":
    u = input("Enter new username: ")
    p = input("Enter password: ")
    r = input("Enter role (admin/employee): ").strip() or "employee"
    add_user(u, p, r)
