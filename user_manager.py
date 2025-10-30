import json
import hashlib
import os
import getpass

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user():
    username = input("Enter new username: ").strip()
    role = input("Enter role (admin/employee): ").strip().lower()
    if role not in ["admin", "employee"]:
        print("[!] Invalid role. Must be 'admin' or 'employee'.")
        return

    password = getpass.getpass("Enter password: ").strip()
    confirm = getpass.getpass("Confirm password: ").strip()
    if password != confirm:
        print("[!] Passwords do not match.")
        return

    users = load_users()
    if username in users:
        print("[!] User already exists.")
        return

    users[username] = {
        "role": role,
        "password_hash": hash_password(password)
    }
    save_users(users)
    print(f"[+] User '{username}' added successfully.")

def remove_user():
    username = input("Enter username to remove: ").strip()
    users = load_users()
    if username not in users:
        print("[!] User not found.")
        return
    confirm = input(f"Are you sure you want to remove '{username}'? (y/n): ").lower()
    if confirm == "y":
        del users[username]
        save_users(users)
        print(f"[+] User '{username}' removed successfully.")

def list_users():
    users = load_users()
    if not users:
        print("[!] No users found.")
        return
    print("\nCurrent Users:")
    for username, info in users.items():
        print(f" - {username} ({info['role']})")
    print()

def change_password():
    username = input("Enter username: ").strip()
    users = load_users()
    if username not in users:
        print("[!] User not found.")
        return
    password = getpass.getpass("Enter new password: ").strip()
    confirm = getpass.getpass("Confirm new password: ").strip()
    if password != confirm:
        print("[!] Passwords do not match.")
        return
    users[username]["password_hash"] = hash_password(password)
    save_users(users)
    print(f"[+] Password for '{username}' updated successfully.")

def main():
    while True:
        print("\n=== User Manager ===")
        print("1. Add User")
        print("2. Remove User")
        print("3. List Users")
        print("4. Change Password")
        print("5. Exit")

        choice = input("Select an option: ").strip()
        if choice == "1":
            add_user()
        elif choice == "2":
            remove_user()
        elif choice == "3":
            list_users()
        elif choice == "4":
            change_password()
        elif choice == "5":
            print("Exiting User Manager.")
            break
        else:
            print("[!] Invalid choice. Try again.")

if __name__ == "__main__":
    main()
