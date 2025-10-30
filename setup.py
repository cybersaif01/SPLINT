# setup.py
import configparser
import getpass
import bcrypt

def create_config():
    """
    Generates a new config.ini file with user-provided settings
    and a securely hashed admin password.
    """
    config = configparser.ConfigParser()

    print("--- SPLINT HIDS Configuration Setup ---")
    print("Please provide the following details to create your config.ini file.")

    # --- Main Settings ---
    config['main'] = {}
    config['main']['server_url'] = input("Enter the server URL [http://localhost:5000]: ") or "http://localhost:5000"
    config['main']['log_file'] = input("Enter the auth log file to monitor [/var/log/auth.log]: ") or "/var/log/auth.log"
    config['main']['state_file'] = 'blocked_ips.json' # File to save blocked IPs
    config['main']['log_output_file'] = 'splint.log' # File for application logs

    # --- Brute Force Detection Settings ---
    config['bruteforce'] = {}
    config['bruteforce']['threshold'] = input("Enter failed login threshold (e.g., 5): ") or '5'
    config['bruteforce']['window_seconds'] = input("Enter time window in seconds (e.g., 60): ") or '60'
    config['bruteforce']['block_duration_minutes'] = input("Enter IP block duration in minutes (e.g., 15): ") or '15'


    # --- Admin Password ---
    config['admin'] = {}
    while True:
        password = getpass.getpass("Enter a new secure admin password: ").strip()
        password_confirm = getpass.getpass("Confirm the password: ").strip()
        if password == password_confirm and password:
            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            config['admin']['password_hash'] = hashed_password.decode('utf-8')
            break
        else:
            print("[!] Passwords do not match or are empty. Please try again.")

    # --- Write to file ---
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

    print("\n[✓] Configuration saved successfully to config.ini!")
    print("[IMPORTANT] Please run main.py to start the application.")


if __name__ == "__main__":
    create_config()
