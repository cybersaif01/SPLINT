import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def get_config(key, default=None):
    """
    Retrieves a configuration value from environment variables.
    """
    return os.getenv(key, default)

def get_log_files():
    """
    Returns a list of log files defined in the environment.
    Example:
    LOG_FILES="/var/log/auth.log,/var/log/syslog"
    """
    log_files_str = os.getenv("LOG_FILES", "/var/log/auth.log")
    return [log.strip() for log in log_files_str.split(',')]

# --- Additional convenience getters ---

def get_supabase_config():
    """
    Returns Supabase URL and Key from environment.
    """
    return {
        "url": get_config("SUPABASE_URL"),
        "key": get_config("SUPABASE_SERVICE_KEY") or get_config("SUPABASE_ANON_KEY")
    }

def get_system_id():
    """
    Returns the system unique identifier for this agent.
    """
    return get_config("SYSTEM_ID", os.getenv("COMPUTERNAME") or os.getenv("HOSTNAME") or "UNKNOWN_SYSTEM")

def get_server_url():
    """
    Returns your backend server URL (optional if using Supabase only).
    """
    return get_config("SERVER_URL", "")
