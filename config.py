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
    Special handler for comma-separated log file lists.
    """
    log_files_str = os.getenv("LOG_FILES", "/var/log/auth.log")
    return [log.strip() for log in log_files_str.split(',')]
