# db.py
import sqlite3
import os

# --- Create a reliable, absolute path for the database ---
# This will place the database file in the same directory as this db.py script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, "splint_agent.db")

def create_connection():
    """Create a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device TEXT NOT NULL,
                type TEXT,
                description TEXT
            );
        ''')
        return conn
    except Exception as e:
        # We print the DB_PATH to make debugging easier
        print(f"Error connecting to database at {DB_PATH}: {e}")
    return None

def insert_log(timestamp, device, type, description):
    """Log a new event to the database."""
    conn = create_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO logs (timestamp, device, type, description) VALUES (?, ?, ?, ?)",
                (timestamp, device, type, description)
            )
            conn.commit()
        except Exception as e:
            print(f"Error inserting log into DB: {e}")
        finally:
            conn.close()