# activity_logger.py

import json
import os
from datetime import datetime

ACTIVITY_LOG = "activity_log.json"

def report_activity(event):
    """
    event = {
        "type": "usb",
        "description": "USB device inserted: 1234:abcd"
    }
    """
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        **event
    }

    existing = []
    if os.path.exists(ACTIVITY_LOG):
        with open(ACTIVITY_LOG, "r") as f:
            try:
                existing = json.load(f)
            except:
                existing = []

    existing.insert(0, log_entry)
    with open(ACTIVITY_LOG, "w") as f:
        json.dump(existing, f, indent=4)
