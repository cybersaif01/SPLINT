# collector.py
import time
import os

def tail_file(file_path):
    with open(file_path, 'r') as f:
        f.seek(0, os.SEEK_END)  # Jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)  # Wait if no new line
                continue
            yield line.strip()  # Clean up and return line
