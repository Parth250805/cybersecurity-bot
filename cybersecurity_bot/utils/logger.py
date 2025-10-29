import os
from datetime import datetime
from pathlib import Path

# Define the log file path inside the logs folder
LOG_DIR = Path(__file__).resolve().parents[2] / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)  # Create logs folder if missing
LOG_FILE = LOG_DIR / "detections.log"


def log_detection(process_name: str, pid: int):
    """
    Logs details about detected suspicious or malicious processes
    into a timestamped log file located in the 'logs' directory.
    """

    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] Detected: {process_name} (PID: {pid})\n"

        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(log_entry)

        print(f"📝 Logged detection: {process_name} (PID: {pid})")

    except Exception as e:
        print(f"❌ Failed to log detection: {e}")
