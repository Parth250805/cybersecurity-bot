from detector import scan_for_malware
from notifier import send_alert
from logger import log_detection
from killer import kill_process
from emailer import send_email_alert  # This is your email module
import time

print("🛡️ Cybersecurity Bot is now monitoring your system...")

while True:
    suspicious_processes = scan_for_malware()
    for process in suspicious_processes:
        process_name = process.name()
        pid = process.pid

        alert_message = f"Suspicious process found: {process_name} (PID: {pid})"
        send_alert(alert_message)
        log_detection(process_name, pid)
        send_email_alert(
            subject="⚠️ Malware Detected!",
            body=f"Suspicious process detected:\n{process_name} (PID: {pid})"
        )
        kill_process(pid)

    time.sleep(5)  # Adjust as needed
