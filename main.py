from detector import scan_for_malware
from notifier import send_alert
from logger import log_detection
from killer import kill_process
from emailer import send_email_alert
import time

print("🛡️ Cybersecurity Bot is now monitoring your system...")

handled_pids = set()  # Store already-detected PIDs

while True:
    try:
        suspicious_processes = scan_for_malware()
        for process in suspicious_processes:
            pid = process.pid
            process_name = process.name()

            if pid in handled_pids:
                continue

            send_alert(process_name, pid)
            log_detection(process_name, pid)
            send_email_alert(
                subject="⚠️ Malware Detected!",
                body=f"Suspicious process detected:\n{process_name} (PID: {pid})"
            )
            kill_process(pid)
            handled_pids.add(pid)

        time.sleep(5)

    except Exception as e:
        print(f"❌ Error in monitoring loop: {e}")
        time.sleep(5)  # prevent spamming if it fails

