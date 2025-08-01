import time
import os
from dotenv import load_dotenv
import yaml
import psutil

from detector import scan_for_malware
from notifier import send_alert
from logger import log_detection
from killer import kill_process
from emailer import send_email_alert
from vt_scanner import get_file_hash, check_virustotal
from predictor import predict_process_risk

# Load environment variables and config.yaml
load_dotenv()
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f) or {}

MONITOR_INTERVAL = config.get("monitor_interval_seconds", 5)
RISK_SCORE_KILL_THRESHOLD = config.get("risk_score_kill_threshold", 0.7)
EMAIL_ALERTS = config.get("email_alerts", True)
POPUP_ALERTS = config.get("popups", True)

WHITELIST = set(name.lower() for name in config.get("whitelist", []))
BLACKLIST = set(name.lower() for name in config.get("blacklist", []))

print("🛡️ Cybersecurity Bot is now monitoring your system...")

handled_pids = set()

while True:
    try:
        suspicious_processes = scan_for_malware()  # Make sure your detector uses WHITELIST/BLACKLIST or accesses config internally

        for process in suspicious_processes:
            pid = process.pid
            process_name = process.name()

            if pid in handled_pids:
                continue

            # VirusTotal check (you can keep your existing code here)
            try:
                file_path = process.exe()
                file_hash = get_file_hash(file_path)
                vt_result, vt_stats = check_virustotal(file_hash)
                is_malicious = vt_result is True
                vt_report = f"VirusTotal stats: {vt_stats}" if vt_stats else "No stats."
            except Exception as e:
                file_path = "Unknown"
                file_hash = "Unknown"
                is_malicious = False
                vt_report = f"⚠️ VirusTotal check failed: {e}"

            # === This is the updated ML prediction block you wanted: ===
            try:
                cpu = process.cpu_percent(interval=0.1)
                memory = process.memory_percent()
                num_threads = process.num_threads()
                num_connections = len(process.connections())
                features = [[cpu, memory, num_threads, num_connections]]
                risk_score = predict_process_risk(features)
            except Exception as e:
                print(f"⚠️ ML prediction failed: {e}")
                risk_score = -1
                # Optionally set features to zero or fallback

            # Prepare your alert email or message body (adjusted to include new features)
            email_body = (
                f"Suspicious process detected:\n"
                f"Name: {process_name}\nPID: {pid}\n"
                f"File: {file_path}\nHash: {file_hash}\n"
                f"CPU: {cpu:.2f}%, Memory: {memory:.2f}%, Threads: {num_threads}, Connections: {num_connections}\n"
                f"Risk Score (0=low, 1=high): {risk_score:.2f}\n"
                f"{vt_report}\n"
            )
            if is_malicious:
                email_body += "\n⚠️ VirusTotal flagged this as malicious!"

            # Popup alert
            if POPUP_ALERTS:
                send_alert(process_name, pid)

            # Log detection
            log_detection(process_name, pid)

            # Send email alert
            if EMAIL_ALERTS:
                send_email_alert(subject="⚠️ Malware Detected!", body=email_body)

            # Kill process if flagged or high risk
            if (risk_score > RISK_SCORE_KILL_THRESHOLD) or is_malicious or (process_name.lower() in BLACKLIST):
                kill_process(pid)

            handled_pids.add(pid)

        time.sleep(MONITOR_INTERVAL)

    except Exception as e:
        print(f"❌ Error in monitoring loop: {e}")
        time.sleep(MONITOR_INTERVAL)
