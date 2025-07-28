from detector import scan_for_malware
from notifier import send_alert
from logger import log_detection
from killer import kill_process
from emailer import send_email_alert
from vt_scanner import get_file_hash, check_virustotal
from predictor import predict_process_risk

import time
import psutil

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

            try:
                file_path = process.exe()
                file_hash = get_file_hash(file_path)
                is_malicious, vt_report_url = check_virustotal(file_hash)
            except Exception as e:
                file_path = "Unknown"
                file_hash = "Unknown"
                is_malicious = False
                vt_report_url = None
                print(f"⚠️ VirusTotal check failed: {e}")

            # 🧠 Machine Learning Prediction
            try:
                cpu = process.cpu_percent(interval=0.1)
                memory = process.memory_percent()
                num_threads = process.num_threads()
                risk_score = predict_process_risk([[cpu, memory, num_threads]])
            except Exception as e:
                print(f"⚠️ ML Prediction failed: {e}")
                risk_score = -1

            # 📨 Email Body
            email_body = (
                f"Suspicious process detected:\n"
                f"Name: {process_name}\nPID: {pid}\n"
                f"File: {file_path}\nHash: {file_hash}\n"
                f"CPU: {cpu:.2f}%, Memory: {memory:.2f}%, Threads: {num_threads}\n"
                f"Risk Score (0 low - 1 high): {risk_score:.2f}\n"
            )

            if is_malicious:
                email_body += f"\n⚠️ VirusTotal flagged this file as malicious!\nReport: {vt_report_url}"
            else:
                email_body += f"\n✔️ VirusTotal found no major threats (or hash not in database)."

            send_alert(process_name, pid)
            log_detection(process_name, pid)
            send_email_alert(subject="⚠️ Malware Detected!", body=email_body)

            # 🚫 Kill process if high risk or flagged by VirusTotal
            if risk_score > 0.7 or is_malicious:
                kill_process(pid)

            handled_pids.add(pid)

        time.sleep(5)

    except Exception as e:
        print(f"❌ Error in monitoring loop: {e}")
        time.sleep(5)
