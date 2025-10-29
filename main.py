import os
import sys
from pathlib import Path

# Ensure we run with the project's virtual environment so dependencies are available
try:
    if not os.environ.get("VIRTUAL_ENV"):
        _here = Path(__file__).resolve()
        _project_root = _here.parent
        venv_python = _project_root / ".venv" / "Scripts" / "python.exe"
        if venv_python.exists() and Path(sys.executable).resolve() != venv_python.resolve():
            os.execv(str(venv_python), [str(venv_python), str(_here)] + sys.argv[1:])
except Exception:
    pass
import time
import signal
import threading
import yaml
import psutil
from dotenv import load_dotenv

# === FIXED CONFIG PATH (works anywhere) ===
# Find the absolute project root containing the "cybersecurity_bot" folder
CURRENT_DIR = Path(__file__).resolve()
for parent in CURRENT_DIR.parents:
    if (parent / "cybersecurity_bot" / "config" / "config.yaml").exists():
        CONFIG_PATH = parent / "cybersecurity_bot" / "config" / "config.yaml"
        PROJECT_ROOT = parent
        break
else:
    raise FileNotFoundError(
        f"❌ Could not find config.yaml anywhere in parents of {CURRENT_DIR}"
    )

# === IMPORTS AFTER PATH IS FIXED ===
from cybersecurity_bot.core.detector import scan_for_malware
from cybersecurity_bot.utils.notifier import send_alert
from cybersecurity_bot.utils.logger import log_detection
from cybersecurity_bot.utils.killer import kill_process
from cybersecurity_bot.utils.emailer import send_email_alert
from cybersecurity_bot.utils.vt_scanner import get_file_hash, check_virustotal
from cybersecurity_bot.core.predictor import predict_process_risk

# === LOAD CONFIG ===
load_dotenv()

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f) or {}

MONITOR_INTERVAL = config.get("monitor_interval_seconds", 5)
RISK_SCORE_KILL_THRESHOLD = config.get("risk_score_kill_threshold", 0.7)
EMAIL_ALERTS = config.get("email_alerts", True)
POPUP_ALERTS = config.get("popups", True)
WHITELIST = set(name.lower() for name in config.get("whitelist", []))
BLACKLIST = set(name.lower() for name in config.get("blacklist", []))

DEBUG = False
try:
    DEBUG = bool(int(os.environ.get("CSBOT_DEBUG", "0")))
except Exception:
    DEBUG = False

print(f"🛡️ Cybersecurity Bot is now monitoring your system...")
if DEBUG:
    print(f"✅ Using config file: {CONFIG_PATH}")

handled_pids = set()

# === Graceful shutdown via Ctrl+C ===
stop_event = threading.Event()

def _handle_sigint(signum, frame):
    try:
        stop_event.set()
        print("\n🛑 Stopping... (Ctrl+C)")
    except Exception:
        pass

try:
    signal.signal(signal.SIGINT, _handle_sigint)
except Exception:
    # On some environments signal handling may not be available; fallback to KeyboardInterrupt
    pass

# === Single-instance lock ===
LOCK_PATH = PROJECT_ROOT / ".run.lock"
_lock_fd = None
try:
    try:
        _lock_fd = os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_RDWR)
    except FileExistsError:
        print("⚠️ Another instance is already running. Exiting.")
        sys.exit(0)

    # === MAIN LOOP ===
    while not stop_event.is_set():
        suspicious_processes = scan_for_malware(stop_event)

        for process in suspicious_processes:
            if stop_event.is_set():
                break
            pid = process.pid
            process_name = process.name()

            if pid in handled_pids:
                continue

            # === VirusTotal Check ===
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

            # === ML Prediction ===
            try:
                if stop_event.is_set():
                    break
                # Non-blocking CPU sample to avoid delays
                cpu = process.cpu_percent(interval=0.0)
                memory = process.memory_percent()
                num_threads = process.num_threads()
                # Use net_connections to avoid deprecation warnings
                try:
                    num_connections = len(process.net_connections())
                except Exception:
                    num_connections = 0
                features = [[cpu, memory, num_threads, num_connections]]
                risk_score = predict_process_risk(features)
            except Exception as e:
                if DEBUG:
                    print(f"⚠️ ML prediction failed: {e}")
                risk_score = -1

            # === Email/Alert Message ===
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

            if POPUP_ALERTS:
                send_alert(process_name, pid)

            log_detection(process_name, pid)

            if EMAIL_ALERTS:
                send_email_alert(subject="⚠️ Malware Detected!", body=email_body)

            if (
                risk_score > RISK_SCORE_KILL_THRESHOLD
                or is_malicious
                or (process_name.lower() in BLACKLIST)
            ):
                kill_process(pid)

            handled_pids.add(pid)

        if stop_event.wait(MONITOR_INTERVAL):
            break
except KeyboardInterrupt:
    print("\n🛑 Stopped by user.")
except Exception as e:
    print(f"❌ Error in monitoring loop: {e}")
finally:
    try:
        if _lock_fd is not None:
            os.close(_lock_fd)
        if LOCK_PATH.exists():
            LOCK_PATH.unlink(missing_ok=True)
    except Exception:
        pass
