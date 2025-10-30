import os
import sys
import io

# Force UTF-8 encoding for stdout
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

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

def send_status_email(status="ok", details=None):
    """Send a status email about the system state"""
    if status == "start":
        subject = "🟢 Cybersecurity Bot Started"
        body = "The Cybersecurity Bot has started monitoring your system.\n\nConfiguration:\n"
        body += f"- Monitor Interval: {MONITOR_INTERVAL} seconds\n"
        body += f"- Risk Score Threshold: {RISK_SCORE_KILL_THRESHOLD}\n"
        body += f"- Email Alerts: {'Enabled' if EMAIL_ALERTS else 'Disabled'}\n"
        body += f"- Popup Alerts: {'Enabled' if POPUP_ALERTS else 'Disabled'}\n"
    elif status == "stop":
        subject = "🔴 Cybersecurity Bot Stopped"
        body = "The Cybersecurity Bot has stopped monitoring your system.\n"
        if details:
            body += f"\nReason: {details}"
    else:  # status == "ok"
        subject = "✅ System Security Status: All Clear"
        body = "No suspicious activities detected in the last scan.\n\nSystem Status:\n"
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            body += f"- CPU Usage: {cpu}%\n"
            body += f"- Memory Usage: {memory.percent}%\n"
        except:
            body += "- System metrics unavailable\n"

    send_email_alert(subject, body)

print(f"🛡️ Cybersecurity Bot is now monitoring your system...")
if DEBUG:
    print(f"✅ Using config file: {CONFIG_PATH}")

# Send startup email
send_status_email("start")

handled_pids = set()
scan_count = 0
last_all_clear_time = 0

# === Graceful shutdown via Ctrl+C ===
stop_event = threading.Event()

def _handle_sigint(signum, frame):
    try:
        stop_event.set()
        print("\n🛑 Stopping... (Ctrl+C)")
        send_status_email("stop", "User interrupted (Ctrl+C)")
        # Force exit after 3 seconds if normal shutdown fails
        import threading
        threading.Timer(3.0, lambda: os._exit(0)).start()
    except Exception:
        os._exit(0)

try:
    signal.signal(signal.SIGINT, _handle_sigint)
except Exception:
    # On some environments signal handling may not be available; fallback to KeyboardInterrupt
    pass

# === Single-instance lock ===
LOCK_PATH = PROJECT_ROOT / ".run.lock"
_lock_fd = None
try:
    # Allow restarting by always removing stale lock file
    try:
        if LOCK_PATH.exists():
            LOCK_PATH.unlink()
    except:
        pass
    
    # Create new lock file
    try:
        _lock_fd = os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_RDWR)
    except FileExistsError:
        print("⚠️ Another instance is already running. Exiting.")
        sys.exit(0)

    # Check if this is a quick scan
    QUICK_SCAN = bool(int(os.environ.get("CSBOT_QUICK_SCAN", "0")))
    
    # === MAIN LOOP ===
    while not stop_event.is_set():
        scan_count += 1
        print(f"\n🔍 {'Quick Scan' if QUICK_SCAN else f'Starting scan #{scan_count}'}...")
        
        suspicious_processes = scan_for_malware(stop_event)
        processes_checked = 0
        
        # Count total processes for progress
        try:
            total_processes = len(list(psutil.process_iter(['pid', 'name'])))
            print(f"📊 Total processes to scan: {total_processes}")
        except:
            total_processes = 0
            print("⚠️ Could not determine total process count")

        for process in suspicious_processes:
            if stop_event.is_set():
                break
                
            processes_checked += 1
            if processes_checked % 10 == 0:  # Show progress every 10 processes
                print(f"✓ Checked {processes_checked} processes...")
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

        # Print scan completion message
        print(f"✅ Scan #{scan_count} completed! Checked {processes_checked} processes.")
        
        # If no suspicious processes were found, send all-clear email every hour
        current_time = time.time()
        if not suspicious_processes and (current_time - last_all_clear_time >= 3600):  # 3600 seconds = 1 hour
            print("🟢 No suspicious processes found!")
            send_status_email("ok")
            last_all_clear_time = current_time
        elif suspicious_processes:
            print(f"⚠️ Found {len(suspicious_processes)} suspicious processes in this scan.")

        # If quick scan, exit after one scan
        if QUICK_SCAN:
            print("\n✅ Quick scan completed!")
            break
            
        # Wait for next scan
        print(f"\n⏳ Waiting {MONITOR_INTERVAL} seconds until next scan...")
        if stop_event.wait(MONITOR_INTERVAL):
            break
except KeyboardInterrupt:
    print("\n🛑 Stopped by user.")
    send_status_email("stop", "User stopped the bot")
except Exception as e:
    error_msg = f"❌ Error in monitoring loop: {e}"
    print(error_msg)
    send_status_email("stop", error_msg)
finally:
    print("\n👋 Cybersecurity Bot shutting down...")
    try:
        if _lock_fd is not None:
            os.close(_lock_fd)
        if LOCK_PATH.exists():
            LOCK_PATH.unlink(missing_ok=True)
    except Exception:
        pass
