from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "config.yaml"
import psutil
import yaml

# Load config.yaml for whitelist and blacklist
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

WHITELIST = set(name.lower() for name in config.get("whitelist", []))
BLACKLIST = set(name.lower() for name in config.get("blacklist", []))

# Keywords common in malware names
SUSPICIOUS_KEYWORDS = [
    "malware", "keylogger", "stealer", "ransom",
    "rat", "spy", "inject", "virus", "hack", "ddos",
]

def scan_for_malware(stop_event=None):
    suspicious = []
    # Verbose by default; set CSBOT_DEBUG=0 to silence
    DEBUG = True
    try:
        import os as _os
        DEBUG = bool(int(_os.environ.get("CSBOT_DEBUG", "1")))
    except Exception:
        DEBUG = True
    if DEBUG:
        print("🔍 Scanning processes...")

    for process in psutil.process_iter(['pid', 'name']):
        if stop_event is not None and getattr(stop_event, 'is_set', lambda: False)():
            break
        try:
            name = process.info['name']
            if not name:
                continue

            name_lower = name.lower()
            if DEBUG:
                print(f"Found: {name}")

            # Skip if process is whitelisted
            if name_lower in WHITELIST:
                continue

            # Immediately flag if blacklisted
            if name_lower in BLACKLIST:
                if DEBUG:
                    print(f"🚨 Blacklist match: {name}")
                suspicious.append(process)
                continue

            # Check for suspicious keywords
            if any(keyword in name_lower for keyword in SUSPICIOUS_KEYWORDS):
                if DEBUG:
                    print(f"🚨 Suspicious keyword match: {name}")
                suspicious.append(process)
                continue

            # Behavior check: high CPU or memory usage
            # Use non-blocking CPU sampling to avoid long sleeps during cancellation
            cpu = process.cpu_percent(interval=0.0)
            mem = process.memory_percent()
            if cpu > 50 or mem > 30:
                if DEBUG:
                    print(f"⚠️ High resource usage: {name} (CPU: {cpu}%, MEM: {mem:.2f}%)")
                suspicious.append(process)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return suspicious