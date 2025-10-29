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

def scan_for_malware():
    suspicious = []
    print("🔍 Scanning processes...")

    for process in psutil.process_iter(['pid', 'name']):
        try:
            name = process.info['name']
            if not name:
                continue

            name_lower = name.lower()
            print(f"Found: {name}")  # Debug

            # Skip if process is whitelisted
            if name_lower in WHITELIST:
                continue

            # Immediately flag if blacklisted
            if name_lower in BLACKLIST:
                print(f"🚨 Blacklist match: {name}")
                suspicious.append(process)
                continue

            # Check for suspicious keywords
            if any(keyword in name_lower for keyword in SUSPICIOUS_KEYWORDS):
                print(f"🚨 Suspicious keyword match: {name}")
                suspicious.append(process)
                continue

            # Behavior check: high CPU or memory usage
            cpu = process.cpu_percent(interval=0.5)
            mem = process.memory_percent()
            if cpu > 50 or mem > 30:
                print(f"⚠️ High resource usage: {name} (CPU: {cpu}%, MEM: {mem:.2f}%)")
                suspicious.append(process)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return suspicious