import psutil

# Whitelist: trusted known processes (case-insensitive)
WHITELIST = {
    # Windows System Processes
    "svchost.exe", "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "smss.exe", "system", "explorer.exe", "dwm.exe", "fontdrvhost.exe",
    "conhost.exe", "taskhostw.exe", "spoolsv.exe", "SearchIndexer.exe",
    "RuntimeBroker.exe", "SecurityHealthService.exe", "ctfmon.exe",

    # Browsers & Productivity
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
    "teams.exe", "onedrive.exe", "outlook.exe", "word.exe", "excel.exe",
    "powerpnt.exe", "notepad.exe", "notepad++.exe",

    # Developer Tools
    "code.exe",  # VS Code
    "pycharm64.exe", "sublime_text.exe", "atom.exe",
    "python.exe", "node.exe", "java.exe", "git.exe",

    # Command Line & Shells
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "wsl.exe",

    # Background & Services
    "vmware-vmx.exe", "vmware-tray.exe", "vmware-hostd.exe",
    "Dropbox.exe", "slack.exe", "zoom.exe"
}


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

            # Check for suspicious keywords
            if any(keyword in name_lower for keyword in SUSPICIOUS_KEYWORDS):
                print(f"🚨 Suspicious keyword match: {name}")
                suspicious.append(process)
                continue

            # Optional behavior check: high CPU or memory usage
            cpu = process.cpu_percent(interval=0.5)
            mem = process.memory_percent()
            if cpu > 50 or mem > 30:
                print(f"⚠️ High resource usage: {name} (CPU: {cpu}%, MEM: {mem:.2f}%)")
                suspicious.append(process)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return suspicious
