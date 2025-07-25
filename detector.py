# detector.py
import psutil

# List of suspicious (fake malware) process names
BLACKLIST = [
    "fakechrome.exe", "malware.exe", "ransomware.exe", "keylogger.exe",
    "stealer.exe", "hackerapp.exe", "rattool.exe", "spywareagent.exe",
    "darkwebloader.exe", "trojanhorse.exe", "cryptojacker.exe",
    "infoleak.exe", "fakeupdater.exe", "phishkit.exe", "cmdinjector.exe"
]

def scan_for_malware():
    suspicious_processes = []

    for process in psutil.process_iter(['pid', 'name']):
        try:
            name = process.info['name'].lower()
            if name in BLACKLIST:
                suspicious_processes.append({
                    'pid': process.info['pid'],
                    'name': name
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return suspicious_processes
