import csv
import random
import os
from cybersecurity_bot.config.config import DATASET_PATH

def generate_synthetic_benign_samples(num_samples=20):
    safe_names = [
        "chrome.exe", "explorer.exe", "cmd.exe", "notepad.exe", "powershell.exe",
        "python.exe", "svchost.exe", "firefox.exe", "msedge.exe", "onedrive.exe",
        "outlook.exe", "teams.exe", "dwm.exe", "winlogon.exe"
    ]
    with open(DATASET_PATH, 'a', newline='') as f:
        writer = csv.writer(f)
        for i in range(num_samples):
            pid = 20000 + i
            name = random.choice(safe_names)
            cpu_percent = random.uniform(0, 10)
            memory_percent = random.uniform(0, 5)
            num_threads = random.randint(1, 15)
            num_connections = random.randint(0, 3)
            is_suspicious = 0
            writer.writerow([pid, name, cpu_percent, memory_percent, num_threads, num_connections, is_suspicious])
    print(f"✅ Added {num_samples} synthetic benign samples to {DATASET_PATH}")

if __name__ == "__main__":
    print(f"Current working directory: {os.getcwd()}")
    generate_synthetic_benign_samples(20)