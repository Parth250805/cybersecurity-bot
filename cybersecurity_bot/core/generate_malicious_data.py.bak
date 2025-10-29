import csv
import random
import os
from cybersecurity_bot.config.config import DATASET_PATH

def generate_synthetic_malicious_samples(num_samples=20):
    with open(DATASET_PATH, 'a', newline='') as f:
        writer = csv.writer(f)
        for i in range(num_samples):
            pid = 10000 + i
            name = f"suspicious_{i}.exe"
            cpu_percent = random.uniform(70, 99)
            memory_percent = random.uniform(30, 60)
            num_threads = random.randint(10, 30)
            num_connections = random.randint(5, 15)
            is_suspicious = 1
            writer.writerow([pid, name, cpu_percent, memory_percent, num_threads, num_connections, is_suspicious])
    print(f"✅ Added {num_samples} synthetic malicious samples to {DATASET_PATH}")

if __name__ == "__main__":
    print(f"Current working directory: {os.getcwd()}")
    generate_synthetic_malicious_samples(20)