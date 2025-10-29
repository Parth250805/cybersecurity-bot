import psutil
import csv
import os

DATASET_FILE = 'dataset.csv'

def collect_features():
    header = ['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'num_connections', 'is_suspicious']
    
    # Create the CSV file with header if it doesn't exist
    if not os.path.exists(DATASET_FILE):
        with open(DATASET_FILE, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(header)

    with open(DATASET_FILE, 'a', newline='') as file:
        writer = csv.writer(file)
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                p = psutil.Process(pid)
                
                cpu = p.cpu_percent(interval=0.1)
                mem = p.memory_percent()
                threads = p.num_threads()
                connections = len(p.connections())

                # You can later label these (0 = safe, 1 = malware)
                is_suspicious = 0  

                writer.writerow([pid, name, cpu, mem, threads, connections, is_suspicious])

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

if __name__ == "__main__":
    print("Collecting process features...")
    collect_features()
    print("✅ Data written to dataset.csv")
