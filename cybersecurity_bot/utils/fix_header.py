# fix_header.py
from cybersecurity_bot.config.config import DATASET_PATH

header = 'pid,name,cpu_percent,memory_percent,num_threads,num_connections,is_suspicious\n'

def add_header_if_missing():
    with open(DATASET_PATH, 'r+') as f:
        content = f.read()
        if not content.startswith('pid,'):
            print("Header missing. Adding header to dataset.csv")
            f.seek(0)
            f.write(header + content)
        else:
            print("Header already present.")

if __name__ == "__main__":
    add_header_if_missing()