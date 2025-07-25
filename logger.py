# logger.py

def log_detection(process_name, pid):
    with open("detection.log", "a") as log_file:
        log_file.write(f"Suspicious process: {process_name} (PID: {pid})\n")
