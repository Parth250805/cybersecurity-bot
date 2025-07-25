from datetime import datetime

def log_detection(message):
    with open("detection_log.txt", "a", encoding="utf-8") as file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"[{timestamp}] {message}\n")
