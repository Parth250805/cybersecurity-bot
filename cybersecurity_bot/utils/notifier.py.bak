# notifier.py
from plyer import notification

def send_alert(process_name, pid):
    message = f"{process_name} (PID: {pid})"

    # Show pop-up notification
    notification.notify(
        title="⚠️ Malware Alert Detected!",
        message=message,
        timeout=5  # seconds
    )
