from plyer import notification


def send_alert(process_name: str, pid: int):
    """
    Displays a desktop notification when a suspicious process is detected.
    """

    try:
        title = "⚠️ Malware Alert!"
        message = f"Suspicious process detected:\n{process_name} (PID: {pid})"

        notification.notify(
            title=title,
            message=message,
            app_name="Cybersecurity Bot",
            timeout=10,  # seconds
        )

        print(f"🔔 Popup alert shown for {process_name} (PID: {pid})")

    except Exception as e:
        print(f"❌ Failed to show notification: {e}")

