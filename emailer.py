import smtplib
from email.mime.text import MIMEText

def send_email_alert(subject, body):
    SMTP_SERVER = "smtp.office365.com"
    SMTP_PORT = 587
    SMTP_USERNAME = "parth205masurkar@outlook.com"
    SMTP_PASSWORD = "Parth@250805"  # Use app password if 2FA is enabled

    sender = SMTP_USERNAME
    receiver = "your_email@outlook.com"  # You can change this to any recipient

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
            print("📧 Email alert sent!")
    except Exception as e:
        print("❌ Failed to send email:", e)
