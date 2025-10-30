import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load credentials from .env file
load_dotenv()

SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_TO = os.getenv("EMAIL_TO")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = os.getenv("SMTP_PORT")

def send_email_alert(subject: str, body: str):
    """
    Sends an email alert using SMTP when a malicious or suspicious process is detected.
    Requires valid credentials in your .env file.
    """

    if not SMTP_USER or not SMTP_PASSWORD or not EMAIL_TO:
        print("⚠️ Email credentials missing in .env file. Skipping email alert.")
        return

    try:
        # Create email structure
        msg = MIMEMultipart()
        msg["From"] = SMTP_USER
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        # Connect to mail server
        with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT)) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)

        print(f"📧 Email alert sent to {EMAIL_TO}")

    except smtplib.SMTPAuthenticationError:
        print("❌ SMTP Authentication failed! Check your email or app password.")
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")
