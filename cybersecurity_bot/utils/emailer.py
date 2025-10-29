import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

# Load credentials from .env file
load_dotenv()

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

def send_email_alert(subject: str, body: str):
    """
    Sends an email alert using SMTP when a malicious or suspicious process is detected.
    Requires valid credentials in your .env file.
    """

    if not EMAIL_SENDER or not EMAIL_PASSWORD or not EMAIL_RECEIVER:
        print("⚠️ Email credentials missing in .env file. Skipping email alert.")
        return

    try:
        # Create email structure
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        # Connect to mail server (Gmail example)
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"📧 Email alert sent to {EMAIL_RECEIVER}")

    except smtplib.SMTPAuthenticationError:
        print("❌ SMTP Authentication failed! Check your email or app password.")
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")
