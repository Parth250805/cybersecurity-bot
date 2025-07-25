import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "parthmasurkar205@gmail.com"
SMTP_PASSWORD = "mwsh hbjn gsub lgsj"  # App password from Google

def send_email_alert(subject, body):
    print("📧 Connecting to Gmail SMTP server...")

    try:
        # Setup the email
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = SMTP_USERNAME
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Connect to SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        print("✅ Logged in successfully!")

        server.send_message(msg)
        server.quit()
        print("📨 Email sent successfully!")

    except smtplib.SMTPAuthenticationError as e:
        print(f"❌ Authentication error: {e}")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
