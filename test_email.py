from cybersecurity_bot.utils.emailer import send_email_alert

# Test the email functionality
send_email_alert(
    subject="Test Email from Cybersecurity Bot",
    body="This is a test email to verify the email alerting system is working correctly."
)