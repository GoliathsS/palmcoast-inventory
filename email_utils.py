import smtplib
from email.message import EmailMessage
import os

# Gmail credentials
GMAIL_USER = os.getenv("noreply.palmcoast@gmail.com")
GMAIL_APP_PASSWORD = os.getenv("ayoh luhi oojh fvlc")

def send_maintenance_email(vehicle_name, due_miles):
    message = EmailMessage()
    message["From"] = GMAIL_USER
    message["To"] = "Cole@palmcoastpestcontrol.com"
    message["Subject"] = f"🚨 Oil Change Alert for {vehicle_name}"
    message.set_content(
        f"""
Hey Cole,

This is a heads-up that the vehicle **{vehicle_name}** is due for an oil change in **{due_miles} miles**.

Please schedule maintenance accordingly to stay on track.

– Palm Coast Vehicle System
""")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(message)
            print(f"✅ Email sent for {vehicle_name} ({due_miles} mi)")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
