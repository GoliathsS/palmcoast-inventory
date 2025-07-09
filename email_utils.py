import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv

load_dotenv()

# Load credentials from environment variables
GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

def send_maintenance_email(vehicle_name, due_miles, current_miles, license_plate=None):
    message = EmailMessage()
    message["From"] = GMAIL_USER
    message["To"] = "Cole@palmcoastpestcontrol.com"
    message["Subject"] = f"🚛 Oil Change Reminder: {vehicle_name} ({due_miles} mi due)"

    # Optional license plate display
    plate_line = f"• Plate: {license_plate}" if license_plate else ""

    message.set_content(f"""
Hi Cole,

This is your automated reminder from the Palm Coast Vehicle System 🚨

The vehicle **{vehicle_name}** is approaching its oil change interval.

–––––––––––––––––––––––––
📍 Vehicle: {vehicle_name}
{plate_line}
📊 Current Mileage: {current_miles}
🛠️ Due At: {due_miles} miles
–––––––––––––––––––––––––

Please schedule service soon to keep everything running smoothly.

If the oil has already been changed, you can mark this task as complete in the system.

Thanks,
– Palm Coast Maintenance Tracker
""")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(message)
            print(f"✅ Email sent for {vehicle_name} (due at {due_miles} mi)")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
