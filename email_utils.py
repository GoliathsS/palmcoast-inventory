import smtplib
from email.message import EmailMessage
from email.utils import make_msgid
import os
from dotenv import load_dotenv

load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

def send_maintenance_email(vehicle_id, vehicle_name, due_miles, current_miles, license_plate=None):
    message = EmailMessage()
    message["From"] = GMAIL_USER
    message["To"] = ", ".join([
        "Cole@palmcoastpestcontrol.com",
        "Scott@palmcoastpestcontrol.com"
    ])
    message["Subject"] = f"🚛 Oil Change Reminder: {vehicle_name} ({due_miles} mi due)"

    # Content ID for the embedded logo image
    logo_cid = make_msgid(domain="palmcoastpestcontrol.com")[1:-1]  # strip <> from cid

    plate_line_text = f"• Plate: {license_plate}" if license_plate else ""
    plate_line_html = f"<strong>Plate:</strong> {license_plate}<br>" if license_plate else ""

    # Plain text fallback
    message.set_content(f"""
Hi Cole,

This is your automated reminder from the Palm Coast Vehicle System 🚨

The vehicle {vehicle_name} is approaching its oil change interval.

–––––––––––––––––––––––––
📍 Vehicle: {vehicle_name}
{plate_line_text}
📊 Current Mileage: {current_miles}
🛠️ Due At: {due_miles} miles
–––––––––––––––––––––––––

Please schedule service soon to keep everything running smoothly.

If the oil has already been changed, you can mark this task as complete in the system.

Thanks,
– Palm Coast Maintenance Tracker
""")

    # HTML version with logo
    message.add_alternative(f"""
<html>
  <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <div style="max-width: 600px; margin: auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
      <div style="text-align: center;">
        <img src="cid:{logo_cid}" alt="Palm Coast Logo" style="max-width: 180px; margin-bottom: 20px;">
      </div>
      <h2 style="text-align: center; color: #2e6da4;">🚛 Oil Change Reminder</h2>
      <p>Hi Cole,</p>
      <p>This is your automated reminder from the <strong>Palm Coast Vehicle System</strong> 🔧</p>

      <hr>
      <p style="font-size: 15px;">
        📍 <strong>Vehicle:</strong> {vehicle_name}<br>
        {plate_line_html}
        📊 <strong>Current Mileage:</strong> {current_miles}<br>
        🛠️ <strong>Due At:</strong> {due_miles} miles
      </p>
      <hr>

      <p>Please schedule service soon to keep everything running smoothly.</p>
      <p>If the oil has already been changed, you can mark this task as complete in the system.</p>

      <p style="margin-top: 30px;">Thanks,<br><em>Palm Coast Maintenance Tracker</em></p>
    </div>
  </body>
</html>
""", subtype='html')

    # Embed the logo image
    with open("Logo.png", "rb") as img:
        message.get_payload()[1].add_related(
            img.read(),
            maintype='image',
            subtype='png',
            cid=f"<{logo_cid}>"
        )

    # Send the email
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(message)
            print(f"✅ Email sent for {vehicle_name} (due at {due_miles} mi)")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
