import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Gmail credentials
GMAIL_USER = "noreply.palmcoast@gmail.com"
GMAIL_APP_PASSWORD = "ayoh luhi oojh fvlc"  # Replace with your actual 16-char app password

def send_maintenance_email(vehicle_name, due_miles):
    recipient = "Cole@palmcoastpestcontrol.com"
    subject = f"🛠️ Oil Change Alert: {vehicle_name} is due in {due_miles} miles"
    
    body = f"""
    <h2>Oil Change Alert</h2>
    <p><strong>{vehicle_name}</strong> is due for an oil change in <strong>{due_miles} miles</strong>.</p>
    <p>Please schedule maintenance as soon as possible to keep the vehicle in good condition.</p>
    """

    message = MIMEMultipart()
    message["From"] = GMAIL_USER
    message["To"] = recipient
    message["Subject"] = subject
    message.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(message)
            print(f"✅ Email sent for {vehicle_name} ({due_miles} mi)")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
