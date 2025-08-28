import os
import smtplib
from email.message import EmailMessage
from email.utils import make_msgid, formatdate
from datetime import datetime, timedelta, date, timezone
from dotenv import load_dotenv

load_dotenv()

GMAIL_USER = os.getenv("GMAIL_USER")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://palmcoast-inventory.onrender.com")
BRAND_PRIMARY = os.getenv("BRAND_PRIMARY", "#14532d")   # Palm Coast green
BRAND_INK = os.getenv("BRAND_INK", "#0b1220")

RECIPIENTS = [
    "Cole@palmcoastpestcontrol.com",
    "Scott@palmcoastpestcontrol.com",
    "Victoria@palmcoastpestcontrol.com",
    "Todd@palmcoastpestcontrol.com",
]

def _severity(current_miles: int, due_miles: int) -> str:
    if current_miles >= due_miles:
        return "OVERDUE"
    gap = due_miles - current_miles
    if gap <= 500:
        return "Due Soon"
    return "Upcoming"

def _subject(vehicle_name: str, due_miles: int, current_miles: int) -> str:
    sev = _severity(current_miles, due_miles)
    delta = due_miles - current_miles
    if sev == "OVERDUE":
        return f"Oil Change OVERDUE — {vehicle_name} (due at {due_miles:,} mi)"
    return f"Oil Change {sev} — {vehicle_name} ({delta:,} mi to {due_miles:,})"

def _build_plaintext(vehicle_name, due_miles, current_miles, plate, action_link):
    plate_line = f"Plate: {plate}\n" if plate else ""
    sev = _severity(current_miles, due_miles)
    return f"""Palm Coast Maintenance Tracker

Status: {sev}
Vehicle: {vehicle_name}
{plate_line}Current Mileage: {current_miles:,}
Due At: {due_miles:,} miles

Please schedule service and mark completion:
{action_link}

If this has been completed, click the link above to update the record.
"""

def _build_html(vehicle_name, due_miles, current_miles, plate, action_link, logo_cid):
    sev = _severity(current_miles, due_miles)
    delta = max(due_miles - current_miles, 0)
    sev_bg = "#b93815" if sev == "OVERDUE" else ("#b45309" if delta <= 500 else "#0f766e")
    sev_fg = "#ffffff"

    plate_html = f"""
      <tr>
        <td style="padding:6px 0;font-size:14px;color:{BRAND_INK};">
          <strong>Plate:</strong> {plate}
        </td>
      </tr>""" if plate else ""

    preheader = f"{vehicle_name} oil change {sev.lower()}. Current: {current_miles:,} mi. Due at {due_miles:,}."

    # table-based, inline CSS for broad client support
    return f"""\
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="color-scheme" content="light only">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Oil Change Reminder</title>
</head>
<body style="margin:0;padding:0;background:#f4f4f4;">
  <!-- Preheader (hidden) -->
  <div style="display:none;font-size:1px;color:#f4f4f4;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;">
    {preheader}
  </div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;">
    <tr>
      <td align="center" style="padding:24px 12px;">
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;background:#ffffff;border-radius:8px;">
          <tr>
            <td align="center" style="padding:24px 24px 8px 24px;">
              <img src="cid:{logo_cid}" alt="Palm Coast Pest Control" width="180" style="display:block;border:0;outline:none;text-decoration:none;margin:0 auto 8px auto;">
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:22px;color:{BRAND_INK};font-weight:700;margin-top:6px;">
                Oil Change Reminder
              </div>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding:8px 24px 0 24px;">
              <span style="display:inline-block;background:{sev_bg};color:{sev_fg};font-family:Arial,Helvetica,sans-serif;font-size:12px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;padding:6px 10px;border-radius:999px;">
                {sev}
              </span>
            </td>
          </tr>

          <tr>
            <td style="padding:18px 24px 0 24px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,Helvetica,sans-serif;">
                <tr>
                  <td style="padding:6px 0;font-size:14px;color:{BRAND_INK};">
                    <strong>Vehicle:</strong> {vehicle_name}
                  </td>
                </tr>
                {plate_html}
                <tr>
                  <td style="padding:6px 0;font-size:14px;color:{BRAND_INK};">
                    <strong>Current Mileage:</strong> {current_miles:,}
                  </td>
                </tr>
                <tr>
                  <td style="padding:6px 0 12px 0;font-size:14px;color:{BRAND_INK};">
                    <strong>Due At:</strong> {due_miles:,} miles
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding:6px 24px 24px 24px;">
              <!-- Bulletproof button -->
              <table role="presentation" cellspacing="0" cellpadding="0">
                <tr>
                  <td bgcolor="{BRAND_PRIMARY}" style="border-radius:6px;">
                    <a href="{action_link}" target="_blank"
                       style="font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:700;line-height:44px;color:#ffffff;text-decoration:none;padding:0 18px;display:inline-block;border-radius:6px;">
                       Mark as Completed
                    </a>
                  </td>
                </tr>
              </table>
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#667085;margin-top:10px;">
                If the button doesn’t work, paste this link into your browser:<br>
                <span style="word-break:break-all;color:#475467;">{action_link}</span>
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:0 24px 24px 24px;">
              <hr style="border:none;border-top:1px solid #e6e7ec;margin:0 0 16px 0;">
              <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#475467;">
                Please schedule service to keep the vehicle in top condition. If service has already been completed,
                mark it done to clear this reminder.
              </p>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding:0 24px 24px 24px;">
              <div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#98a2b3;">
                Palm Coast Pest Control • (561) 250-6261
              </div>
            </td>
          </tr>
        </table>
        <div style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#98a2b3;margin-top:12px;">
          Sent {formatdate(localtime=True)}
        </div>
      </td>
    </tr>
  </table>
</body>
</html>
"""

def _ics_for_tomorrow(vehicle_name: str, action_link: str) -> str:
    from datetime import datetime, timedelta, date, timezone
    today = date.today()
    dtstart = (today + timedelta(days=1)).strftime("%Y%m%d")
    dtend = (today + timedelta(days=2)).strftime("%Y%m%d")
    uid = f"{int(datetime.now(timezone.utc).timestamp())}-{vehicle_name.replace(' ', '')}@palmcoast"
    now = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    desc = f"Schedule oil change for {vehicle_name}. Update status: {action_link}"

    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Palm Coast//Maintenance//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{now}",
        f"SUMMARY:Schedule Oil Change — {vehicle_name}",
        f"DESCRIPTION:{desc}",
        f"DTSTART;VALUE=DATE:{dtstart}",
        f"DTEND;VALUE=DATE:{dtend}",
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    return "\r\n".join(lines) + "\r\n"

def send_maintenance_email(vehicle_id: int, vehicle_name: str, due_miles: int, current_miles: int, license_plate: str | None = None):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise RuntimeError("Missing GMAIL_USER or GMAIL_APP_PASSWORD")

    # Deep link to your app (adjust route as needed)
    action_link = f"{APP_BASE_URL}/vehicles/{vehicle_id}#maintenance"

    logo_cid = make_msgid(domain="palmcoastpestcontrol.com")[1:-1]  # strip <>

    msg = EmailMessage()
    msg["From"] = GMAIL_USER
    msg["To"] = ", ".join(RECIPIENTS)
    msg["Subject"] = _subject(vehicle_name, due_miles, current_miles)
    msg["Date"] = formatdate(localtime=True)
    msg["X-Priority"] = "2"  # high-ish, but not urgent
    msg["Importance"] = "High"

    # Plain text (fallback)
    msg.set_content(_build_plaintext(vehicle_name, due_miles, current_miles, license_plate, action_link))

    # HTML alternative + inline logo (add_related must target the HTML part right after creation)
    html = _build_html(vehicle_name, due_miles, current_miles, license_plate, action_link, logo_cid)
    msg.add_alternative(html, subtype="html")
    try:
        with open("Logo.png", "rb") as img:
            # HTML part is the last payload we just added
            msg.get_payload()[-1].add_related(img.read(), maintype="image", subtype="png", cid=f"<{logo_cid}>")
    except FileNotFoundError:
        # Safe to continue without logo
        pass

    # Optional: attach .ics calendar file (nice touch)
    ics = _ics_for_tomorrow(vehicle_name, action_link)
    msg.add_attachment(
        ics,  # str payload
        subtype="calendar",
        filename="oil-change-reminder.ics",
        params={"method": "PUBLISH", "name": "oil-change-reminder.ics"},
        headers=["Content-Class: urn:content-classes:calendarmessage"]  # <-- string header, not tuple
    )

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)
            print(f"✅ Email sent: {vehicle_name} ({_severity(current_miles, due_miles)})")
    except Exception as e:
        print(f"❌ Error sending email: {e}")
