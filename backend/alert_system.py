"""
Alert System for BlockVerify
Handles email alerts (SMTP) and in-app notification storage.
"""

import smtplib
import json
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List


ALERTS_FILE = "alerts.json"


def _load_alerts() -> List[dict]:
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _save_alerts(alerts: List[dict]):
    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2, default=str)


def store_alert(alert_type: str, severity: str, message: str, file_name: str = None) -> dict:
    """Persist an alert to disk and return it."""
    alerts = _load_alerts()
    alert = {
        "id": len(alerts) + 1,
        "type": alert_type,
        "severity": severity,
        "message": message,
        "file_name": file_name,
        "timestamp": datetime.utcnow().isoformat(),
        "read": False
    }
    alerts.insert(0, alert)
    _save_alerts(alerts)
    return alert


def get_alerts(unread_only: bool = False) -> List[dict]:
    alerts = _load_alerts()
    if unread_only:
        return [a for a in alerts if not a.get("read")]
    return alerts


def mark_all_read():
    alerts = _load_alerts()
    for a in alerts:
        a["read"] = True
    _save_alerts(alerts)


def send_email_alert(
    to_email: str,
    subject: str,
    body: str,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 587,
    smtp_user: str = None,
    smtp_pass: str = None
) -> bool:
    """
    Send an email alert via SMTP.
    Configure smtp_user and smtp_pass via environment variables:
      ALERT_EMAIL_USER and ALERT_EMAIL_PASS
    """
    user = smtp_user or os.environ.get("ALERT_EMAIL_USER")
    pwd  = smtp_pass or os.environ.get("ALERT_EMAIL_PASS")

    if not user or not pwd:
        print("[ALERT] Email credentials not configured — alert stored in dashboard only.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = user
        msg["To"]      = to_email

        html_body = f"""
        <html><body style="font-family:sans-serif;background:#f4f4f4;padding:24px">
          <div style="background:#fff;border-radius:8px;padding:24px;max-width:560px;margin:auto">
            <h2 style="color:#26215C;margin-top:0">BlockVerify Alert</h2>
            <p style="color:#333">{body}</p>
            <hr style="border:none;border-top:1px solid #eee">
            <small style="color:#999">BlockVerify · {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC</small>
          </div>
        </body></html>
        """
        msg.attach(MIMEText(body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(user, pwd)
            server.sendmail(user, to_email, msg.as_string())
        print(f"[ALERT] Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"[ALERT] Email failed: {e}")
        return False


def fire_tamper_alert(file_name: str, file_id: int, alert_email: str = None, diff_msg: str = ""):
    """Fire tamper detection alert — store + optionally email."""
    msg = f"TAMPER DETECTED: File '{file_name}' (ID #{file_id}) hash does not match blockchain record. Immediate review required.{diff_msg}"
    alert = store_alert("TAMPER_DETECTED", "CRITICAL", msg, file_name)
    if alert_email:
        send_email_alert(alert_email, f"[BlockVerify] TAMPER DETECTED — {file_name}", msg)
    return alert


def fire_anomaly_alert(anomaly: dict, alert_email: str = None):
    """Fire an AI anomaly alert."""
    msg = anomaly.get("message", "Anomaly detected")
    alert = store_alert(anomaly["type"], anomaly["severity"], msg, anomaly.get("file_name"))
    if alert_email:
        send_email_alert(alert_email, f"[BlockVerify] AI Alert — {anomaly['type']}", msg)
    return alert

def fire_upload_alert(file_name: str, alert_email: str = None):
    """Fire an upload success alert."""
    msg = f"Your file '{file_name}' has been successfully uploaded and secured by BlockVerify via blockchain."
    if alert_email:
        send_email_alert(alert_email, f"[BlockVerify] File Uploaded Successfully — {file_name}", msg)
    
def fire_restore_alert(file_name: str, file_id: int, alert_email: str = None):
    """Fire restore alert when file becomes safe again."""
    msg = f"FILE RESTORED: File '{file_name}' (ID #{file_id}) has been successfully verified as intact and restored."
    alert = store_alert("FILE_RESTORED", "INFO", msg, file_name)
    if alert_email:
        send_email_alert(alert_email, f"[BlockVerify] FILE RESTORED — {file_name}", msg)
    return alert
