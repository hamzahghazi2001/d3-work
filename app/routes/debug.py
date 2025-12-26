import logging
import smtplib
from email.message import EmailMessage
from flask import Blueprint, jsonify

from ..config import Config
from ..extensions import db
from ..models import AuditLog

bp = Blueprint("debug", __name__)
log = logging.getLogger("debug")

@bp.get("/debug/send-test-email")
def send_test_email():
    msg = EmailMessage()
    msg["From"] = "noreply@example.test"
    msg["To"] = "test@example.test"
    msg["Subject"] = "Phase 1 Mailpit Test"
    msg.set_content("If you see this in Mailpit, SMTP is wired correctly.")

    with smtplib.SMTP(Config.MAILPIT_HOST, Config.MAILPIT_SMTP_PORT) as s:
        s.send_message(msg)

    log.info("TEST_EMAIL_SENT to Mailpit SMTP")
    db.session.add(AuditLog(event_type="TEST_EMAIL_SENT", message="Sent Phase 1 test email via Mailpit"))
    db.session.commit()

    return jsonify(sent=True)
