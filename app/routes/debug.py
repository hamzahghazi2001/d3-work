import logging
import smtplib
from email.message import EmailMessage
from flask import Blueprint, jsonify, request

from ..config import Config
from ..extensions import db
from ..models import AuditLog

bp = Blueprint("debug", __name__)
logger = logging.getLogger(__name__)


@bp.route("/debug/send-test-email")
def send_test_email():
    msg = EmailMessage()
    msg["Subject"] = "Phase 1 Test Email"
    msg["From"] = "test@local"
    msg["To"] = "you@example.com"
    msg.set_content("If you see this in Mailpit, SMTP is working.")

    with smtplib.SMTP(Config.MAILPIT_HOST, Config.MAILPIT_SMTP_PORT) as s:
        s.send_message(msg)

    db.session.add(
        AuditLog(
            event_type="TEST_EMAIL_SENT",
            outcome="SUCCESS",
            user_id=None,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            message="Sent Phase 1 test email via Mailpit",
            meta={"to": "you@example.com"},
        )
    )
    db.session.commit()

    return jsonify({"status": "ok", "message": "Email sent. Check Mailpit UI."})
