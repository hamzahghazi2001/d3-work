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
    msg["Subject"] = "Test Email"
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
            message="Sent test email via Mailpit",
            meta={"to": "you@example.com"},
        )
    )
    db.session.commit()

    return jsonify({"status": "ok", "message": "Email sent. Check Mailpit UI."})


@bp.post("/debug/seed-credential")
def seed_credential():
    """
    Insert a dummy credential row for a given user_id so /login/start 
    This does NOT enable real login success (that still needs a real authenticator).
    """
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id")
    credential_id = body.get("credential_id")  
    public_key = body.get("public_key")       
    sign_count = int(body.get("sign_count", 0))

    if not user_id or not credential_id or not public_key:
        return jsonify({"error": "missing_fields"}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    cred = Credential(
        user_id=user.id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=sign_count,
        transports=[],
    )
    db.session.add(cred)
    db.session.commit()
    return jsonify({"status": "ok", "credential_db_id": cred.id})
