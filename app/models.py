from __future__ import annotations

import secrets
from datetime import datetime, timezone

from .extensions import db


def utcnow() -> datetime:
    """Timezone-aware UTC timestamps."""
    return datetime.now(timezone.utc)


def new_webauthn_user_id() -> bytes:
    """Stable, non-PII WebAuthn user handle (32 random bytes)."""
    return secrets.token_bytes(32)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)

    # Stable WebAuthn user handle 
    webauthn_user_id = db.Column(db.LargeBinary(32), unique=True, nullable=False, default=new_webauthn_user_id)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    credentials = db.relationship("Credential", back_populates="user", cascade="all,delete-orphan")


class Credential(db.Model):
    __tablename__ = "credentials"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user = db.relationship("User", back_populates="credentials")

    # Store as base64url strings (easy to JSON/debug)
    credential_id = db.Column(db.Text, unique=True, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False, default=0)

    transports = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    event_type = db.Column(db.String(64), nullable=False)
    outcome = db.Column(db.String(16), nullable=False)  # e.g., SUCCESS / FAIL

    user_id = db.Column(db.Integer, nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)

    message = db.Column(db.Text, nullable=True)
    meta = db.Column(db.JSON, nullable=True)
