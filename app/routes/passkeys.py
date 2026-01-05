import base64
import json
import logging

import redis
from flask import Blueprint, current_app, jsonify, render_template, request
from webauthn import (
    base64url_to_bytes,
    generate_registration_options,
    options_to_json,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    RegistrationCredential,
    UserVerificationRequirement,
)

from ..extensions import db
from ..models import AuditLog, Credential, User

bp = Blueprint("passkeys", __name__)
log = logging.getLogger(__name__)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _extract_challenge_b64_from_client_data(client_data_b64: str) -> str:
    """Decode clientDataJSON (base64url) and extract the challenge (base64url string)."""
    padded = client_data_b64 + "=" * (-len(client_data_b64) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    obj = json.loads(raw.decode("utf-8"))
    challenge = obj.get("challenge")
    if not challenge or not isinstance(challenge, str):
        raise ValueError("clientDataJSON.challenge missing/invalid")
    return challenge


@bp.get("/demo/passkeys")
def demo_passkeys():
    return render_template("passkeys_demo.html")


@bp.post("/register/start")
def register_start():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()

    rp_id = current_app.config["WEBAUTHN_RP_ID"]
    rp_name = current_app.config["WEBAUTHN_RP_NAME"]
    ttl = int(current_app.config["WEBAUTHN_CHALLENGE_TTL_SECONDS"])

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user.webauthn_user_id,
        user_name=user.email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )

    # Store a server-issued challenge context keyed by the challenge itself.
    # This lets /register/finish find the user without trusting any user_id/email echoed back.
    challenge_b64 = _b64url_encode(options.challenge)
    r = redis.Redis.from_url(current_app.config["REDIS_URL"], decode_responses=True)
    r.setex(f"webauthn:reg_chal:{challenge_b64}", ttl, str(user.id))

    db.session.add(
        AuditLog(
            event_type="WEBAUTHN_REGISTER_START",
            outcome="SUCCESS",
            user_id=user.id,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            message="Issued WebAuthn registration challenge",
            meta={"rp_id": rp_id, "ttl_seconds": ttl},
        )
    )
    db.session.commit()

    # Return options JSON (as dict)
    return jsonify(json.loads(options_to_json(options)))


@bp.post("/register/finish")
def register_finish():
    raw_body = request.get_json(silent=True) or {}
    client_data_b64 = (raw_body.get("response") or {}).get("clientDataJSON")
    if not client_data_b64:
        return jsonify({"error": "response.clientDataJSON required"}), 400

    try:
        challenge_b64 = _extract_challenge_b64_from_client_data(client_data_b64)
    except Exception as e:
        return jsonify({"error": f"invalid clientDataJSON: {e}"}), 400

    r = redis.Redis.from_url(current_app.config["REDIS_URL"], decode_responses=True)
    key = f"webauthn:reg_chal:{challenge_b64}"
    user_id_str = r.get(key)

    if not user_id_str:
        return jsonify({"error": "challenge missing/expired (replay rejected)"}), 400

    # Parse credential and verify cryptographically
    try:
        credential = RegistrationCredential.parse_obj(raw_body)
    except Exception as e:
        return jsonify({"error": f"invalid credential payload: {e}"}), 400

    expected_origin = current_app.config["WEBAUTHN_ORIGIN"]
    expected_rp_id = current_app.config["WEBAUTHN_RP_ID"]

    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_origin=expected_origin,
            expected_rp_id=expected_rp_id,
            require_user_verification=True,
        )
    except Exception as e:
        db.session.add(
            AuditLog(
                event_type="WEBAUTHN_REGISTER_FINISH",
                outcome="FAIL",
                user_id=int(user_id_str),
                ip=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                message="Registration verification failed",
                meta={"error": str(e)},
            )
        )
        db.session.commit()
        return jsonify({"error": f"verification failed: {e}"}), 400

    # ONE-TIME challenge consumption after successful verification.
    deleted = r.delete(key)
    if deleted != 1:
        return jsonify({"error": "challenge already used (replay rejected)"}), 400

    user = User.query.get(int(user_id_str))
    if not user:
        return jsonify({"error": "user missing"}), 500

    credential_id_b64 = _b64url_encode(verification.credential_id)
    public_key_b64 = _b64url_encode(verification.credential_public_key)
    sign_count = int(verification.sign_count)

    # Prevent duplicates
    existing = Credential.query.filter_by(credential_id=credential_id_b64).first()
    if existing:
        return jsonify({"error": "credential already registered"}), 409

    transports = raw_body.get("transports")
    transports_str = ",".join(transports) if isinstance(transports, list) else None

    db.session.add(
        Credential(
            user_id=user.id,
            credential_id=credential_id_b64,
            public_key=public_key_b64,
            sign_count=sign_count,
            transports=transports_str,
        )
    )

    db.session.add(
        AuditLog(
            event_type="WEBAUTHN_REGISTER_FINISH",
            outcome="SUCCESS",
            user_id=user.id,
            ip=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            message="Stored credential after successful verification",
            meta={"credential_id": credential_id_b64, "sign_count": sign_count},
        )
    )
    db.session.commit()

    return jsonify({"status": "ok", "user_id": user.id, "credential_id": credential_id_b64})


@bp.get("/passkeys/credentials")
def list_credentials():
    """Debug endpoint to prove persistence for evidence capture."""
    rows = (
        db.session.query(Credential, User)
        .join(User, User.id == Credential.user_id)
        .order_by(Credential.created_at.desc())
        .limit(25)
        .all()
    )
    out = []
    for cred, user in rows:
        out.append(
            {
                "user_id": user.id,
                "email": user.email,
                "credential_id": cred.credential_id,
                "sign_count": cred.sign_count,
                "created_at": cred.created_at.isoformat(),
            }
        )
    return jsonify(out)
