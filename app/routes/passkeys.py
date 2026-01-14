import base64
import json
import logging
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import AuthenticationCredential
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

@bp.post("/login/start")
def login_start():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "missing_email"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    creds = Credential.query.filter_by(user_id=user.id).all()
    if not creds:
        return jsonify({"error": "no_credentials_for_user"}), 404

    allow_creds = []
    for c in creds:
        allow_creds.append(
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(c.credential_id),
                type=PublicKeyCredentialType.PUBLIC_KEY,
                transports=c.transports or [],
            )
        )

    options = generate_authentication_options(
        rp_id=current_app.config["WEBAUTHN_RP_ID"],
        allow_credentials=allow_creds,
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )

    challenge_b64 = options.challenge
    redis_client = redis.Redis.from_url(current_app.config["REDIS_URL"], decode_responses=True)

    key = f"webauthn:auth_chal:{challenge_b64}"
    redis_client.setex(
        key,
        current_app.config["WEBAUTHN_AUTH_CHALLENGE_TTL_SECONDS"],
        json.dumps({"user_id": user.id, "email": user.email}, separators=(",", ":")),
    )

    db.session.add(AuditLog(
        event_type="WEBAUTHN_LOGIN_START",
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        details={"challenge_key": "stored", "ttl_s": current_app.config["WEBAUTHN_AUTH_CHALLENGE_TTL_SECONDS"]},
    ))
    db.session.commit()

    return jsonify(options.model_dump())


@bp.post("/login/finish")
def login_finish():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    challenge_b64 = body.get("challenge_b64")
    assertion = body.get("assertion")  # SimpleWebAuthn response object

    if not email or not challenge_b64 or not assertion:
        return jsonify({"error": "missing_fields"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "user_not_found"}), 404

    redis_client = redis.Redis.from_url(current_app.config["REDIS_URL"], decode_responses=True)
    key = f"webauthn:auth_chal:{challenge_b64}"
    stored = redis_client.get(key)
    if not stored:
        db.session.add(AuditLog(
            event_type="WEBAUTHN_LOGIN_FAIL",
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            details={"reason": "challenge_missing_or_expired"},
        ))
        db.session.commit()
        return jsonify({"error": "challenge_missing_or_expired"}), 400

    stored_ctx = json.loads(stored)
    if stored_ctx.get("user_id") != user.id:
        db.session.add(AuditLog(
            event_type="WEBAUTHN_LOGIN_FAIL",
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            details={"reason": "challenge_user_mismatch"},
        ))
        db.session.commit()
        return jsonify({"error": "challenge_user_mismatch"}), 400

    cred_id_b64 = assertion.get("id")
    if not cred_id_b64:
        return jsonify({"error": "missing_credential_id"}), 400

    cred = Credential.query.filter_by(user_id=user.id, credential_id=cred_id_b64).first()
    if not cred:
        db.session.add(AuditLog(
            event_type="WEBAUTHN_LOGIN_FAIL",
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            details={"reason": "unknown_credential"},
        ))
        db.session.commit()
        return jsonify({"error": "unknown_credential"}), 400

    try:
        credential = AuthenticationCredential.parse_raw(json.dumps(assertion))

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_origin=current_app.config["WEBAUTHN_ORIGIN"],
            expected_rp_id=current_app.config["WEBAUTHN_RP_ID"],
            credential_public_key=base64url_to_bytes(cred.public_key),
            credential_current_sign_count=cred.sign_count,
            require_user_verification=False,
        )
    except Exception as e:
        db.session.add(AuditLog(
            event_type="WEBAUTHN_LOGIN_FAIL",
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            details={"reason": "assertion_verify_failed"},
        ))
        db.session.commit()
        return jsonify({"error": "assertion_verify_failed"}), 400

    # Update sign_count
    cred.sign_count = verification.new_sign_count
    db.session.add(cred)

    # Anti-replay: delete challenge key after success
    redis_client.delete(key)

    # Create session (server-side, Redis)
    sid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    redis_client.setex(
        f"session:{sid}",
        current_app.config["SESSION_TTL_SECONDS"],
        json.dumps({"user_id": user.id, "last_auth_at": now, "created_at": now}, separators=(",", ":")),
    )

    db.session.add(AuditLog(
        event_type="WEBAUTHN_LOGIN_SUCCESS",
        user_id=user.id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent"),
        details={"session": "created", "last_auth_at": now},
    ))
    db.session.commit()

    resp = jsonify({"status": "ok"})
    resp.set_cookie(
        current_app.config["SESSION_COOKIE_NAME"],
        sid,
        httponly=True,
        samesite="Lax",
    )
    return resp
@bp.get("/logout")
def logout():
    sid = request.cookies.get(current_app.config["SESSION_COOKIE_NAME"])
    if sid:
        redis_client = redis.Redis.from_url(current_app.config["REDIS_URL"], decode_responses=True)
        sess = redis_client.get(f"session:{sid}")
        redis_client.delete(f"session:{sid}")

        user_id = None
        if sess:
            try:
                user_id = json.loads(sess).get("user_id")
            except Exception:
                pass

        db.session.add(AuditLog(
            event_type="LOGOUT_SUCCESS",
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            details={},
        ))
        db.session.commit()

    resp = jsonify({"status": "ok"})
    resp.set_cookie(current_app.config["SESSION_COOKIE_NAME"], "", expires=0)
    return resp


@bp.get("/protected")
def protected():
    sid = request.cookies.get(current_app.config["SESSION_COOKIE_NAME"])
    if not sid:
        return jsonify({"error": "not_authenticated"}), 401

    redis_client = redis.Redis.from_url(current_app.config["REDIS_URL"], decode_responses=True)
    sess = redis_client.get(f"session:{sid}")
    if not sess:
        return jsonify({"error": "not_authenticated"}), 401

    ctx = json.loads(sess)
    return jsonify({"status": "ok", "user_id": ctx.get("user_id"), "last_auth_at": ctx.get("last_auth_at")})


@bp.get("/demo/login")
def demo_login():
    return render_template("passkeys_login_demo.html")
