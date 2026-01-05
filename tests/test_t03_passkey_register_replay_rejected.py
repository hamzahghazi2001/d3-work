import base64
import json
import os

import redis
import requests


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_t03_passkey_register_finish_replay_rejected():
    """T-03: /register/finish rejects when the server-side challenge context is missing (replay/expired)."""
    base_url = os.getenv("BASE_URL", "http://localhost:5000")

    # Start to obtain a real server-issued challenge
    start = requests.post(
        f"{base_url}/register/start",
        json={"email": "phase2_t03@example.com"},
        timeout=10,
    )
    assert start.status_code == 200, start.text
    challenge = start.json()["challenge"]

    # Delete challenge context to simulate "already used / expired"
    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    rc = redis.Redis.from_url(redis_url, decode_responses=True)
    rc.delete(f"webauthn:reg_chal:{challenge}")

    # Minimal payload that contains clientDataJSON with the challenge
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": os.getenv("WEBAUTHN_ORIGIN", "http://localhost:5000"),
        "crossOrigin": False,
    }
    client_data_b64 = b64url_encode(json.dumps(client_data).encode("utf-8"))

    dummy = {
        "id": "dummy",
        "rawId": "dummy",
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_b64,
            "attestationObject": "dummy",
        },
    }

    finish = requests.post(
        f"{base_url}/register/finish",
        json=dummy,
        timeout=10,
    )
    assert finish.status_code == 400, finish.text
    assert "replay" in finish.text.lower() or "expired" in finish.text.lower()
