import os

import redis
import requests


def test_t02_passkey_register_start_stores_challenge():
    """T-02: /register/start returns WebAuthn options and stores a server-side challenge in Redis."""
    base_url = os.getenv("BASE_URL", "http://localhost:5000")
    r = requests.post(
        f"{base_url}/register/start",
        json={"email": "phase2_t02@example.com"},
        timeout=10,
    )
    assert r.status_code == 200, r.text

    data = r.json()
    assert "challenge" in data
    assert "rp" in data
    assert "user" in data

    challenge = data["challenge"]
    assert isinstance(challenge, str) and len(challenge) > 10

    redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    rc = redis.Redis.from_url(redis_url, decode_responses=True)

    key = f"webauthn:reg_chal:{challenge}"
    val = rc.get(key)
    assert val is not None, "Expected challenge context to exist in Redis"
    assert val.isdigit(), "Expected stored user_id to be numeric"

    ttl = rc.ttl(key)
    assert ttl > 0, f"Expected TTL > 0, got {ttl}"
