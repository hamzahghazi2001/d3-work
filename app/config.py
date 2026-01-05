import os


class Config:
    DATABASE_URL = os.getenv("DATABASE_URL")
    REDIS_URL = os.getenv("REDIS_URL")
    MAILPIT_HOST = os.getenv("MAILPIT_HOST", "mailpit")
    MAILPIT_SMTP_PORT = int(os.getenv("MAILPIT_SMTP_PORT", "1025"))
    EVIDENCE_LOG_PATH = os.getenv("EVIDENCE_LOG_PATH", "/workspace/evidence/logs/Log-A1_web-startup.log")

    WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "D3 Work (Local)")
    WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:5000")
    WEBAUTHN_CHALLENGE_TTL_SECONDS = int(os.getenv("WEBAUTHN_CHALLENGE_TTL_SECONDS", "600"))
