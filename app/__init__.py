import logging
from flask import Flask
from dotenv import load_dotenv

from .extensions import db, migrate
from .logging_setup import setup_logging
from .routes import register_routes


def create_app():
    # Load .env BEFORE importing Config (your Config reads env at import-time)
    load_dotenv()
    from .config import Config  # import here on purpose

    app = Flask(__name__)

    # Load all config keys (WEBAUTHN_*, REDIS_URL, etc.)
    app.config.from_object(Config)

    # SQLAlchemy expects this key
    app.config["SQLALCHEMY_DATABASE_URI"] = app.config.get("DATABASE_URL")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # (prevents silent 500s later)
    required = ["DATABASE_URL", "REDIS_URL", "WEBAUTHN_RP_ID", "WEBAUTHN_RP_NAME", "WEBAUTHN_ORIGIN"]
    missing = [k for k in required if not app.config.get(k)]
    if missing:
        raise RuntimeError(f"Missing required config keys: {', '.join(missing)}")

    # setup_logging expects a *path string*
    setup_logging(app.config["EVIDENCE_LOG_PATH"])
    logging.getLogger("app").info("WEB_STARTUP")

    db.init_app(app)
    migrate.init_app(app, db)


    with app.app_context():
        from . import models  # registers models
        db.create_all()

    register_routes(app)
    return app
