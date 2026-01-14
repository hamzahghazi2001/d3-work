import logging
import time
from flask import Flask
from dotenv import load_dotenv

from .extensions import db, migrate
from .logging_setup import setup_logging
from .routes import register_routes
from sqlalchemy.exc import OperationalError

def create_app():
    load_dotenv()
    from .config import Config 
    app = Flask(__name__)

    app.config.from_object(Config)

    app.config["SQLALCHEMY_DATABASE_URI"] = app.config.get("DATABASE_URL")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    required = ["DATABASE_URL", "REDIS_URL", "WEBAUTHN_RP_ID", "WEBAUTHN_RP_NAME", "WEBAUTHN_ORIGIN"]
    missing = [k for k in required if not app.config.get(k)]
    if missing:

    setup_logging(app.config["EVIDENCE_LOG_PATH"])
    logging.getLogger("app").info("WEB_STARTUP")

    db.init_app(app)
    migrate.init_app(app, db)


    with app.app_context():
        from . import models  
        db.create_all()

    register_routes(app)
    return app
    
    with app.app_context():
        from . import models 

        for attempt in range(30):
            try:
                db.create_all()
                break
            except OperationalError:
                time.sleep(1)
        else:
        raise