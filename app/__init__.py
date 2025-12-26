import logging
from flask import Flask
from dotenv import load_dotenv

from .config import Config
from .extensions import db, migrate
from .logging_setup import setup_logging
from .routes import register_routes

def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    setup_logging(Config.EVIDENCE_LOG_PATH)
    logging.getLogger("app").info("WEB_STARTUP")

    db.init_app(app)
    migrate.init_app(app, db)

    register_routes(app)
    return app
