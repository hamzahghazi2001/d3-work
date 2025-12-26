from flask import Blueprint, jsonify
from sqlalchemy import text, inspect
import redis

from ..config import Config
from ..extensions import db

bp = Blueprint("health", __name__)

@bp.get("/health")
def health():
    return jsonify(status="ok")

@bp.get("/health/deps")
def health_deps():
    out = {
        "db_ok": False,
        "redis_ok": False,
        "required_tables_present": False,
        "missing_tables": [],
    }

    # DB ping + table check
    try:
        db.session.execute(text("SELECT 1"))
        insp = inspect(db.engine)
        tables = set(insp.get_table_names())
        required = {"users", "credentials", "audit_log"}
        missing = sorted(list(required - tables))
        out["missing_tables"] = missing
        out["db_ok"] = True
        out["required_tables_present"] = (len(missing) == 0)
    except Exception as e:
        out["db_error"] = str(e)

    # Redis ping
    try:
        r = redis.Redis.from_url(Config.REDIS_URL)
        out["redis_ok"] = (r.ping() is True)
    except Exception as e:
        out["redis_error"] = str(e)

    return jsonify(out), (200 if (out["db_ok"] and out["redis_ok"]) else 503)
