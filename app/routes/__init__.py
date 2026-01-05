from .health import bp as health_bp
from .debug import bp as debug_bp
from .passkeys import bp as passkeys_bp


def register_routes(app):
    app.register_blueprint(health_bp)
    app.register_blueprint(debug_bp)
    app.register_blueprint(passkeys_bp)
