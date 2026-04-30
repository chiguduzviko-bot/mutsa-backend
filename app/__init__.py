import os

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_restx import Api
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

api = Api(
    title="Chain of Custody Evidence Tracker API",
    version="1.0.0",
    description="REST API for digital forensic chain-of-custody management",
    doc="/docs",
    authorizations={
        "Bearer": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "JWT Authorization header using Bearer scheme. Example: Bearer <token>",
        }
    },
    security="Bearer",
)


def create_app(config_name=None):
    app = Flask(__name__)
    env = config_name or os.environ.get("FLASK_ENV", "development")
    if env == "production" or os.environ.get("RAILWAY_ENVIRONMENT"):
        app.config.from_object("app.config.ProductionConfig")
    else:
        app.config.from_object("app.config.DevelopmentConfig")

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)

    allowed_origins = app.config.get("CORS_ORIGINS", ["http://localhost:5173"])
    CORS(
        app,
        resources={r"/api/*": {"origins": allowed_origins}},
        supports_credentials=True,
    )

    from . import models  # noqa: F401
    from .models.db_triggers import register_db_triggers
    from .routes.admin import admin_bp
    from .routes.auth import auth_ns
    from .routes.cases import cases_ns
    from .routes.custody import custody_ns
    from .routes.evidence import evidence_ns
    from .routes.health import health_ns

    register_db_triggers()

    api.init_app(app)
    api.add_namespace(auth_ns, path="/api/auth")
    api.add_namespace(health_ns, path="/api/health")
    api.add_namespace(cases_ns, path="/api/cases")
    api.add_namespace(evidence_ns, path="/api/evidence")
    api.add_namespace(custody_ns, path="/api/custody")
    app.register_blueprint(admin_bp, url_prefix="/api")

    return app
