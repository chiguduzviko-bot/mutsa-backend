import os
from datetime import timedelta

from flask import Flask, request
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
    env = config_name or os.environ.get("FLASK_ENV")
    is_railway = bool(
        os.environ.get("RAILWAY_ENVIRONMENT")
        or os.environ.get("RAILWAY_PROJECT_ID")
        or os.environ.get("RAILWAY_SERVICE_ID")
        or os.environ.get("RAILWAY_PUBLIC_DOMAIN")
        or os.environ.get("PORT")
    )
    if not env:
        env = "production" if is_railway else "development"

    if str(env).lower() == "production" or is_railway:
        app.config.from_object("app.config.ProductionConfig")
    else:
        app.config.from_object("app.config.DevelopmentConfig")

    runtime_db_url = (
        app.config.get("SQLALCHEMY_DATABASE_URI")
        or os.environ.get("DATABASE_URL")
        or os.environ.get("SQLALCHEMY_DATABASE_URI")
    )
    if runtime_db_url and runtime_db_url.startswith("postgres://"):
        runtime_db_url = runtime_db_url.replace("postgres://", "postgresql://", 1)

    # Prevent Railway worker boot crashes when DB vars are temporarily missing.
    # The API stays up and login endpoints will return controlled DB errors instead.
    if not runtime_db_url:
        runtime_db_url = "sqlite:////tmp/chain_custody_fallback.db"
        app.logger.warning("No DB env vars found; using temporary SQLite fallback.")

    app.config["SQLALCHEMY_DATABASE_URI"] = runtime_db_url
    app.config["FLASK_ENV"] = os.environ.get("FLASK_ENV", "production" if is_railway else "development")
    app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "mutsa-jwt-fallback-secret-change-me")
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)

    allowed_origins = [
        os.environ.get("FRONTEND_URL", "https://mutsa-frontend.vercel.app"),
        "http://localhost:3000",
        "http://localhost:5173",
    ]

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": allowed_origins,
                "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": True,
            }
        },
    )

    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            return app.make_default_options_response()

    from . import models  # noqa: F401
    from .models.db_triggers import register_db_triggers
    from .routes.admin import admin_bp
    from .routes.audit import audit_bp
    from .routes.auth import auth_ns
    from .routes.cases import cases_ns
    from .routes.custody import custody_ns
    from .routes.evidence import evidence_ns
    from .routes.health import health_ns

    register_db_triggers()

    api.init_app(app)
    api.add_namespace(auth_ns, path="/api/auth")
    api.add_namespace(auth_ns, path="/auth")
    api.add_namespace(health_ns, path="/api/health")
    api.add_namespace(cases_ns, path="/api/cases")
    api.add_namespace(evidence_ns, path="/api/evidence")
    api.add_namespace(custody_ns, path="/api/custody")
    app.register_blueprint(admin_bp, url_prefix="/api")
    app.register_blueprint(audit_bp, url_prefix="/api")

    return app
