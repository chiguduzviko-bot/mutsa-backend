import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


def _get_database_url():
    database_url = os.environ.get("DATABASE_URL")
    if database_url and database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql://", 1)
    return database_url


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-secret-key")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-me-jwt-secret")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:postgres@localhost:5432/chain_custody_db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    CORS_ORIGINS = [
        os.environ.get("FRONTEND_URL", "https://mutsa-frontend.vercel.app"),
        "http://localhost:3000",
        "http://localhost:5173",
    ]


class DevelopmentConfig(Config):
    ENV = "development"
    DEBUG = True


class ProductionConfig(Config):
    ENV = "production"
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = _get_database_url() or os.environ.get(
        "SQLALCHEMY_DATABASE_URI",
        Config.SQLALCHEMY_DATABASE_URI,
    )
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
    CORS_ORIGINS = [
        os.environ.get("FRONTEND_URL", "https://mutsa-frontend.vercel.app"),
        "http://localhost:3000",
        "http://localhost:5173",
    ]


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
