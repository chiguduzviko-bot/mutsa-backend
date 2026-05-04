import enum
import uuid
from datetime import datetime

import bcrypt
from sqlalchemy import Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import validates

from app import db

_LEGACY_ROLE_MAP = {
    "SUPERVISOR": "AUTHORIZER",
}


class UserRole(enum.Enum):
    ADMIN = "ADMIN"
    AUDITOR = "AUDITOR"
    INVESTIGATOR = "INVESTIGATOR"
    AUTHORIZER = "AUTHORIZER"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    employee_number = db.Column(db.String(32), unique=True, nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(24))
    role = db.Column(db.Enum(UserRole, name="user_role_enum"), nullable=False, default=UserRole.AUDITOR)
    password_hash = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("idx_users_role", "role"),
    )

    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    def check_password(self, password):
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))

    @staticmethod
    def normalize_role_value(role_value):
        if isinstance(role_value, UserRole):
            return role_value
        raw = str(role_value or "").strip().upper()
        raw = _LEGACY_ROLE_MAP.get(raw, raw)
        return UserRole(raw)

    @validates("role")
    def _validate_role(self, _key, value):
        return self.normalize_role_value(value)
