import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from app import db

FLAG_CATEGORIES = ("HASH_MISMATCH", "UNUSUAL_ACCESS", "OTHER")
FLAG_STATUSES = ("OPEN", "REVIEWED", "DISMISSED")


class AuditLogFlag(db.Model):
    __tablename__ = "audit_log_flags"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_log_id = db.Column(
        UUID(as_uuid=True),
        db.ForeignKey("evidence_access_log.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    flagged_by_user_id = db.Column(
        UUID(as_uuid=True),
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    reason = db.Column(db.Text, nullable=False)
    category = db.Column(
        db.Enum(*FLAG_CATEGORIES, name="flag_category_enum", create_constraint=True),
        nullable=False,
        default="OTHER",
        index=True,
    )
    status = db.Column(
        db.Enum(*FLAG_STATUSES, name="flag_status_enum", create_constraint=True),
        nullable=False,
        default="OPEN",
        index=True,
    )
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
