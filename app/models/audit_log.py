import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from app import db


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False, index=True)
    user_name = db.Column(db.String(255), nullable=False)
    user_role = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(50), nullable=False, index=True)
    case_id = db.Column(UUID(as_uuid=True), db.ForeignKey("cases.id"), nullable=True)
    case_number = db.Column(db.String(50), nullable=True)
    evidence_id = db.Column(UUID(as_uuid=True), db.ForeignKey("evidence.id"), nullable=True)
    evidence_ref = db.Column(db.String(50), nullable=True)
    details = db.Column(db.Text, nullable=True)
    hash_at_time = db.Column(db.String(255), nullable=True)
    hash_status = db.Column(db.String(20), nullable=True)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
