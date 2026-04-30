import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import JSONB, UUID

from app import db


class AuditTrail(db.Model):
    __tablename__ = "audit_trail"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    actor_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), index=True)
    actor_role = db.Column(db.String(20))
    action = db.Column(db.String(64), nullable=False, index=True)
    entity_type = db.Column(db.String(40), nullable=False)
    entity_id = db.Column(UUID(as_uuid=True))
    evidence_id = db.Column(UUID(as_uuid=True), db.ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    case_id = db.Column(UUID(as_uuid=True), db.ForeignKey("cases.id", ondelete="SET NULL"), nullable=True)
    hash_at_time = db.Column(db.String(64), nullable=True)
    details = db.Column(JSONB, nullable=False, default=dict)
    metadata_ = db.Column("metadata", JSONB, nullable=False, default=dict)
    occurred_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
