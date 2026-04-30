import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import INET, UUID

from app import db


class EvidenceAccessLog(db.Model):
    __tablename__ = "evidence_access_log"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    evidence_id = db.Column(UUID(as_uuid=True), db.ForeignKey("evidence.id"), nullable=False, index=True)
    case_id = db.Column(UUID(as_uuid=True), db.ForeignKey("cases.id"), nullable=False, index=True)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    hash_at_time = db.Column(db.String(64))
    ip_address = db.Column(INET)
    user_agent = db.Column(db.Text)
    notes = db.Column(db.Text)
    occurred_at = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow, index=True)
