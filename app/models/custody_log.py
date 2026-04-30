import enum
from datetime import datetime

from sqlalchemy import event
from sqlalchemy.dialects.postgresql import UUID

from app import db


class CustodyAction(enum.Enum):
    COLLECTED = "COLLECTED"
    TRANSFERRED = "TRANSFERRED"
    RECEIVED = "RECEIVED"
    ANALYZED = "ANALYZED"
    SECURED = "SECURED"
    SUBMITTED_TO_COURT = "SUBMITTED_TO_COURT"


class CustodyLog(db.Model):
    __tablename__ = "custody_log"

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    evidence_id = db.Column(UUID(as_uuid=True), db.ForeignKey("evidence.id"), nullable=False)
    from_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    to_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    action = db.Column(db.Enum(CustodyAction, name="custody_action_enum"), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    notes = db.Column(db.Text)
    transferred_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    received_at = db.Column(db.DateTime)
    recorded_by_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


def _block_custody_log_mutation(*_args, **_kwargs):
    raise ValueError("custody_log is append-only. UPDATE and DELETE are not allowed.")


event.listen(CustodyLog, "before_update", _block_custody_log_mutation)
event.listen(CustodyLog, "before_delete", _block_custody_log_mutation)
