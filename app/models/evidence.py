import enum
import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from app import db


class EvidenceType(enum.Enum):
    DIGITAL_FILE = "DIGITAL_FILE"
    PHYSICAL = "PHYSICAL"
    SCREENSHOT = "SCREENSHOT"
    TRANSACTION_LOG = "TRANSACTION_LOG"
    DEVICE = "DEVICE"
    OTHER = "OTHER"


class EvidenceState(enum.Enum):
    COLLECTED = "COLLECTED"
    IN_TRANSIT = "IN_TRANSIT"
    IN_ANALYSIS = "IN_ANALYSIS"
    SECURED = "SECURED"
    SUBMITTED_TO_COURT = "SUBMITTED_TO_COURT"


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = db.Column(UUID(as_uuid=True), db.ForeignKey("cases.id"), nullable=False)
    evidence_tag = db.Column(db.String(50), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    source = db.Column(db.String(255))
    notes = db.Column(db.Text)
    evidence_type = db.Column(db.Enum(EvidenceType, name="evidence_type_enum"), nullable=False)
    state = db.Column(db.Enum(EvidenceState, name="evidence_state_enum"), nullable=False, default=EvidenceState.COLLECTED)
    collected_by_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    current_custodian_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    collected_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    storage_location = db.Column(db.String(255), nullable=False)
    is_sensitive = db.Column(db.Boolean, nullable=False, default=True)
    submitted_to_court_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
