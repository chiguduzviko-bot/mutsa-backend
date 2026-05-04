import enum
import uuid
from datetime import datetime

from sqlalchemy.dialects.postgresql import UUID

from app import db


class FraudType(enum.Enum):
    SIM_SWAP = "SIM_SWAP"
    PHISHING = "PHISHING"
    IDENTITY_THEFT = "IDENTITY_THEFT"
    FINANCIAL_FRAUD = "FINANCIAL_FRAUD"
    CYBERCRIME = "CYBERCRIME"
    MONEY_LAUNDERING = "MONEY_LAUNDERING"
    OTHER = "OTHER"
    BUSINESS_EMAIL_COMPROMISE = "BUSINESS_EMAIL_COMPROMISE"
    INSIDER_FRAUD = "INSIDER_FRAUD"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"


class CaseStatus(enum.Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    OPEN = "OPEN"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    REJECTED = "REJECTED"
    CLOSED = "CLOSED"
    RESOLVED = "RESOLVED"


class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_number = db.Column(db.String(40), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    suspect_info = db.Column(db.Text)
    fraud_type = db.Column(db.Enum(FraudType, name="fraud_type_enum"), nullable=False)
    status = db.Column(db.Enum(CaseStatus, name="case_status_enum"), nullable=False, default=CaseStatus.OPEN)
    incident_date = db.Column(db.Date, nullable=False)
    opened_by_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"), nullable=False)
    assigned_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    supervisor_user_id = db.Column(UUID(as_uuid=True), db.ForeignKey("users.id"))
    amount_zwl = db.Column(db.Numeric(18, 2))
    amount_usd = db.Column(db.Numeric(18, 2))
    location = db.Column(db.String(120), nullable=False, default="Zimbabwe")
    closed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
