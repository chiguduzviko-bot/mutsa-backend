"""Audit logging helper for dashboard tracking."""
import logging

from app import db
from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def log_audit(
    user,
    action,
    case_obj=None,
    evidence_obj=None,
    details=None,
    hash_at_time=None,
    hash_status=None,
):
    """
    Insert an audit_log row. Never raises — exceptions are logged only.

    Args:
        user: User object with id, full_name, role
        action: str (CASE_CREATED, EVIDENCE_ADDED, etc.)
        case_obj: Case object (optional)
        evidence_obj: Evidence object (optional)
        details: str describing the action (optional)
        hash_at_time: SHA-256 hash (optional)
        hash_status: "OK", "TAMPERED", etc. (optional)
    """
    try:
        user_role = str(getattr(user.role, "value", user.role)).strip().upper() if user else "UNKNOWN"
        entry = AuditLog(
            user_id=user.id if user else None,
            user_name=user.full_name if user else "UNKNOWN",
            user_role=user_role,
            action=action,
            case_id=case_obj.id if case_obj else None,
            case_number=case_obj.case_number if case_obj else None,
            evidence_id=evidence_obj.id if evidence_obj else None,
            evidence_ref=evidence_obj.evidence_tag if evidence_obj else None,
            details=details,
            hash_at_time=hash_at_time,
            hash_status=hash_status,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("audit log write failed for action=%s: %s", action, exc)
