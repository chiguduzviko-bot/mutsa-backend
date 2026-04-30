"""Centralized audit-trail helper.

Writes a row to audit_trail for any action (LOGIN, LOGOUT, VIEWED, etc.)
Silently swallows exceptions to prevent audit writes from crashing the main request.
"""
import logging

from app import db
from app.models.audit_trail import AuditTrail

logger = logging.getLogger(__name__)


def write_audit(
    action,
    *,
    actor_user_id=None,
    actor_role=None,
    entity_type="SYSTEM",
    entity_id=None,
    evidence_id=None,
    case_id=None,
    hash_at_time=None,
    details=None,
    metadata=None,
    request=None,
):
    """Insert one audit_trail row.  Never raises — exceptions are logged only."""
    try:
        meta = dict(metadata or {})
        if request is not None:
            meta.setdefault("ip", (
                request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or request.remote_addr
            ))
            meta.setdefault("user_agent", request.user_agent.string if request.user_agent else None)
            meta.setdefault("endpoint", request.path)
            meta.setdefault("method", request.method)

        row = AuditTrail(
            actor_user_id=actor_user_id,
            actor_role=actor_role,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            evidence_id=evidence_id,
            case_id=case_id,
            hash_at_time=hash_at_time,
            details=details or {},
            metadata_=meta,
        )
        db.session.add(row)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("audit write failed for action=%s: %s", action, exc)
