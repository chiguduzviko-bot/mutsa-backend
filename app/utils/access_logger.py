import logging

from app import db
from app.models.evidence import Evidence
from app.models.evidence_access_log import EvidenceAccessLog
from app.models.file_hash import FileHash

logger = logging.getLogger(__name__)


def log_access(evidence_id, user_id, action, notes=None, request=None):
    try:
        evidence = Evidence.query.filter_by(id=evidence_id).first()
        if not evidence:
            return

        latest_original_hash = (
            FileHash.query.filter_by(evidence_id=evidence.id, is_current=True)
            .order_by(FileHash.hashed_at.desc())
            .first()
        )
        if not latest_original_hash:
            latest_original_hash = (
                FileHash.query.filter_by(evidence_id=evidence.id)
                .order_by(FileHash.hashed_at.desc())
                .first()
            )

        ip_address = None
        user_agent = None
        if request is not None:
            ip_address = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
            user_agent = request.user_agent.string if request.user_agent else None

        access_log = EvidenceAccessLog(
            evidence_id=evidence.id,
            case_id=evidence.case_id,
            user_id=user_id,
            action=action,
            hash_at_time=latest_original_hash.sha256_hash if latest_original_hash else None,
            ip_address=ip_address,
            user_agent=user_agent,
            notes=notes,
        )
        db.session.add(access_log)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.exception("Failed to persist evidence access log: %s", exc)
