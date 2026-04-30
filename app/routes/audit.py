import csv
import io
import uuid
from datetime import datetime, time
from functools import wraps

from flask import Blueprint, Response, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import func

from app import db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_access_log import EvidenceAccessLog
from app.models.user import User

audit_bp = Blueprint("audit", __name__)


def _to_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.combine(datetime.strptime(value, "%Y-%m-%d").date(), time.min)
        except ValueError:
            return None


def require_auditor(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = _to_uuid(get_jwt_identity())
        user = User.query.filter_by(id=user_id, is_active=True).first() if user_id else None
        role = str(getattr(user.role, "value", user.role)).strip().upper() if user else ""
        if not user or role not in ("ADMIN", "AUDITOR"):
            return jsonify(success=False, message="Auditor access required"), 403
        return fn(*args, **kwargs)

    return wrapper


def _base_query():
    return (
        db.session.query(EvidenceAccessLog, User, Evidence, Case)
        .join(User, User.id == EvidenceAccessLog.user_id)
        .join(Evidence, Evidence.id == EvidenceAccessLog.evidence_id)
        .join(Case, Case.id == EvidenceAccessLog.case_id)
    )


def _apply_filters(query):
    action = (request.args.get("action") or "").strip().upper()
    user_id = _to_uuid(request.args.get("user_id"))
    date_from = _parse_date(request.args.get("date_from"))
    date_to = _parse_date(request.args.get("date_to"))

    if action:
        query = query.filter(EvidenceAccessLog.action == action)
    if user_id:
        query = query.filter(EvidenceAccessLog.user_id == user_id)
    if date_from:
        query = query.filter(EvidenceAccessLog.occurred_at >= date_from)
    if date_to:
        query = query.filter(EvidenceAccessLog.occurred_at <= date_to)
    return query


def _hash_status(hash_at_time):
    return "OK" if hash_at_time else "UNKNOWN"


def _serialize_log(log, user, evidence, case):
    return {
        "id": str(log.id),
        "user_id": str(user.id),
        "user_name": user.full_name,
        "user_role": str(getattr(user.role, "value", user.role)).upper(),
        "action": log.action,
        "evidence_ref": evidence.evidence_tag,
        "case_number": case.case_number,
        "hash_at_time": log.hash_at_time,
        "hash_status": _hash_status(log.hash_at_time),
        "timestamp": log.occurred_at.isoformat() + "Z" if log.occurred_at else None,
    }


@audit_bp.get("/audit/logs")
@require_auditor
def get_audit_logs():
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 50) or 50), 1), 200)

    query = _apply_filters(_base_query())
    total = query.count()
    rows = (
        query.order_by(EvidenceAccessLog.occurred_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return jsonify(
        success=True,
        data={
            "logs": [_serialize_log(*row) for row in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
        },
    )


@audit_bp.get("/audit/stats")
@require_auditor
def get_audit_stats():
    today = datetime.utcnow().date()
    start_today = datetime.combine(today, time.min)
    end_today = datetime.combine(today, time.max)
    base = EvidenceAccessLog.query.filter(
        EvidenceAccessLog.occurred_at >= start_today,
        EvidenceAccessLog.occurred_at <= end_today,
    )

    return jsonify(
        success=True,
        data={
            "total_actions_today": base.count(),
            "active_users_today": base.with_entities(func.count(func.distinct(EvidenceAccessLog.user_id))).scalar() or 0,
            "evidence_items_touched": base.with_entities(func.count(func.distinct(EvidenceAccessLog.evidence_id))).scalar() or 0,
            "hash_verifications": base.filter(EvidenceAccessLog.action == "HASH_VERIFIED").count(),
        },
    )


@audit_bp.get("/audit/logs/export")
@require_auditor
def export_audit_logs():
    rows = _apply_filters(_base_query()).order_by(EvidenceAccessLog.occurred_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "user_id",
            "user_name",
            "user_role",
            "action",
            "evidence_ref",
            "case_number",
            "hash_at_time",
            "hash_status",
            "timestamp",
        ]
    )
    for log, user, evidence, case in rows:
        item = _serialize_log(log, user, evidence, case)
        writer.writerow(
            [
                item["id"],
                item["user_id"],
                item["user_name"],
                item["user_role"],
                item["action"],
                item["evidence_ref"],
                item["case_number"],
                item["hash_at_time"] or "",
                item["hash_status"],
                item["timestamp"] or "",
            ]
        )

    csv_text = output.getvalue()
    output.close()
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_trail.csv"},
    )
