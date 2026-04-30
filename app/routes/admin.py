import csv
import io
import uuid
from datetime import datetime, time

from flask import Blueprint, Response, g, jsonify, request
from sqlalchemy import cast, func

from app import db
from app.models.audit_log_flag import AuditLogFlag, FLAG_CATEGORIES, FLAG_STATUSES
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.evidence_access_log import EvidenceAccessLog
from app.models.file_hash import FileHash
from app.models.user import User
from app.utils.decorators import requireRole

admin_bp = Blueprint("admin", __name__)

_AUDITOR_OR_ADMIN = ("ADMIN", "AUDITOR")
_ADMIN_ONLY = ("ADMIN",)


# ─── helpers ──────────────────────────────────────────────────────────────────

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


def _ok(data=None, message="", status=200):
    return jsonify({"success": True, "data": data or {}, "message": message}), status


def _err(message, status=400):
    return jsonify({"success": False, "data": {}, "message": message}), status


def _apply_log_filters(query):
    user_id = _to_uuid(request.args.get("user_id"))
    evidence_id = _to_uuid(request.args.get("evidence_id"))
    case_id = _to_uuid(request.args.get("case_id"))
    action = request.args.get("action")
    date_from = _parse_date(request.args.get("date_from"))
    date_to = _parse_date(request.args.get("date_to"))

    if user_id:
        query = query.filter(EvidenceAccessLog.user_id == user_id)
    if evidence_id:
        query = query.filter(EvidenceAccessLog.evidence_id == evidence_id)
    if case_id:
        query = query.filter(EvidenceAccessLog.case_id == case_id)
    if action:
        query = query.filter(EvidenceAccessLog.action == action.strip().upper())
    if date_from:
        query = query.filter(EvidenceAccessLog.occurred_at >= date_from)
    if date_to:
        query = query.filter(EvidenceAccessLog.occurred_at <= date_to)
    return query


def _log_with_joins():
    latest_hash_sub = (
        db.session.query(
            FileHash.evidence_id.label("evidence_id"),
            func.max(FileHash.hashed_at).label("latest_hashed_at"),
        )
        .group_by(FileHash.evidence_id)
        .subquery()
    )
    file_info_sub = (
        db.session.query(FileHash.evidence_id, FileHash.file_name)
        .join(
            latest_hash_sub,
            (FileHash.evidence_id == latest_hash_sub.c.evidence_id)
            & (FileHash.hashed_at == latest_hash_sub.c.latest_hashed_at),
        )
        .subquery()
    )
    return (
        db.session.query(
            EvidenceAccessLog, User, Evidence, Case, file_info_sub.c.file_name
        )
        .join(User, User.id == EvidenceAccessLog.user_id)
        .join(Evidence, Evidence.id == EvidenceAccessLog.evidence_id)
        .join(Case, Case.id == EvidenceAccessLog.case_id)
        .outerjoin(file_info_sub, file_info_sub.c.evidence_id == Evidence.id)
    )


def _serialize_log_row(log, user, evidence, case, file_name):
    return {
        "id": str(log.id),
        "occurred_at": log.occurred_at.isoformat() if log.occurred_at else None,
        "user": {
            "id": str(user.id),
            "full_name": user.full_name,
            "role": user.role.value,
            "badge_number": user.employee_number,
        },
        "evidence": {
            "id": str(evidence.id),
            "evidence_ref": evidence.evidence_tag,
            "description": evidence.description,
            "file_name": file_name,
        },
        "case": {
            "id": str(case.id),
            "case_number": case.case_number,
            "fraud_type": case.fraud_type.value,
        },
        "action": log.action,
        "hash_at_time": log.hash_at_time,
        "ip_address": str(log.ip_address) if log.ip_address else None,
        "notes": log.notes,
    }


# ─── Evidence access log – list ───────────────────────────────────────────────

@admin_bp.get("/admin/evidence-access-log")
@requireRole(*_ADMIN_ONLY)
def list_evidence_access_logs():
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 50) or 50), 1), 200)

    query = _apply_log_filters(_log_with_joins())
    total = query.count()
    rows = (
        query.order_by(EvidenceAccessLog.occurred_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return _ok(
        {
            "items": [_serialize_log_row(*r) for r in rows],
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page if total else 0,
        },
        message="Evidence access logs fetched",
    )


# ─── Evidence access log – stats ──────────────────────────────────────────────

@admin_bp.get("/admin/evidence-access-log/stats")
@requireRole(*_AUDITOR_OR_ADMIN)
def evidence_access_log_stats():
    today = datetime.utcnow().date()
    start_today = datetime.combine(today, time.min)
    end_today = datetime.combine(today, time.max)

    base = EvidenceAccessLog.query.filter(
        EvidenceAccessLog.occurred_at >= start_today,
        EvidenceAccessLog.occurred_at <= end_today,
    )

    total_actions = base.count()
    active_users = base.with_entities(func.count(func.distinct(EvidenceAccessLog.user_id))).scalar() or 0
    evidence_touched = base.with_entities(func.count(func.distinct(EvidenceAccessLog.evidence_id))).scalar() or 0
    hash_verifications = base.filter(EvidenceAccessLog.action == "HASH_VERIFIED").count()

    actions_by_type = {
        action: count
        for action, count in (
            base.with_entities(EvidenceAccessLog.action, func.count(EvidenceAccessLog.id))
            .group_by(EvidenceAccessLog.action)
            .all()
        )
    }

    top_users = [
        {"user_name": name, "role": role, "action_count": count}
        for name, role, count in (
            base.join(User, User.id == EvidenceAccessLog.user_id)
            .with_entities(
                User.full_name,
                cast(User.role, db.String),
                func.count(EvidenceAccessLog.id).label("action_count"),
            )
            .group_by(User.full_name, User.role)
            .order_by(func.count(EvidenceAccessLog.id).desc())
            .limit(5)
            .all()
        )
    ]

    return _ok(
        {
            "total_actions_today": total_actions,
            "active_users_today": active_users,
            "evidence_items_touched_today": evidence_touched,
            "hash_verifications_today": hash_verifications,
            "actions_by_type": actions_by_type,
            "top_users": top_users,
        },
        message="Evidence access stats fetched",
    )


# ─── Evidence access log – CSV export ─────────────────────────────────────────

@admin_bp.get("/admin/evidence-access-log/export")
@requireRole(*_AUDITOR_OR_ADMIN)
def export_evidence_access_log_csv():
    rows = _apply_log_filters(_log_with_joins()).order_by(EvidenceAccessLog.occurred_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "timestamp", "user_name", "user_role", "badge_number",
        "action", "evidence_ref", "case_number", "hash_at_time",
        "session_event", "ip_address",
    ])
    session_events = {"LOGIN", "LOGOUT", "SYSTEM_LOGOUT", "LOGIN_FAILED"}
    for log, user, evidence, case, _file_name in rows:
        writer.writerow([
            log.occurred_at.isoformat() if log.occurred_at else "",
            user.full_name,
            user.role.value,
            user.employee_number,
            log.action,
            evidence.evidence_tag,
            case.case_number,
            log.hash_at_time or "",
            "YES" if log.action in session_events else "",
            str(log.ip_address) if log.ip_address else "",
        ])

    csv_bytes = output.getvalue()
    output.close()
    return Response(
        csv_bytes,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=evidence_access_log.csv"},
    )


# ─── Flags – create ───────────────────────────────────────────────────────────

@admin_bp.post("/admin/evidence-access-log/<string:log_id>/flags")
@requireRole(*_AUDITOR_OR_ADMIN)
def create_flag(log_id):
    log_uuid = _to_uuid(log_id)
    if not log_uuid:
        return _err("Invalid log id", 400)

    log_entry = EvidenceAccessLog.query.filter_by(id=log_uuid).first()
    if not log_entry:
        return _err("Access log entry not found", 404)

    body = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "").strip()
    if not reason:
        return _err("reason is required", 400)

    category = (body.get("category") or "OTHER").strip().upper()
    if category not in FLAG_CATEGORIES:
        return _err(f"category must be one of: {', '.join(FLAG_CATEGORIES)}", 400)

    actor = g.current_user
    flag = AuditLogFlag(
        audit_log_id=log_entry.id,
        flagged_by_user_id=actor.id,
        reason=reason,
        category=category,
        status="OPEN",
    )
    db.session.add(flag)
    db.session.commit()

    return _ok(_serialize_flag(flag), message="Flag created", status=201)


# ─── Flags – list ─────────────────────────────────────────────────────────────

@admin_bp.get("/admin/evidence-access-log/flags")
@requireRole(*_AUDITOR_OR_ADMIN)
def list_flags():
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 50) or 50), 1), 200)

    query = AuditLogFlag.query

    status_filter = (request.args.get("status") or "").strip().upper()
    if status_filter and status_filter in FLAG_STATUSES:
        query = query.filter(AuditLogFlag.status == status_filter)

    category_filter = (request.args.get("category") or "").strip().upper()
    if category_filter and category_filter in FLAG_CATEGORIES:
        query = query.filter(AuditLogFlag.category == category_filter)

    total = query.count()
    flags = (
        query.order_by(AuditLogFlag.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return _ok(
        {
            "items": [_serialize_flag(f) for f in flags],
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page if total else 0,
        },
        message="Flags fetched",
    )


# ─── Flags – resolve/dismiss (ADMIN only) ─────────────────────────────────────

@admin_bp.patch("/admin/evidence-access-log/flags/<string:flag_id>")
@requireRole(*_ADMIN_ONLY)
def update_flag_status(flag_id):
    flag_uuid = _to_uuid(flag_id)
    if not flag_uuid:
        return _err("Invalid flag id", 400)

    flag = AuditLogFlag.query.filter_by(id=flag_uuid).first()
    if not flag:
        return _err("Flag not found", 404)

    body = request.get_json(silent=True) or {}
    new_status = (body.get("status") or "").strip().upper()
    if not new_status:
        return _err("status is required", 400)
    if new_status not in FLAG_STATUSES:
        return _err(f"status must be one of: {', '.join(FLAG_STATUSES)}", 400)

    flag.status = new_status
    db.session.commit()
    return _ok(_serialize_flag(flag), message=f"Flag status updated to {new_status}")


# ─── serializer ───────────────────────────────────────────────────────────────

def _serialize_flag(flag):
    return {
        "id": str(flag.id),
        "audit_log_id": str(flag.audit_log_id),
        "flagged_by_user_id": str(flag.flagged_by_user_id),
        "reason": flag.reason,
        "category": flag.category if isinstance(flag.category, str) else flag.category.value,
        "status": flag.status if isinstance(flag.status, str) else flag.status.value,
        "created_at": flag.created_at.isoformat() if flag.created_at else None,
        "updated_at": flag.updated_at.isoformat() if flag.updated_at else None,
    }
