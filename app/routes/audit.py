import csv
import io
import uuid
from datetime import datetime, time
from flask import Blueprint, Response, jsonify, request
from sqlalchemy import func

from app import db
from app.models.audit_log import AuditLog
from app.utils.decorators import requireRole
from app.utils.serializers import serialize_audit_log

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


def _apply_filters(query):
    action = (request.args.get("action") or "").strip().upper()
    user_id = _to_uuid(request.args.get("user_id"))
    date_from = _parse_date(request.args.get("date_from"))
    date_to = _parse_date(request.args.get("date_to"))

    if action:
        query = query.filter(AuditLog.action == action)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if date_from:
        query = query.filter(AuditLog.timestamp >= date_from)
    if date_to:
        query = query.filter(AuditLog.timestamp <= date_to)
    return query


def _serialize_log(log):
    return serialize_audit_log(log)


@audit_bp.get("/audit/logs")
@requireRole("AUDITOR")
def get_audit_logs():
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 50) or 50), 1), 200)

    query = AuditLog.query
    query = _apply_filters(query)
    total = query.count()
    rows = (
        query.order_by(AuditLog.timestamp.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return jsonify(
        success=True,
        data={
            "logs": [_serialize_log(row) for row in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
        },
        message="Audit logs fetched",
    )


@audit_bp.get("/audit/stats")
@requireRole("AUDITOR")
def get_audit_stats():
    today = datetime.utcnow().date()
    start_today = datetime.combine(today, time.min)
    end_today = datetime.combine(today, time.max)
    base = AuditLog.query.filter(
        AuditLog.timestamp >= start_today,
        AuditLog.timestamp <= end_today,
    )

    return jsonify(
        success=True,
        data={
            "total_actions_today": base.count(),
            "active_users_today": base.with_entities(func.count(func.distinct(AuditLog.user_id))).scalar() or 0,
            "evidence_items_touched": base.with_entities(func.count(func.distinct(AuditLog.evidence_id))).scalar() or 0,
            "hash_verifications": base.filter(AuditLog.action == "HASH_VERIFIED").count(),
        },
        message="Audit stats fetched",
    )


@audit_bp.get("/audit/logs/export")
@audit_bp.get("/audit/export")
@requireRole("AUDITOR")
def export_audit_logs():
    rows = _apply_filters(AuditLog.query).order_by(AuditLog.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "user_id",
            "user_name",
            "user_role",
            "action",
            "case_number",
            "evidence_ref",
            "details",
            "hash_at_time",
            "hash_status",
            "timestamp",
        ]
    )
    for log in rows:
        item = _serialize_log(log)
        writer.writerow(
            [
                item["id"],
                item["user_id"] or "",
                item["user_name"],
                item["user_role"],
                item["action"],
                item["case_number"] or "",
                item["evidence_ref"] or "",
                item["details"] or "",
                item["hash_at_time"] or "",
                item["hash_status"] or "",
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
