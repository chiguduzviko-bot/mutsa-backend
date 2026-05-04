import enum
import logging
import uuid
from datetime import datetime

from flask import request
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restx import Namespace, Resource, fields

from app import db
from app.models.audit_trail import AuditTrail
from app.models.case import Case, CaseStatus, FraudType
from app.models.evidence import Evidence
from app.models.user import User
from app.utils.decorators import requireRole

logger = logging.getLogger(__name__)

cases_ns = Namespace("cases", description="Case management operations")
VALID_FRAUD_TYPES = [
    "SIM_SWAP",
    "PHISHING",
    "IDENTITY_THEFT",
    "FINANCIAL_FRAUD",
    "CYBERCRIME",
    "MONEY_LAUNDERING",
    "OTHER",
]

case_create_model = cases_ns.model(
    "CaseCreateInput",
    {
        "title": fields.String(required=True),
        "fraud_type": fields.String(required=True, enum=[f.value for f in FraudType]),
        "description": fields.String(required=False),
        "suspect_info": fields.String(required=False),
        "assigned_to": fields.String(required=False, description="User UUID"),
    },
)

case_update_model = cases_ns.model(
    "CaseUpdateInput",
    {
        "title": fields.String(required=False),
        "description": fields.String(required=False),
        "suspect_info": fields.String(required=False),
        "assigned_to": fields.String(required=False, description="User UUID"),
        "fraud_type": fields.String(required=False, enum=[f.value for f in FraudType]),
    },
)

case_status_update_model = cases_ns.model(
    "CaseStatusUpdateInput",
    {
        "status": fields.String(required=True, enum=["OPEN", "REJECTED"]),
        "reason": fields.String(required=True),
    },
)


def _response(success, data=None, message="", status=200):
    return {"success": success, "data": data or {}, "message": message}, status


def _to_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _parse_case_status(value):
    if value is None:
        raise ValueError("Missing status")
    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "ACTIVE": "OPEN",
        "IN_PROGRESS": "UNDER_INVESTIGATION",
    }
    normalized = aliases.get(normalized, normalized)
    return CaseStatus(normalized)


def _parse_fraud_type(value):
    if value is None:
        raise ValueError("Missing fraud type")
    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    return FraudType(normalized)


def _generate_case_number():
    date_part = datetime.utcnow().strftime("%Y%m%d")
    for _ in range(20):
        candidate = f"CASE-{date_part}-{uuid.uuid4().hex[:6].upper()}"
        if not Case.query.filter_by(case_number=candidate).first():
            return candidate
    raise RuntimeError("Failed to generate unique case number")


_FRAUD_TYPE_ALIASES = {
    # display labels a frontend might send
    "BUSINESS EMAIL COMPROMISE": "BUSINESS_EMAIL_COMPROMISE",
    "BUSINESS_EMAIL": "BUSINESS_EMAIL_COMPROMISE",
    "BEC": "BUSINESS_EMAIL_COMPROMISE",
    "EMAIL COMPROMISE": "BUSINESS_EMAIL_COMPROMISE",
    "SIM SWAP": "SIM_SWAP",
    "SIMSWAP": "SIM_SWAP",
    "SIM-SWAP": "SIM_SWAP",
    "INSIDER FRAUD": "INSIDER_FRAUD",
    "INSIDER": "INSIDER_FRAUD",
    "ACCOUNT TAKEOVER": "ACCOUNT_TAKEOVER",
    "ACCOUNT-TAKEOVER": "ACCOUNT_TAKEOVER",
    "ATO": "ACCOUNT_TAKEOVER",
    "PHISH": "PHISHING",
}


def _normalize_fraud_type(value):
    """Return a canonical FraudType string or raise ValueError."""
    raw = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    # also check display-label aliases before underscore substitution
    display = str(value or "").strip().upper()
    canonical = _FRAUD_TYPE_ALIASES.get(display) or _FRAUD_TYPE_ALIASES.get(raw) or raw
    return FraudType(canonical).value


def _normalize_case_create_payload(data):
    payload = dict(data or {})

    title_aliases = [
        "caseTitle", "case_title", "case_name", "caseName",
        "name", "subject", "title_name",
    ]
    for alias in title_aliases:
        if alias in payload and "title" not in payload:
            payload["title"] = payload[alias]
            break

    field_aliases = {
        "caseNumber": "case_number",
        "referenceNumber": "case_number",
        "reference_number": "case_number",
        "referenceNo": "case_number",
        "reference_no": "case_number",
        "fraudType": "fraud_type",
        "fraud_category": "fraud_type",
        "fraudCategory": "fraud_type",
        "type": "fraud_type",
        "suspectInfo": "suspect_info",
        "suspect_information": "suspect_info",
        "assignedTo": "assigned_to",
        "assigned_user": "assigned_to",
        "assignedUser": "assigned_to",
        "investigator": "assigned_to",
        "investigatorId": "assigned_to",
        "supervisor": "supervisor_user_id",
        "supervisorId": "supervisor_user_id",
        "amountZwl": "amount_zwl",
        "amountUsd": "amount_usd",
        "incidentDate": "incident_date",
    }
    for old_key, new_key in field_aliases.items():
        if old_key in payload and new_key not in payload:
            payload[new_key] = payload[old_key]

    fraud_type_value = payload.get("fraud_type")
    if fraud_type_value:
        try:
            payload["fraud_type"] = _normalize_fraud_type(fraud_type_value)
        except ValueError:
            pass  # leave as-is; the route handler will return a descriptive 400
    else:
        payload["fraud_type"] = FraudType.PHISHING.value

    case_number = payload.get("case_number")
    if isinstance(case_number, str):
        payload["case_number"] = case_number.strip()

    return payload


def _enum_to_api(value, *, fallback="UNKNOWN"):
    """String value for SQLAlchemy enum columns; avoids 500s on NULL or unexpected DB values."""
    if value is None:
        return fallback
    if isinstance(value, enum.Enum):
        return value.value
    return str(value)


def _serialize_case(case):
    return {
        "id": str(case.id),
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "suspect_info": case.suspect_info,
        "fraud_type": _enum_to_api(case.fraud_type, fallback="OTHER"),
        "status": _enum_to_api(case.status, fallback="OPEN"),
        "incident_date": case.incident_date.isoformat() if case.incident_date else None,
        "assigned_to": str(case.assigned_user_id) if case.assigned_user_id else None,
        "opened_by_user_id": str(case.opened_by_user_id) if case.opened_by_user_id else None,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }


def _serialize_evidence(item):
    return {
        "id": str(item.id),
        "evidence_tag": item.evidence_tag,
        "title": item.title,
        "description": item.description,
        "evidence_type": item.evidence_type.value,
        "state": item.state.value,
        "current_custodian_id": str(item.current_custodian_id),
        "storage_location": item.storage_location,
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


@cases_ns.route("")
class CaseListResource(Resource):
    @requireRole("ADMIN", "INVESTIGATOR", "AUTHORIZER")
    @jwt_required()
    def get(self):
        try:
            page = request.args.get("page", default=1, type=int)
            per_page = request.args.get("per_page", default=10, type=int)
            status = request.args.get("status")
            fraud_type = request.args.get("fraud_type")

            if page < 1 or per_page < 1 or per_page > 100:
                return _response(False, message="Invalid pagination parameters", status=400)

            query = Case.query.filter(
                Case.status.isnot(None),
                Case.fraud_type.isnot(None),
            )
            if status:
                try:
                    query = query.filter(Case.status == _parse_case_status(status))
                except ValueError:
                    return _response(False, message="Invalid status filter", status=400)
            if fraud_type:
                try:
                    query = query.filter(Case.fraud_type == _parse_fraud_type(fraud_type))
                except ValueError:
                    return _response(False, message="Invalid fraud_type filter", status=400)

            pagination = query.order_by(Case.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
            items = [_serialize_case(c) for c in pagination.items]

            data = {
                "items": items,
                "cases": items,
                "total": pagination.total,
                "page": page,
                "per_page": per_page,
            }
            return _response(True, data=data, message="Cases fetched")
        except Exception:
            logger.exception("GET /api/cases failed")
            return _response(False, message="Failed to list cases", status=500)

    @cases_ns.expect(case_create_model, validate=False)
    @requireRole("ADMIN", "INVESTIGATOR")
    @jwt_required()
    def post(self):
        json_payload = request.get_json(silent=True) or {}
        form_payload = request.form.to_dict(flat=True) if request.form else {}
        raw_keys = list({**form_payload, **json_payload}.keys())
        data = _normalize_case_create_payload({**form_payload, **json_payload})

        logger.debug("POST /api/cases  raw_keys=%s  normalized=%s", raw_keys, data)

        required = ["title", "fraud_type"]
        missing = [k for k in required if not data.get(k)]
        if missing:
            logger.warning("POST /api/cases 400 – missing fields. received keys: %s", raw_keys)
            return _response(
                False,
                message=f"Missing required fields: {', '.join(missing)}. "
                        f"Received keys: {raw_keys}. "
                        f"Required: title (or caseTitle / case_title), fraud_type (or fraudType).",
                status=400,
            )

        actor_id = _to_uuid(get_jwt_identity())
        if not actor_id:
            return _response(False, message="Invalid token identity", status=401)

        actor = User.query.filter_by(id=actor_id, is_active=True).first()
        if not actor:
            return _response(False, message="User not found", status=404)
        actor_role = str(getattr(actor.role, "value", actor.role)).strip().upper()

        try:
            fraud_type = FraudType(data["fraud_type"])
        except ValueError:
            logger.warning("POST /api/cases 400 – invalid fraud_type=%s", data.get("fraud_type"))
            return _response(
                False,
                message=f"Invalid fraud_type value: '{data['fraud_type']}'. "
                        f"Allowed values: {', '.join(VALID_FRAUD_TYPES)}.",
                status=400,
            )

        assigned_to_uuid = _to_uuid(data.get("assigned_to")) if data.get("assigned_to") else None
        if assigned_to_uuid and not User.query.filter_by(id=assigned_to_uuid).first():
            return _response(False, message="Assigned user not found", status=404)

        case_number = _generate_case_number()
        case = Case(
            case_number=case_number,
            title=data["title"],
            description=data.get("description"),
            suspect_info=data.get("suspect_info"),
            fraud_type=fraud_type,
            status=CaseStatus.PENDING_APPROVAL if actor_role == "INVESTIGATOR" else CaseStatus.OPEN,
            incident_date=datetime.utcnow().date(),
            opened_by_user_id=actor_id,
            assigned_user_id=assigned_to_uuid,
        )
        db.session.add(case)
        db.session.flush()
        db.session.add(
            AuditTrail(
                actor_user_id=actor_id,
                action="CREATE_CASE",
                entity_type="CASE",
                entity_id=case.id,
                details={"case_number": case.case_number, "status": case.status.value},
            )
        )
        db.session.commit()
        return _response(True, data={"id": str(case.id), "case_number": case.case_number}, message="Case created", status=201)


@cases_ns.route("/<string:case_id>")
class CaseDetailResource(Resource):
    @jwt_required()
    def get(self, case_id):
        case_uuid = _to_uuid(case_id)
        if not case_uuid:
            return _response(False, message="Invalid case id", status=400)
        case = Case.query.filter_by(id=case_uuid).first()
        if not case:
            return _response(False, message="Case not found", status=404)
        evidence_items = Evidence.query.filter_by(case_id=case.id).order_by(Evidence.created_at.desc()).all()
        payload = _serialize_case(case)
        payload["evidence"] = [_serialize_evidence(e) for e in evidence_items]
        return _response(True, data=payload, message="Case details fetched")

    @cases_ns.expect(case_update_model, validate=True)
    @jwt_required()
    def put(self, case_id):
        case_uuid = _to_uuid(case_id)
        if not case_uuid:
            return _response(False, message="Invalid case id", status=400)
        case = Case.query.filter_by(id=case_uuid).first()
        if not case:
            return _response(False, message="Case not found", status=404)

        data = request.get_json() or {}
        if "status" in data:
            return _response(False, message="Status changes are only allowed via /cases/<id>/status", status=400)
        if not data:
            return _response(False, message="No update fields provided", status=400)

        if "fraud_type" in data:
            try:
                case.fraud_type = FraudType(data["fraud_type"])
            except ValueError:
                return _response(False, message="Invalid fraud_type value", status=400)
        if "title" in data:
            case.title = data["title"]
        if "description" in data:
            case.description = data["description"]
        if "suspect_info" in data:
            case.suspect_info = data["suspect_info"]
        if "assigned_to" in data:
            assigned_to_uuid = _to_uuid(data["assigned_to"]) if data["assigned_to"] else None
            if data["assigned_to"] and not assigned_to_uuid:
                return _response(False, message="assigned_to must be a valid UUID", status=400)
            if assigned_to_uuid and not User.query.filter_by(id=assigned_to_uuid).first():
                return _response(False, message="Assigned user not found", status=404)
            case.assigned_user_id = assigned_to_uuid

        actor_id = _to_uuid(get_jwt_identity())
        db.session.add(
            AuditTrail(
                actor_user_id=actor_id,
                action="UPDATE_CASE",
                entity_type="CASE",
                entity_id=case.id,
                details={"updated_fields": list(data.keys())},
            )
        )
        db.session.commit()
        return _response(True, data=_serialize_case(case), message="Case updated")


@cases_ns.route("/<string:case_id>/status")
class CaseStatusResource(Resource):
    @cases_ns.expect(case_status_update_model, validate=True)
    @requireRole("ADMIN", "AUTHORIZER")
    @jwt_required()
    def put(self, case_id):
        case_uuid = _to_uuid(case_id)
        if not case_uuid:
            return _response(False, message="Invalid case id", status=400)
        case = Case.query.filter_by(id=case_uuid).first()
        if not case:
            return _response(False, message="Case not found", status=404)

        data = request.get_json() or {}
        if not data.get("reason"):
            return _response(False, message="Reason is required", status=400)
        try:
            new_status = CaseStatus(data["status"])
        except ValueError:
            return _response(False, message="Invalid status value", status=400)
        if new_status not in (CaseStatus.OPEN, CaseStatus.REJECTED):
            return _response(False, message="Status must be OPEN or REJECTED", status=400)

        actor_id = _to_uuid(get_jwt_identity())
        actor = User.query.filter_by(id=actor_id).first() if actor_id else None
        if not actor:
            return _response(False, message="User not found", status=404)
        actor_role = str(getattr(actor.role, "value", actor.role)).strip().upper()
        if case.status != CaseStatus.PENDING_APPROVAL:
            return _response(False, message="Only pending approval cases can be approved or rejected", status=400)
        if actor_role not in {"ADMIN", "AUTHORIZER"}:
            return _response(False, message="Only Admins or Authorizers can approve or reject cases", status=403)

        old_status = case.status
        case.status = new_status

        db.session.add(
            AuditTrail(
                actor_user_id=actor.id,
                action="UPDATE_CASE_STATUS",
                entity_type="CASE",
                entity_id=case.id,
                details={"from": old_status.value, "to": new_status.value, "reason": data["reason"]},
            )
        )
        db.session.commit()
        return _response(
            True,
            data={
                "status_update": {
                    "id": str(case.id),
                    "from": old_status.value,
                    "to": case.status.value,
                    "reason": data["reason"],
                }
            },
            message="Case status updated",
        )


@cases_ns.route("/<string:case_id>/timeline")
class CaseTimelineResource(Resource):
    @jwt_required()
    def get(self, case_id):
        case_uuid = _to_uuid(case_id)
        if not case_uuid:
            return _response(False, message="Invalid case id", status=400)
        case = Case.query.filter_by(id=case_uuid).first()
        if not case:
            return _response(False, message="Case not found", status=404)

        audits = (
            AuditTrail.query.filter(
                ((AuditTrail.entity_type == "CASE") & (AuditTrail.entity_id == case.id))
                | (
                    (AuditTrail.entity_type == "EVIDENCE")
                    & (AuditTrail.entity_id.in_(db.session.query(Evidence.id).filter(Evidence.case_id == case.id)))
                )
            )
            .order_by(AuditTrail.occurred_at.asc())
            .all()
        )
        items = [
            {
                "id": audit.id,
                "actor_user_id": str(audit.actor_user_id) if audit.actor_user_id else None,
                "action": audit.action,
                "details": audit.details or {},
                "occurred_at": audit.occurred_at.isoformat() if audit.occurred_at else None,
            }
            for audit in audits
        ]
        return _response(True, data={"case_id": str(case.id), "timeline": items}, message="Case timeline fetched")
