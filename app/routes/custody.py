import logging
import uuid
from datetime import datetime

from flask import request
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restx import Namespace, Resource, fields

from app import db
from app.models.audit_trail import AuditTrail
from app.models.custody_log import CustodyAction, CustodyLog
from app.models.evidence import Evidence, EvidenceState
from app.models.user import User
from app.utils.access_logger import log_access

custody_ns = Namespace("custody", description="Custody transfer operations")
logger = logging.getLogger(__name__)

transfer_model = custody_ns.model(
    "CustodyTransferInput",
    {
        "transferred_to_user_id": fields.String(required=True),
        "reason": fields.String(required=True),
        "location": fields.String(required=True),
        "notes": fields.String(required=False),
    },
)

status_model = custody_ns.model(
    "EvidenceStatusUpdateInput",
    {
        "new_status": fields.String(required=True, enum=[s.value for s in EvidenceState]),
        "reason": fields.String(required=True),
        "notes": fields.String(required=False),
    },
)

ALLOWED_STATUS_FLOW = {
    EvidenceState.COLLECTED: EvidenceState.IN_TRANSIT,
    EvidenceState.IN_TRANSIT: EvidenceState.IN_ANALYSIS,
    EvidenceState.IN_ANALYSIS: EvidenceState.SECURED,
    EvidenceState.SECURED: EvidenceState.SUBMITTED_TO_COURT,
}

STATUS_TO_ACTION = {
    EvidenceState.IN_TRANSIT: CustodyAction.TRANSFERRED,
    EvidenceState.IN_ANALYSIS: CustodyAction.ANALYZED,
    EvidenceState.SECURED: CustodyAction.SECURED,
    EvidenceState.SUBMITTED_TO_COURT: CustodyAction.SUBMITTED_TO_COURT,
}


def _response(success, data=None, message="", status=200):
    return {"success": success, "data": data or {}, "message": message}, status


def _to_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _serialize_custody_entry(entry, previous_status):
    if entry.action == CustodyAction.TRANSFERRED:
        to_status = EvidenceState.IN_TRANSIT.value
    elif entry.action == CustodyAction.ANALYZED:
        to_status = EvidenceState.IN_ANALYSIS.value
    elif entry.action == CustodyAction.SECURED:
        to_status = EvidenceState.SECURED.value
    elif entry.action == CustodyAction.SUBMITTED_TO_COURT:
        to_status = EvidenceState.SUBMITTED_TO_COURT.value
    else:
        to_status = previous_status

    reason = None
    if entry.notes and "Reason: " in entry.notes:
        reason = entry.notes.split("Reason: ", 1)[1].split(" | Notes:", 1)[0]

    payload = {
        "id": entry.id,
        "who": str(entry.recorded_by_user_id),
        "when": entry.transferred_at.isoformat() if entry.transferred_at else None,
        "from_status": previous_status,
        "to_status": to_status,
        "reason": reason,
        "location": entry.location,
        "action": entry.action.value,
        "from_user_id": str(entry.from_user_id) if entry.from_user_id else None,
        "to_user_id": str(entry.to_user_id) if entry.to_user_id else None,
        "recorded_by_user_id": str(entry.recorded_by_user_id),
        "transferred_at": entry.transferred_at.isoformat() if entry.transferred_at else None,
        "notes": entry.notes,
    }
    return payload, to_status


def _identity_user():
    identity = _to_uuid(get_jwt_identity())
    if not identity:
        return None
    return User.query.filter_by(id=identity, is_active=True).first()


def _load_evidence_or_error(evidence_id):
    evidence_uuid = _to_uuid(evidence_id)
    if not evidence_uuid:
        return None, _response(False, message="Invalid evidence id", status=400)
    evidence = Evidence.query.filter_by(id=evidence_uuid).first()
    if not evidence:
        return None, _response(False, message="Evidence not found", status=404)
    return evidence, None


def _append_custody_log(*, evidence_id, from_user_id, to_user_id, action, location, reason, notes, recorded_by_user_id):
    # INSERT-only by design: never mutate existing records.
    entry = CustodyLog(
        evidence_id=evidence_id,
        from_user_id=from_user_id,
        to_user_id=to_user_id,
        action=action,
        location=location,
        notes=f"Reason: {reason}" + (f" | Notes: {notes}" if notes else ""),
        transferred_at=datetime.utcnow(),
        recorded_by_user_id=recorded_by_user_id,
    )
    db.session.add(entry)
    return entry


@custody_ns.route("/evidence/<string:evidence_id>/transfer")
class EvidenceTransferResource(Resource):
    @custody_ns.expect(transfer_model, validate=True)
    @jwt_required()
    def post(self, evidence_id):
        evidence, err = _load_evidence_or_error(evidence_id)
        if err:
            return err
        actor = _identity_user()
        if not actor:
            return _response(False, message="Authenticated user not found", status=404)

        payload = request.get_json() or {}
        to_user_id = _to_uuid(payload.get("transferred_to_user_id"))
        if not to_user_id:
            return _response(False, message="transferred_to_user_id must be a valid UUID", status=400)
        recipient = User.query.filter_by(id=to_user_id, is_active=True).first()
        if not recipient:
            return _response(False, message="Transfer recipient not found", status=404)
        if to_user_id == evidence.current_custodian_id:
            return _response(False, message="Evidence is already with this investigator", status=400)

        reason = (payload.get("reason") or "").strip()
        location = (payload.get("location") or "").strip()
        notes = payload.get("notes")
        if not reason:
            return _response(False, message="reason is required", status=400)
        if not location:
            return _response(False, message="location is required", status=400)

        previous_state = evidence.state
        previous_custodian = evidence.current_custodian_id
        evidence.current_custodian_id = to_user_id
        if evidence.state == EvidenceState.COLLECTED:
            evidence.state = EvidenceState.IN_TRANSIT

        log_entry = _append_custody_log(
            evidence_id=evidence.id,
            from_user_id=previous_custodian,
            to_user_id=to_user_id,
            action=CustodyAction.TRANSFERRED,
            location=location,
            reason=reason,
            notes=notes,
            recorded_by_user_id=actor.id,
        )
        db.session.add(
            AuditTrail(
                actor_user_id=actor.id,
                action="TRANSFER_CUSTODY",
                entity_type="EVIDENCE",
                entity_id=evidence.id,
                details={
                    "from_status": previous_state.value,
                    "to_status": evidence.state.value,
                    "transferred_to_user_id": str(to_user_id),
                    "reason": reason,
                    "location": location,
                },
            )
        )
        db.session.commit()
        log_access(evidence.id, actor.id, "TRANSFERRED", notes=reason, request=request)

        logger.info(
            "Custody transfer notification: evidence=%s from=%s to=%s location=%s",
            str(evidence.id),
            str(actor.id),
            str(to_user_id),
            location,
        )

        return _response(
            True,
            data={
                "custody_log_id": log_entry.id,
                "evidence_id": str(evidence.id),
                "from_user_id": str(previous_custodian) if previous_custodian else None,
                "to_user_id": str(to_user_id),
                "status": evidence.state.value,
            },
            message="Evidence transferred successfully",
            status=201,
        )


@custody_ns.route("/evidence/<string:evidence_id>/status")
class EvidenceStatusResource(Resource):
    @custody_ns.expect(status_model, validate=True)
    @jwt_required()
    def put(self, evidence_id):
        evidence, err = _load_evidence_or_error(evidence_id)
        if err:
            return err
        actor = _identity_user()
        if not actor:
            return _response(False, message="Authenticated user not found", status=404)

        payload = request.get_json() or {}
        reason = (payload.get("reason") or "").strip()
        notes = payload.get("notes")
        if not reason:
            return _response(False, message="reason is required", status=400)

        try:
            new_status = EvidenceState(payload.get("new_status"))
        except ValueError:
            return _response(False, message="Invalid new_status value", status=400)

        current_status = evidence.state
        expected_next = ALLOWED_STATUS_FLOW.get(current_status)
        if new_status == current_status:
            return _response(False, message="Evidence is already in that status", status=400)
        if expected_next != new_status:
            return _response(
                False,
                message=f"Invalid status transition from {current_status.value} to {new_status.value}",
                status=400,
            )

        evidence.state = new_status
        if new_status == EvidenceState.SUBMITTED_TO_COURT:
            evidence.submitted_to_court_at = datetime.utcnow()

        action = STATUS_TO_ACTION[new_status]
        log_entry = _append_custody_log(
            evidence_id=evidence.id,
            from_user_id=evidence.current_custodian_id,
            to_user_id=evidence.current_custodian_id,
            action=action,
            location=evidence.storage_location,
            reason=reason,
            notes=notes,
            recorded_by_user_id=actor.id,
        )
        db.session.add(
            AuditTrail(
                actor_user_id=actor.id,
                action="UPDATE_EVIDENCE_STATE",
                entity_type="EVIDENCE",
                entity_id=evidence.id,
                details={"from_status": current_status.value, "to_status": new_status.value, "reason": reason},
            )
        )
        db.session.commit()
        log_access(
            evidence.id,
            actor.id,
            "STATUS_CHANGED",
            notes=f"{current_status.value} -> {new_status.value}; reason: {reason}",
            request=request,
        )

        return _response(
            True,
            data={"custody_log_id": log_entry.id, "evidence_id": str(evidence.id), "new_status": new_status.value},
            message="Evidence status updated",
        )


@custody_ns.route("/custody-log/<string:evidence_id>")
class CustodyLogResource(Resource):
    @jwt_required()
    def get(self, evidence_id):
        evidence, err = _load_evidence_or_error(evidence_id)
        if err:
            return err

        logs = (
            CustodyLog.query.filter_by(evidence_id=evidence.id)
            .order_by(CustodyLog.transferred_at.asc())
            .all()
        )
        timeline = []
        previous_status = EvidenceState.COLLECTED.value
        for entry in logs:
            serialized, previous_status = _serialize_custody_entry(entry, previous_status)
            timeline.append(serialized)

        return _response(
            True,
            data={"evidence_id": str(evidence.id), "entries": timeline, "items": timeline, "timeline": timeline, "custody_records": timeline},
            message="Custody log fetched",
        )
