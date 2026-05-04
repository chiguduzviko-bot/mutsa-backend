import os
import uuid
from datetime import datetime

from flask import request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required
from flask_restx import Namespace, Resource, fields
from werkzeug.utils import secure_filename

from app import db
from app.models.audit_trail import AuditTrail
from app.models.case import Case
from app.models.custody_log import CustodyAction, CustodyLog
from app.models.evidence import Evidence, EvidenceType
from app.models.file_hash import FileHash
from app.models.user import User
from app.utils.access_logger import log_access
from app.utils.decorators import requireRole
from app.utils.hashing import sha256_hash_file

evidence_ns = Namespace("evidence", description="Evidence management operations")

evidence_create_model = evidence_ns.model(
    "EvidenceCreateInput",
    {
        "description": fields.String(required=False),
        "evidence_type": fields.String(required=False, enum=[t.value for t in EvidenceType]),
        "source": fields.String(required=False),
        "collection_date": fields.String(required=False, description="ISO datetime"),
        "collected_by": fields.String(required=False, description="Collector user UUID; defaults to current user"),
        "notes": fields.String(required=False),
    },
)


def _response(success, data=None, message="", status=200):
    return {"success": success, "data": data or {}, "message": message}, status


def _to_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


def _uploads_root():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    uploads_dir = os.path.join(base_dir, "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    return uploads_dir


def _ensure_case(case_id):
    case_uuid = _to_uuid(case_id)
    if not case_uuid:
        return None, _response(False, message="Invalid case id", status=400)
    case = Case.query.filter_by(id=case_uuid).first()
    if not case:
        return None, _response(False, message="Case not found", status=404)
    return case, None


def _ensure_evidence(evidence_id):
    evidence_uuid = _to_uuid(evidence_id)
    if not evidence_uuid:
        return None, _response(False, message="Invalid evidence id", status=400)
    evidence = Evidence.query.filter_by(id=evidence_uuid).first()
    if not evidence:
        return None, _response(False, message="Evidence not found", status=404)
    return evidence, None


def _serialize_evidence(item):
    latest_hash = (
        FileHash.query.filter_by(evidence_id=item.id)
        .order_by(FileHash.hashed_at.desc())
        .first()
    )
    return {
        "id": str(item.id),
        "case_id": str(item.case_id),
        "evidence_tag": item.evidence_tag,
        "title": item.title,
        "description": item.description,
        "evidence_type": item.evidence_type.value,
        "source": item.source,
        "collection_date": item.collected_at.isoformat() if item.collected_at else None,
        "collected_by": str(item.collected_by_user_id),
        "notes": item.notes,
        "storage_location": item.storage_location,
        "sha256_hash": latest_hash.sha256_hash if latest_hash else None,
        "file_name": latest_hash.file_name if latest_hash else None,
    }


def _serialize_chain_entry(item):
    return {
        "id": item.id,
        "from_user_id": str(item.from_user_id) if item.from_user_id else None,
        "to_user_id": str(item.to_user_id) if item.to_user_id else None,
        "action": item.action.value,
        "location": item.location,
        "notes": item.notes,
        "transferred_at": item.transferred_at.isoformat() if item.transferred_at else None,
        "recorded_by_user_id": str(item.recorded_by_user_id),
    }


def _first_non_empty(mapping, *keys):
    for key in keys:
        value = mapping.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _first_file(files, *keys):
    for key in keys:
        item = files.get(key)
        if item and item.filename:
            return item
    return None


def _parse_or_infer_evidence_type(raw_value, file_name, mime_type):
    if raw_value:
        normalized = str(raw_value).strip().upper().replace("-", "_").replace(" ", "_")
        aliases = {
            "DIGITAL": "DIGITAL_FILE",
            "DIGITAL_EVIDENCE": "DIGITAL_FILE",
            "FILE": "DIGITAL_FILE",
            "DOCUMENT": "DIGITAL_FILE",
            "PHOTO": "DIGITAL_FILE",
            "IMAGE": "DIGITAL_FILE",
            "PICTURE": "DIGITAL_FILE",
            "VIDEO": "DIGITAL_FILE",
            "SCREEN_SHOT": "SCREENSHOT",
            "LOG": "TRANSACTION_LOG",
            "TRANSACTION": "TRANSACTION_LOG",
        }
        normalized = aliases.get(normalized, normalized)
        try:
            return EvidenceType(normalized)
        except ValueError:
            pass

    extension = os.path.splitext(file_name or "")[1].lower().lstrip(".")
    image_extensions = {"png", "jpg", "jpeg", "bmp", "gif", "webp", "tiff"}
    log_extensions = {"csv", "xls", "xlsx", "log", "txt", "json", "xml"}
    document_extensions = {"pdf", "doc", "docx", "ppt", "pptx", "odt", "rtf"}
    video_extensions = {"mp4", "mov", "avi", "mkv", "wmv", "webm", "m4v"}
    audio_extensions = {"mp3", "wav", "aac", "ogg", "m4a"}
    archive_extensions = {"zip", "rar", "7z", "tar", "gz"}

    if extension in log_extensions:
        return EvidenceType.TRANSACTION_LOG
    if extension in image_extensions:
        return EvidenceType.SCREENSHOT
    if extension in document_extensions or extension in video_extensions or extension in audio_extensions or extension in archive_extensions:
        return EvidenceType.DIGITAL_FILE

    mime = (mime_type or "").lower()
    if mime.startswith("image/"):
        return EvidenceType.SCREENSHOT
    if mime.startswith(("video/", "audio/", "application/", "text/")):
        return EvidenceType.DIGITAL_FILE

    return EvidenceType.DIGITAL_FILE


@evidence_ns.route("/cases/<string:case_id>/evidence")
class CaseEvidenceCollectionResource(Resource):
    @evidence_ns.expect(evidence_create_model, validate=False)
    @requireRole("ADMIN", "INVESTIGATOR")
    @jwt_required()
    def post(self, case_id):
        case, err = _ensure_case(case_id)
        if err:
            return err

        form = request.form
        uploaded = _first_file(request.files, "file", "evidence_file", "evidenceFile", "attachment", "document", "upload")
        if not uploaded:
            return _response(False, message="File upload is required (field name: file)", status=400)

        actor_id = _to_uuid(get_jwt_identity())
        collector_raw = _first_non_empty(form, "collected_by", "collectedBy", "collector_id", "collectorId")
        collector_id = _to_uuid(collector_raw) if collector_raw else actor_id
        if not collector_id:
            return _response(False, message="Invalid collected_by UUID", status=400)
        if not User.query.filter_by(id=collector_id).first():
            return _response(False, message="Collector user not found", status=404)

        safe_name = secure_filename(uploaded.filename)
        if not safe_name:
            return _response(False, message="Invalid file name", status=400)

        evidence_type_raw = _first_non_empty(form, "evidence_type", "evidenceType", "type", "evidence_category")
        evidence_type = _parse_or_infer_evidence_type(evidence_type_raw, safe_name, uploaded.mimetype)

        evidence_id = uuid.uuid4()
        evidence_tag = f"EV-{str(evidence_id)[:8].upper()}"
        case_dir = os.path.join(_uploads_root(), str(case.id))
        os.makedirs(case_dir, exist_ok=True)
        stored_name = f"{str(evidence_id)}_{safe_name}"
        abs_path = os.path.join(case_dir, stored_name)
        uploaded.save(abs_path)

        with open(abs_path, "rb") as fp:
            digest = sha256_hash_file(fp)
            size_bytes = os.path.getsize(abs_path)

        collection_date_raw = form.get("collection_date")
        collection_date = datetime.utcnow()
        if collection_date_raw:
            try:
                collection_date = datetime.fromisoformat(collection_date_raw.replace("Z", "+00:00"))
            except ValueError:
                return _response(False, message="collection_date must be ISO format", status=400)

        evidence = Evidence(
            id=evidence_id,
            case_id=case.id,
            evidence_tag=evidence_tag,
            title=safe_name,
            description=form.get("description"),
            evidence_type=evidence_type,
            source=form.get("source"),
            notes=form.get("notes"),
            collected_by_user_id=collector_id,
            current_custodian_id=collector_id,
            collected_at=collection_date,
            storage_location=abs_path,
        )
        db.session.add(evidence)
        db.session.flush()

        file_hash = FileHash(
            evidence_id=evidence.id,
            algorithm="SHA-256",
            sha256_hash=digest,
            file_name=safe_name,
            file_size_bytes=size_bytes,
            hashed_by_user_id=collector_id,
            is_current=True,
        )
        db.session.add(file_hash)

        custody_log = CustodyLog(
            evidence_id=evidence.id,
            from_user_id=None,
            to_user_id=collector_id,
            action=CustodyAction.COLLECTED,
            location=abs_path,
            notes=form.get("notes"),
            transferred_at=collection_date,
            recorded_by_user_id=collector_id,
        )
        db.session.add(custody_log)

        db.session.add(
            AuditTrail(
                actor_user_id=actor_id,
                action="ADD_EVIDENCE",
                entity_type="EVIDENCE",
                entity_id=evidence.id,
                details={"case_id": str(case.id), "sha256": digest},
            )
        )
        db.session.commit()

        return _response(
            True,
            data={
                "id": str(evidence.id),
                "case_id": str(evidence.case_id),
                "evidence_tag": evidence.evidence_tag,
                "file_name": safe_name,
                "sha256_hash": digest,
                "stored_path": abs_path,
            },
            message="Evidence logged successfully",
            status=201,
        )

    @requireRole("ADMIN", "INVESTIGATOR")
    @jwt_required()
    def get(self, case_id):
        case, err = _ensure_case(case_id)
        if err:
            return err
        items = Evidence.query.filter_by(case_id=case.id).order_by(Evidence.created_at.desc()).all()
        serialized_items = [_serialize_evidence(item) for item in items]
        return _response(
            True,
            data={"case_id": str(case.id), "items": serialized_items, "evidence": serialized_items, "evidences": serialized_items},
            message="Evidence list fetched",
        )


@evidence_ns.route("/cases/<string:case_id>/evidences")
class CaseEvidencesAliasResource(Resource):
    @requireRole("ADMIN", "INVESTIGATOR")
    @jwt_required()
    def get(self, case_id):
        case, err = _ensure_case(case_id)
        if err:
            return err
        items = Evidence.query.filter_by(case_id=case.id).order_by(Evidence.created_at.desc()).all()
        serialized_items = [_serialize_evidence(item) for item in items]
        return _response(
            True,
            data={"case_id": str(case.id), "items": serialized_items, "evidence": serialized_items, "evidences": serialized_items},
            message="Evidence list fetched",
        )


@evidence_ns.route("/evidence/<string:evidence_id>")
class EvidenceDetailResource(Resource):
    @jwt_required()
    def get(self, evidence_id):
        evidence, err = _ensure_evidence(evidence_id)
        if err:
            return err
        actor_id = _to_uuid(get_jwt_identity())

        custody = (
            CustodyLog.query.filter_by(evidence_id=evidence.id)
            .order_by(CustodyLog.transferred_at.asc())
            .all()
        )
        chain = [_serialize_chain_entry(item) for item in custody]

        payload = _serialize_evidence(evidence)
        payload["custody_history"] = chain
        payload["chain_of_custody"] = chain
        payload["custody_records"] = chain
        if actor_id:
            log_access(evidence.id, actor_id, "VIEWED", request=request)
        return _response(True, data=payload, message="Evidence details fetched")


@evidence_ns.route("/evidence/<string:evidence_id>/verify-hash")
class EvidenceVerifyHashResource(Resource):
    @jwt_required()
    def get(self, evidence_id):
        evidence, err = _ensure_evidence(evidence_id)
        if err:
            return err

        current_hash_row = (
            FileHash.query.filter_by(evidence_id=evidence.id, is_current=True)
            .order_by(FileHash.hashed_at.desc())
            .first()
        )
        if not current_hash_row:
            return _response(False, message="Original hash not found for evidence", status=404)

        return _response(
            True,
            data={
                "evidence_id": str(evidence.id),
                "algorithm": current_hash_row.algorithm,
                "original_hash": current_hash_row.sha256_hash,
                "sha256_hash": current_hash_row.sha256_hash,
                "file_name": current_hash_row.file_name,
                "file_size_bytes": current_hash_row.file_size_bytes,
                "hashed_at": current_hash_row.hashed_at.isoformat() if current_hash_row.hashed_at else None,
            },
            message="Current hash fetched",
        )

    @jwt_required()
    def post(self, evidence_id):
        evidence, err = _ensure_evidence(evidence_id)
        if err:
            return err
        if "file" not in request.files:
            return _response(False, message="File upload is required (field name: file)", status=400)

        original_hash_row = (
            FileHash.query.filter_by(evidence_id=evidence.id, is_current=True)
            .order_by(FileHash.hashed_at.desc())
            .first()
        )
        if not original_hash_row:
            return _response(False, message="Original hash not found for evidence", status=404)

        uploaded = request.files["file"]
        if not uploaded or not uploaded.filename:
            return _response(False, message="Uploaded file is empty", status=400)

        computed_hash = sha256_hash_file(uploaded.stream)
        original_hash = original_hash_row.sha256_hash
        match = computed_hash == original_hash
        integrity_status = "INTACT" if match else "TAMPERED"

        actor_id = _to_uuid(get_jwt_identity())
        db.session.add(
            AuditTrail(
                actor_user_id=actor_id,
                action="VERIFY_HASH",
                entity_type="EVIDENCE",
                entity_id=evidence.id,
                details={
                    "match": match,
                    "integrity_status": integrity_status,
                    "original_hash": original_hash,
                    "computed_hash": computed_hash,
                },
            )
        )
        db.session.commit()
        if actor_id:
            log_access(evidence.id, actor_id, "HASH_VERIFIED", request=request)

        return _response(
            True,
            data={
                "match": match,
                "is_valid": match,
                "original_hash": original_hash,
                "computed_hash": computed_hash,
                "integrity_status": integrity_status,
            },
            message="Hash verification completed",
        )


@evidence_ns.route("/evidence/<string:evidence_id>/download")
class EvidenceDownloadResource(Resource):
    @jwt_required()
    def get(self, evidence_id):
        evidence, err = _ensure_evidence(evidence_id)
        if err:
            return err

        current_hash_row = (
            FileHash.query.filter_by(evidence_id=evidence.id, is_current=True)
            .order_by(FileHash.hashed_at.desc())
            .first()
        )
        if not current_hash_row:
            return _response(False, message="No file metadata found for evidence", status=404)
        if not evidence.storage_location or not os.path.exists(evidence.storage_location):
            return _response(False, message="Stored evidence file not found", status=404)

        actor_id = _to_uuid(get_jwt_identity())
        if actor_id:
            log_access(evidence.id, actor_id, "DOWNLOADED", request=request)

        return send_file(
            evidence.storage_location,
            as_attachment=True,
            download_name=current_hash_row.file_name or os.path.basename(evidence.storage_location),
        )


@evidence_ns.route("/evidence/<string:evidence_id>/chain")
class EvidenceChainResource(Resource):
    @jwt_required()
    def get(self, evidence_id):
        evidence, err = _ensure_evidence(evidence_id)
        if err:
            return err
        custody = (
            CustodyLog.query.filter_by(evidence_id=evidence.id)
            .order_by(CustodyLog.transferred_at.asc())
            .all()
        )
        chain = [_serialize_chain_entry(item) for item in custody]
        return _response(
            True,
            data={"evidence_id": str(evidence.id), "chain_of_custody": chain, "entries": chain, "custody_history": chain},
            message="Chain of custody fetched",
        )
