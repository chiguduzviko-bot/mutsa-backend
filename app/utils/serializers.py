"""
Shared serialization utilities for API responses.
Handles user denormalization, ISO timestamps, and consistent row shapes.
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from app.models.user import User


def resolve_user_name(user_id: str) -> Optional[str]:
    """Look up a user by ID and return their full name, or None."""
    if not user_id:
        return None
    try:
        user = User.query.filter_by(id=user_id).first()
        return user.full_name if user else None
    except Exception:
        return None


def resolve_user_role(user_id: str) -> Optional[str]:
    """Look up a user by ID and return their role value, or None."""
    if not user_id:
        return None
    try:
        user = User.query.filter_by(id=user_id).first()
        return user.role.value if user else None
    except Exception:
        return None


def to_iso_timestamp(dt: Optional[datetime]) -> Optional[str]:
    """Convert datetime to ISO 8601 format with Z suffix (UTC)."""
    if not dt:
        return None
    if not isinstance(dt, datetime):
        return None
    return dt.isoformat() + "Z"


def serialize_custody_record(
    custody_log: Any,
    include_ids: bool = True,
) -> Dict[str, Any]:
    """
    Serialize a custody log record with denormalized user names.
    Used consistently across all endpoints.
    
    Args:
        custody_log: CustodyLog model instance
        include_ids: Whether to include UUID fields
    
    Returns:
        Serialized custody record with user names resolved
    """
    from_name = resolve_user_name(str(custody_log.from_user_id)) if custody_log.from_user_id else None
    to_name = resolve_user_name(str(custody_log.to_user_id)) if custody_log.to_user_id else None
    recorded_by_name = resolve_user_name(str(custody_log.recorded_by_user_id)) if custody_log.recorded_by_user_id else None

    record = {
        "timestamp": to_iso_timestamp(custody_log.transferred_at),
        "transferred_at": to_iso_timestamp(custody_log.transferred_at),
        "action": custody_log.action.value if hasattr(custody_log.action, "value") else str(custody_log.action),
        "location": custody_log.location,
        "notes": custody_log.notes,
        "from_user_name": from_name,
        "to_user_name": to_name,
        "recorded_by_name": recorded_by_name,
    }
    
    if include_ids:
        record.update({
            "from_user_id": str(custody_log.from_user_id) if custody_log.from_user_id else None,
            "to_user_id": str(custody_log.to_user_id) if custody_log.to_user_id else None,
            "recorded_by_user_id": str(custody_log.recorded_by_user_id) if custody_log.recorded_by_user_id else None,
        })
    
    # Add received_at if available
    if hasattr(custody_log, 'received_at') and custody_log.received_at:
        record["received_at"] = to_iso_timestamp(custody_log.received_at)
    
    # Add created_at if available
    if hasattr(custody_log, 'created_at') and custody_log.created_at:
        record["created_at"] = to_iso_timestamp(custody_log.created_at)
    
    return record


def serialize_audit_log(audit_log: Any) -> Dict[str, Any]:
    """
    Serialize an audit log record with denormalized user info.
    Consistent shape across all audit endpoints.
    
    Args:
        audit_log: AuditLog model instance
    
    Returns:
        Serialized audit log record
    """
    return {
        "id": str(audit_log.id) if hasattr(audit_log, 'id') else None,
        "timestamp": to_iso_timestamp(audit_log.timestamp) if hasattr(audit_log, 'timestamp') else None,
        "user_id": str(audit_log.user_id) if hasattr(audit_log, 'user_id') and audit_log.user_id else None,
        "user_name": audit_log.user_name or "UNKNOWN",
        "user_role": (audit_log.user_role or "UNKNOWN").upper() if hasattr(audit_log, 'user_role') else "UNKNOWN",
        "action": audit_log.action,
        "case_number": audit_log.case_number,
        "evidence_ref": audit_log.evidence_ref,
        "details": audit_log.details,
        "hash_at_time": audit_log.hash_at_time,
        "hash_status": audit_log.hash_status or ("OK" if audit_log.hash_at_time else None),
    }


def serialize_user_response(user: Any, include_password: bool = False) -> Dict[str, Any]:
    """
    Serialize a user object for API responses.
    
    Args:
        user: User model instance
        include_password: Whether to include password_hash (should be False)
    
    Returns:
        Serialized user object
    """
    result = {
        "id": str(user.id),
        "employee_number": user.employee_number,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "role": user.role.value if hasattr(user.role, 'value') else str(user.role),
        "is_active": user.is_active,
        "created_at": to_iso_timestamp(user.created_at),
        "updated_at": to_iso_timestamp(user.updated_at),
    }
    return result


def serialize_evidence_for_list(
    evidence: Any,
    include_file_hash: bool = False,
    file_hash: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Serialize evidence for list responses.
    Includes hash info if available.
    
    Args:
        evidence: Evidence model instance
        include_file_hash: Whether to include file hash details
        file_hash: Optional FileHash model instance (latest)
    
    Returns:
        Serialized evidence object
    """
    result = {
        "id": str(evidence.id),
        "evidence_tag": evidence.evidence_tag,
        "title": evidence.title,
        "item_name": evidence.title,
        "file_name": file_hash.file_name if file_hash else None,
        "description": evidence.description,
        "evidence_type": evidence.evidence_type.value if hasattr(evidence.evidence_type, 'value') else str(evidence.evidence_type),
        "status": evidence.state.value if hasattr(evidence.state, 'value') else str(evidence.state),
        "state": evidence.state.value if hasattr(evidence.state, 'value') else str(evidence.state),
        "collected_at": to_iso_timestamp(evidence.collected_at),
        "storage_location": evidence.storage_location,
        "is_sensitive": evidence.is_sensitive,
        "created_at": to_iso_timestamp(evidence.created_at),
        "updated_at": to_iso_timestamp(evidence.updated_at),
    }
    
    if include_file_hash and file_hash:
        result.update({
            "sha256_hash": file_hash.sha256_hash,
            "file_hash": file_hash.sha256_hash,
            "hash_algorithm": file_hash.algorithm,
            "hashed_at": to_iso_timestamp(file_hash.hashed_at),
            "file_size_bytes": file_hash.file_size_bytes,
            "hash_status": "OK" if file_hash.sha256_hash else None,
        })
    
    return result


def serialize_case_for_list(
    case: Any,
    include_investigator_name: bool = True,
    evidence_count: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Serialize a case for list responses.
    Includes denormalized investigator name and optional evidence count.
    
    Args:
        case: Case model instance
        include_investigator_name: Whether to resolve and include assigned_user_name
        evidence_count: Optional evidence count to avoid N+1 queries
    
    Returns:
        Serialized case object
    """
    result = {
        "id": str(case.id),
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "fraud_type": case.fraud_type.value if hasattr(case.fraud_type, 'value') else str(case.fraud_type),
        "status": case.status.value if hasattr(case.status, 'value') else str(case.status),
        "incident_date": case.incident_date.isoformat() if case.incident_date else None,
        "created_at": to_iso_timestamp(case.created_at),
        "updated_at": to_iso_timestamp(case.updated_at),
        "assigned_to": str(case.assigned_user_id) if case.assigned_user_id else None,
    }
    
    if include_investigator_name:
        assigned_name = resolve_user_name(str(case.assigned_user_id)) if case.assigned_user_id else None
        result["assigned_user_name"] = assigned_name
        result["investigator_name"] = assigned_name
    
    if evidence_count is not None:
        result["evidence_count"] = evidence_count
    
    return result
