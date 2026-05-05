#!/usr/bin/env python
"""
Verification test for API improvements:
- ISO 8601 timestamps
- Denormalized user names
- Consistent custody record shapes
- Evidence counts on cases
"""
import json
from datetime import datetime
from app.utils.serializers import (
    to_iso_timestamp,
    serialize_custody_record,
    serialize_audit_log,
    serialize_user_response,
    serialize_case_for_list,
)
from app.models.user import User, UserRole
from app.models.case import Case, CaseStatus, FraudType
from app.models.custody_log import CustodyLog, CustodyAction
from app.models.audit_log import AuditLog
from app import create_app, db
import uuid

def test_iso_timestamps():
    """Verify all timestamps are ISO 8601 format with Z suffix."""
    app = create_app()
    with app.app_context():
        # Test to_iso_timestamp function
        dt = datetime(2026, 5, 5, 19, 38, 42, 197000)
        iso = to_iso_timestamp(dt)
        assert iso is not None, "ISO timestamp should not be None"
        assert iso.endswith("Z"), f"ISO timestamp should end with Z, got {iso}"
        assert "T" in iso, f"ISO timestamp should contain T separator, got {iso}"
        print(f"✓ ISO timestamp format: {iso}")
        
        # Test None handling
        iso_none = to_iso_timestamp(None)
        assert iso_none is None, "None should return None"
        print("✓ ISO timestamp handles None correctly")


def test_custody_record_serialization():
    """Verify custody records have consistent shape with denormalized names."""
    app = create_app()
    with app.app_context():
        # Create test data
        user1 = User(
            id=uuid.uuid4(),
            employee_number="EMP001",
            full_name="Officer Alice",
            email="alice@test.local",
            role=UserRole.INVESTIGATOR,
        )
        user1.set_password("test123")
        user2 = User(
            id=uuid.uuid4(),
            employee_number="EMP002",
            full_name="Officer Bob",
            email="bob@test.local",
            role=UserRole.INVESTIGATOR,
        )
        user2.set_password("test123")
        recorder = User(
            id=uuid.uuid4(),
            employee_number="EMP003",
            full_name="Recorder Charlie",
            email="charlie@test.local",
            role=UserRole.INVESTIGATOR,
        )
        recorder.set_password("test123")
        
        db.session.add_all([user1, user2, recorder])
        db.session.flush()
        
        case = Case(
            id=uuid.uuid4(),
            case_number="CASE-2026-001",
            title="Test Case",
            fraud_type=FraudType.PHISHING,
            status=CaseStatus.OPEN,
            incident_date=datetime.now().date(),
            opened_by_user_id=user1.id,
        )
        db.session.add(case)
        db.session.flush()
        
        custody_log = CustodyLog(
            evidence_id=uuid.uuid4(),
            from_user_id=user1.id,
            to_user_id=user2.id,
            action=CustodyAction.TRANSFERRED,
            location="Evidence Room A",
            notes="Test transfer",
            transferred_at=datetime.utcnow(),
            recorded_by_user_id=recorder.id,
        )
        db.session.add(custody_log)
        db.session.flush()
        
        # Serialize the custody record
        serialized = serialize_custody_record(custody_log, include_ids=True)
        
        # Verify required fields exist
        required_fields = [
            "timestamp", "transferred_at", "action", "location", "notes",
            "from_user_name", "to_user_name", "recorded_by_name",
            "from_user_id", "to_user_id", "recorded_by_user_id",
        ]
        for field in required_fields:
            assert field in serialized, f"Missing required field: {field}"
        
        # Verify denormalized names
        assert serialized["from_user_name"] == "Officer Alice", "from_user_name should be denormalized"
        assert serialized["to_user_name"] == "Officer Bob", "to_user_name should be denormalized"
        assert serialized["recorded_by_name"] == "Recorder Charlie", "recorded_by_name should be denormalized"
        
        # Verify ISO timestamps
        assert serialized["timestamp"].endswith("Z"), "timestamp should be ISO 8601 with Z"
        assert serialized["transferred_at"].endswith("Z"), "transferred_at should be ISO 8601 with Z"
        
        print("✓ Custody record has consistent shape with denormalized names")
        print(f"  Fields: {', '.join(serialized.keys())}")
        db.session.rollback()


def test_audit_log_serialization():
    """Verify audit logs have user_role and hash_status."""
    app = create_app()
    with app.app_context():
        audit_log = AuditLog(
            id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            user_name="Test User",
            user_role="AUDITOR",
            action="EVIDENCE_VIEWED",
            case_number="CASE-2026-001",
            evidence_ref="EV-001",
            details="Viewed evidence for audit",
            hash_at_time="abc123def456",
            hash_status="OK",
            timestamp=datetime.utcnow(),
        )
        
        serialized = serialize_audit_log(audit_log)
        
        # Verify required fields
        assert "user_role" in serialized, "Missing user_role field"
        assert "hash_status" in serialized, "Missing hash_status field"
        assert "timestamp" in serialized, "Missing timestamp field"
        
        # Verify values
        assert serialized["user_role"] == "AUDITOR", "user_role should be present"
        assert serialized["hash_status"] == "OK", "hash_status should be OK"
        assert serialized["timestamp"].endswith("Z"), "timestamp should be ISO 8601 with Z"
        
        print("✓ Audit log has user_role, hash_status, and ISO timestamp")
        print(f"  user_role: {serialized['user_role']}")
        print(f"  hash_status: {serialized['hash_status']}")
        print(f"  timestamp: {serialized['timestamp']}")


def test_user_response_serialization():
    """Verify user responses include all required fields."""
    app = create_app()
    with app.app_context():
        user = User(
            id=uuid.uuid4(),
            employee_number="EMP-TEST-001",
            full_name="Test Investigator",
            email="test@test.local",
            phone="+263771234567",
            role=UserRole.INVESTIGATOR,
            is_active=True,
        )
        user.set_password("test123")
        
        serialized = serialize_user_response(user)
        
        # Verify all required fields
        required_fields = [
            "id", "employee_number", "full_name", "email", "phone",
            "role", "is_active", "created_at", "updated_at",
        ]
        for field in required_fields:
            assert field in serialized, f"Missing required field: {field}"
        
        # Verify values
        assert serialized["employee_number"] == "EMP-TEST-001"
        assert serialized["full_name"] == "Test Investigator"
        assert serialized["role"] == "INVESTIGATOR"
        assert serialized["is_active"] is True
        
        # Verify ISO timestamps
        assert serialized["created_at"].endswith("Z"), "created_at should be ISO 8601 with Z"
        
        print("✓ User response includes all required fields")
        print(f"  Fields: {', '.join(serialized.keys())}")


def test_case_serialization():
    """Verify case responses include denormalized investigator name."""
    app = create_app()
    with app.app_context():
        investigator = User(
            id=uuid.uuid4(),
            employee_number="EMP-INV-001",
            full_name="Detective Smith",
            email="smith@test.local",
            role=UserRole.INVESTIGATOR,
        )
        investigator.set_password("test123")
        db.session.add(investigator)
        db.session.flush()
        
        case = Case(
            id=uuid.uuid4(),
            case_number="CASE-2026-TEST",
            title="Test Investigation",
            description="A test case for validation",
            fraud_type=FraudType.PHISHING,
            status=CaseStatus.OPEN,
            incident_date=datetime.now().date(),
            opened_by_user_id=investigator.id,
            assigned_user_id=investigator.id,
        )
        db.session.add(case)
        db.session.flush()
        
        serialized = serialize_case_for_list(case, include_investigator_name=True)
        
        # Verify denormalized names
        assert "assigned_user_name" in serialized, "Missing assigned_user_name"
        assert "investigator_name" in serialized, "Missing investigator_name"
        assert serialized["assigned_user_name"] == "Detective Smith", "assigned_user_name should be denormalized"
        assert serialized["investigator_name"] == "Detective Smith", "investigator_name should be denormalized"
        
        # Verify ISO timestamps
        assert serialized["created_at"].endswith("Z"), "created_at should be ISO 8601 with Z"
        
        print("✓ Case response includes denormalized investigator name")
        print(f"  investigator_name: {serialized['investigator_name']}")
        
        db.session.rollback()


if __name__ == "__main__":
    print("\n=== Testing API Improvements ===\n")
    
    try:
        test_iso_timestamps()
        test_custody_record_serialization()
        test_audit_log_serialization()
        test_user_response_serialization()
        test_case_serialization()
        
        print("\n✓ All tests passed! API improvements verified.\n")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}\n")
        exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}\n")
        import traceback
        traceback.print_exc()
        exit(1)
