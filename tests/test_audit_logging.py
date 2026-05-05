"""Test audit logging for auditor dashboard."""
import uuid
from datetime import datetime

import pytest

from app import create_app, db
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole
from app.utils.audit_logger import log_audit


@pytest.fixture(scope="function")
def app():
    """Create a test Flask app with in-memory SQLite."""
    flask_app = create_app()
    flask_app.config["TESTING"] = True
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


class TestAuditLogging:
    """Test audit logging helper and endpoints."""

    def test_log_audit_basic(self, app):
        """Test basic audit log entry creation."""
        with app.app_context():
            # Create a user
            user = User(
                id=uuid.uuid4(),
                employee_number="EMP-001",
                full_name="Test Investigator",
                email="inv@test.local",
                role=UserRole.INVESTIGATOR,
                is_active=True,
            )
            db.session.add(user)
            db.session.commit()

            # Log an action
            log_audit(user, "LOGIN")

            # Verify entry was created
            entry = AuditLog.query.filter_by(action="LOGIN").first()
            assert entry is not None
            assert entry.user_id == user.id
            assert entry.user_name == "Test Investigator"
            assert entry.user_role == "INVESTIGATOR"
            assert entry.action == "LOGIN"

    def test_log_audit_with_case(self, app):
        """Test audit log with case reference."""
        from app.models.case import Case, CaseStatus, FraudType

        with app.app_context():
            user = User(
                id=uuid.uuid4(),
                employee_number="EMP-002",
                full_name="Test User",
                email="test@test.local",
                role=UserRole.INVESTIGATOR,
                is_active=True,
            )
            db.session.add(user)
            db.session.flush()

            case = Case(
                id=uuid.uuid4(),
                case_number="COC-2026-001",
                title="Test Case",
                description="Test",
                fraud_type=FraudType.SIM_SWAP,
                status=CaseStatus.PENDING_APPROVAL,
                opened_by_user_id=user.id,
            )
            db.session.add(case)
            db.session.commit()

            # Log case creation
            log_audit(user, "CASE_CREATED", case_obj=case, details="Created case: Test Case")

            # Verify entry
            entry = AuditLog.query.filter_by(action="CASE_CREATED").first()
            assert entry is not None
            assert entry.case_id == case.id
            assert entry.case_number == "COC-2026-001"
            assert entry.details == "Created case: Test Case"

    def test_log_audit_with_evidence_hash(self, app):
        """Test audit log for hash verification."""
        with app.app_context():
            user = User(
                id=uuid.uuid4(),
                employee_number="EMP-003",
                full_name="Auditor User",
                email="auditor@test.local",
                role=UserRole.AUDITOR,
                is_active=True,
            )
            db.session.add(user)
            db.session.commit()

            # Log hash verification
            test_hash = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
            log_audit(
                user,
                "HASH_VERIFIED",
                hash_at_time=test_hash,
                hash_status="OK",
            )

            # Verify entry
            entry = AuditLog.query.filter_by(action="HASH_VERIFIED").first()
            assert entry is not None
            assert entry.hash_at_time == test_hash
            assert entry.hash_status == "OK"

    def test_log_audit_handles_none_user(self, app):
        """Test that log_audit handles None user gracefully."""
        with app.app_context():
            # Should not raise
            log_audit(None, "TEST_ACTION", details="Test with None user")

            # Entry should still exist
            entry = AuditLog.query.filter_by(action="TEST_ACTION").first()
            assert entry is not None
            assert entry.user_id is None
            assert entry.user_name == "UNKNOWN"
            assert entry.user_role == "UNKNOWN"
