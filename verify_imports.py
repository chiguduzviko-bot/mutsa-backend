#!/usr/bin/env python
"""Quick verification that all new code imports successfully."""

try:
    print("Importing serializers...")
    from app.utils.serializers import (
        resolve_user_name,
        resolve_user_role,
        to_iso_timestamp,
        serialize_custody_record,
        serialize_audit_log,
        serialize_user_response,
        serialize_evidence_for_list,
        serialize_case_for_list,
    )
    print("✓ Serializers module imported successfully")
    
    print("\nImporting routes...")
    from app.routes.cases import _serialize_case
    from app.routes.evidence import _serialize_evidence, _serialize_chain_entry
    from app.routes.audit import _serialize_log
    from app.routes.admin import _serialize_user, _serialize_log_row
    from app.routes.custody import _serialize_custody_entry
    print("✓ All routes imported successfully")
    
    print("\nImporting models...")
    from app.models.user import User, UserRole
    from app.models.case import Case, CaseStatus, FraudType
    from app.models.custody_log import CustodyLog, CustodyAction
    from app.models.audit_log import AuditLog
    print("✓ All models imported successfully")
    
    print("\n✓ All imports successful! Code structure is valid.\n")
    
except Exception as e:
    print(f"\n✗ Import failed: {e}\n")
    import traceback
    traceback.print_exc()
    exit(1)
