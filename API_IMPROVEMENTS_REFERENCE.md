# API Improvements Quick Reference

## Key Usage Examples

### Using ISO Timestamps (everywhere)
```python
from app.utils.serializers import to_iso_timestamp
from datetime import datetime

dt = datetime.utcnow()
iso_str = to_iso_timestamp(dt)  # Returns: "2026-05-05T19:38:42Z"
```

### Denormalizing User Names (in responses)
```python
from app.utils.serializers import resolve_user_name
import uuid

user_uuid = "550e8400-e29b-41d4-a716-446655440000"
name = resolve_user_name(user_uuid)  # Returns: "Alice Smith" or None
```

### Consistent Custody Records
```python
from app.utils.serializers import serialize_custody_record
from app.models.custody_log import CustodyLog

custody = CustodyLog.query.first()
serialized = serialize_custody_record(custody, include_ids=True)

# Returns object with all fields:
# - timestamp, transferred_at (ISO 8601)
# - from_user_name, to_user_name, recorded_by_name (denormalized)
# - from_user_id, to_user_id, recorded_by_user_id (UUIDs)
# - action, location, notes, received_at, created_at
```

### Case with Denormalized Investigator and Evidence Count
```python
@cases_ns.route("")
class CaseListResource(Resource):
    def get(self):
        cases = Case.query.all()
        # Use with include_evidence_count=True in list view
        items = [_serialize_case(c, include_evidence_count=True) for c in cases]
        return {"cases": items}

# Each case now has:
# - assigned_user_name: "Detective Smith" (instead of raw UUID)
# - investigator_name: "Detective Smith" (alias)
# - evidence_count: 3 (from efficient single query)
```

### User Response with All Fields
```python
from app.utils.serializers import serialize_user_response

user = User.query.first()
response = serialize_user_response(user)

# Always includes: id, employee_number, full_name, email, phone,
#                  role, is_active, created_at, updated_at (all ISO 8601)
```

### Audit Log with User Role and Hash Status
```python
from app.utils.serializers import serialize_audit_log

log = AuditLog.query.first()
serialized = serialize_audit_log(log)

# Includes: user_role, hash_status (both denormalized/computed)
# timestamp in ISO 8601 format
```

## Response Examples

### Cases List
```json
{
  "cases": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "case_number": "CASE-20260505-ABC123",
      "title": "Phishing Attack Investigation",
      "assigned_to": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "assigned_user_name": "Detective Alice Smith",
      "investigator_name": "Detective Alice Smith",
      "evidence_count": 5,
      "created_at": "2026-05-05T19:38:42Z",
      "updated_at": "2026-05-05T19:38:42Z"
    }
  ]
}
```

### Evidence Detail with Custody History
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "evidence_tag": "EV-2026-001",
  "title": "Suspect Device Phone",
  "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hashed_at": "2026-05-05T19:38:42Z",
  "hash_status": "OK",
  "custody_history": [
    {
      "timestamp": "2026-05-05T10:00:00Z",
      "action": "COLLECTED",
      "location": "Suspect House",
      "from_user_name": "Officer Alice",
      "to_user_name": "Officer Bob",
      "recorded_by_name": "Officer Charlie",
      "notes": "Collected as evidence"
    },
    {
      "timestamp": "2026-05-05T14:30:00Z",
      "action": "TRANSFERRED",
      "location": "Evidence Room",
      "from_user_name": "Officer Bob",
      "to_user_name": "Analyst Diana",
      "recorded_by_name": "Officer Charlie",
      "notes": "Transferred for analysis"
    }
  ]
}
```

### Audit Log with User Role
```json
{
  "logs": [
    {
      "timestamp": "2026-05-05T19:38:42Z",
      "user_name": "Alice Smith",
      "user_role": "AUDITOR",
      "action": "EVIDENCE_VIEWED",
      "case_number": "CASE-20260505-ABC123",
      "evidence_ref": "EV-2026-001",
      "details": "Viewed evidence for audit purposes",
      "hash_at_time": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "hash_status": "OK"
    }
  ]
}
```

### Admin Access Log Export (CSV)
```csv
timestamp,user_name,user_role,badge_number,action,evidence_ref,case_number,hash_at_time,hash_status,session_event,ip_address
2026-05-05T19:38:42Z,Alice Smith,INVESTIGATOR,EMP-001,EVIDENCE_VIEWED,EV-2026-001,CASE-20260505-ABC123,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,OK,,192.168.1.100
2026-05-05T18:45:00Z,Bob Johnson,AUDITOR,EMP-002,HASH_VERIFIED,EV-2026-002,CASE-20260505-XYZ789,,OK,,192.168.1.101
```

## Testing the Changes

### Quick Import Verification
```bash
python -c "from app.utils.serializers import *; print('✓ All imports successful')"
```

### Test ISO Timestamps
```python
from app.utils.serializers import to_iso_timestamp
from datetime import datetime

dt = datetime(2026, 5, 5, 19, 38, 42)
assert to_iso_timestamp(dt).endswith("Z")
assert "T" in to_iso_timestamp(dt)
```

### Test User Denormalization
```python
from app.utils.serializers import resolve_user_name
from app.models.user import User

user = User.query.first()
name = resolve_user_name(str(user.id))
assert name == user.full_name
```

## Integration Notes

### For Frontend Developers
1. All list and detail views now include denormalized `*_name` fields
2. No need for separate API calls to get user names
3. Timestamps are always `YYYY-MM-DDTHH:MM:SSZ` format
4. Optional `evidence_count` can be used for case summary tiles

### For Data Analysts
1. CSV exports now include `hash_status` and `user_role`
2. Custody records have consistent structure
3. All timestamps suitable for aggregation/analysis
4. User information preserved in access logs

### For Backend Developers
1. Add new denormalized fields to responses without breaking existing code
2. Import serializers for consistent formatting:
   ```python
   from app.utils.serializers import (
       to_iso_timestamp,
       serialize_custody_record,
       serialize_audit_log,
       # etc.
   )
   ```
3. Never mutate existing serialization functions; extend them instead
