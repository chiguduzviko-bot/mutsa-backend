# Chain of Custody API - Complete Contract Documentation

## Overview

This document defines the complete API contract for the Chain of Custody Evidence Tracking system. The API is designed to eliminate frontend fallbacks by providing a single, clear contract for each resource type.

**Base URL**: `https://api.example.com/api` (or local: `http://localhost:5000/api`)

**Authentication**: All endpoints require JWT Bearer token in `Authorization` header.

---

## 1. Evidence Management

### 1.1 List All Evidence

**Endpoint**: `GET /api/evidence`

**Authentication**: Required (INVESTIGATOR, AUDITOR, AUTHORIZER, ADMIN)

**RBAC Rules**:
- `INVESTIGATOR`: See only evidence they collected or currently hold custody of
- `AUDITOR`, `AUTHORIZER`, `ADMIN`: See all evidence

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | integer | Page number (default: 1) |
| `per_page` | integer | Items per page, max 100 (default: 20) |
| `case_id` | UUID | Filter by case ID |
| `status` | string | Filter by evidence status (e.g., COLLECTED, IN_TRANSIT, SECURED) |

**Request**:
```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/evidence?page=1&per_page=20"
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "evidence": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
        "case_id": "550e8400-e29b-41d4-a716-446655440001",
        "evidence_tag": "EV-550E8400",
        "title": "document.pdf",
        "item_name": "document.pdf",
        "file_name": "document.pdf",
        "description": "Invoice from suspect",
        "evidence_type": "DIGITAL_FILE",
        "status": "SECURED",
        "state": "SECURED",
        "source": "Email",
        "collection_date": "2026-05-05T12:00:00Z",
        "collected_at": "2026-05-05T12:00:00Z",
        "collected_by": "550e8400-e29b-41d4-a716-446655440002",
        "notes": "Encrypted email attachment",
        "storage_location": "/uploads/case-id/evidence-id_document.pdf",
        "sha256_hash": "abc123def456...",
        "file_hash": "abc123def456...",
        "hashed_at": "2026-05-05T12:01:00Z",
        "hash_status": "OK",
        "created_at": "2026-05-05T12:00:00Z",
        "updated_at": "2026-05-05T12:01:00Z"
      }
    ],
    "items": [...],
    "total": 42,
    "page": 1,
    "per_page": 20,
    "pages": 3
  },
  "message": "All evidence fetched"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid pagination or filter parameters
- `403 Forbidden`: User role not authorized
- `401 Unauthorized`: Missing or invalid JWT

---

### 1.2 Get Single Evidence by ID

**Endpoint**: `GET /api/evidence/evidence/:evidenceId` *(canonical)*
**Also Works**: `GET /api/evidence/:evidenceId` *(backward compat)*

**Authentication**: Required (INVESTIGATOR, AUDITOR)

**URL Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `evidenceId` | UUID | Evidence resource ID |

**Request**:
```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/evidence/evidence/550e8400-e29b-41d4-a716-446655440000"
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
    "case_id": "550e8400-e29b-41d4-a716-446655440001",
    "evidence_tag": "EV-550E8400",
    "title": "document.pdf",
    "item_name": "document.pdf",
    "file_name": "document.pdf",
    "description": "Invoice from suspect",
    "evidence_type": "DIGITAL_FILE",
    "status": "SECURED",
    "state": "SECURED",
    "source": "Email",
    "collection_date": "2026-05-05T12:00:00Z",
    "collected_at": "2026-05-05T12:00:00Z",
    "collected_by": "550e8400-e29b-41d4-a716-446655440002",
    "notes": "Encrypted email attachment",
    "storage_location": "/uploads/case-id/evidence-id_document.pdf",
    "sha256_hash": "abc123def456...",
    "file_hash": "abc123def456...",
    "hashed_at": "2026-05-05T12:01:00Z",
    "hash_status": "OK",
    "created_at": "2026-05-05T12:00:00Z",
    "updated_at": "2026-05-05T12:01:00Z",
    "custody_history": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440050",
        "timestamp": "2026-05-05T12:00:00Z",
        "transferred_at": "2026-05-05T12:00:00Z",
        "action": "TRANSFERRED",
        "location": "Evidence Room A",
        "notes": "Initial collection",
        "from_user_id": "550e8400-e29b-41d4-a716-446655440002",
        "from_user_name": "Jane Investigator",
        "to_user_id": "550e8400-e29b-41d4-a716-446655440003",
        "to_user_name": "John Analyst",
        "recorded_by_user_id": "550e8400-e29b-41d4-a716-446655440002",
        "recorded_by_name": "Jane Investigator"
      }
    ],
    "chain_of_custody": [...],
    "custody_records": [...]
  },
  "message": "Evidence details fetched"
}
```

**Error Responses**:
- `400 Bad Request`: Invalid evidence ID format
- `404 Not Found`: Evidence not found
- `403 Forbidden`: User not authorized
- `401 Unauthorized`: Missing or invalid JWT

---

### 1.3 Verify Hash - Get Metadata

**Endpoint**: `GET /api/evidence/evidence/:evidenceId/verify-hash`

**Authentication**: Required (INVESTIGATOR, AUDITOR)

**URL Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `evidenceId` | UUID | Evidence resource ID |

**Request**:
```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/evidence/evidence/550e8400-e29b-41d4-a716-446655440000/verify-hash"
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
    "algorithm": "SHA-256",
    "original_hash": "abc123def456...",
    "sha256_hash": "abc123def456...",
    "file_name": "document.pdf",
    "file_size_bytes": 245632,
    "hashed_at": "2026-05-05T12:01:00Z"
  },
  "message": "Current hash fetched"
}
```

---

### 1.4 Verify Hash - Compute and Compare

**Endpoint**: `POST /api/evidence/evidence/:evidenceId/verify-hash`

**Authentication**: Required (INVESTIGATOR, AUDITOR)

**URL Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `evidenceId` | UUID | Evidence resource ID |

**Request** (multipart/form-data):
```bash
curl -X POST \
  -H "Authorization: Bearer <token>" \
  -F "file=@document.pdf" \
  "https://api.example.com/api/evidence/evidence/550e8400-e29b-41d4-a716-446655440000/verify-hash"
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "match": true,
    "is_valid": true,
    "original_hash": "abc123def456...",
    "computed_hash": "abc123def456...",
    "integrity_status": "INTACT"
  },
  "message": "Hash verification completed"
}
```

**Response (200 - Tampered)**:
```json
{
  "success": true,
  "data": {
    "match": false,
    "is_valid": false,
    "original_hash": "abc123def456...",
    "computed_hash": "xyz789abc111...",
    "integrity_status": "TAMPERED"
  },
  "message": "Hash verification completed"
}
```

---

## 2. Cases Management

### 2.1 List All Cases

**Endpoint**: `GET /api/cases`

**Authentication**: Required (INVESTIGATOR, AUTHORIZER)

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | integer | Page number (default: 1) |
| `per_page` | integer | Items per page, max 100 (default: 10) |
| `status` | string | Filter by case status (PENDING_APPROVAL, OPEN, REJECTED, CLOSED) |
| `fraud_type` | string | Filter by fraud type |
| `assigned_to` | UUID | Filter by assignee (matches created_by OR assigned_to) |
| `created_by` | UUID | Filter by creator |

**Request**:
```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/cases?page=1&per_page=10"
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440001",
        "case_number": "CASE-20260505-ABC123",
        "title": "SMS Fraud - Account Takeover",
        "description": "Suspect obtained OTP and transferred funds",
        "suspect_info": "Phone: +27123456789, Email: suspect@example.com",
        "fraud_type": "SIM_SWAP",
        "status": "OPEN",
        "incident_date": "2026-05-03",
        "assigned_to": "550e8400-e29b-41d4-a716-446655440010",
        "assigned_user_name": "Jane Investigator",
        "investigator_name": "Jane Investigator",
        "created_by_id": "550e8400-e29b-41d4-a716-446655440010",
        "created_by_name": "Jane Investigator",
        "creator_name": "Jane Investigator",
        "opened_by_user_id": "550e8400-e29b-41d4-a716-446655440010",
        "evidence_count": 5,
        "created_at": "2026-05-05T10:00:00Z",
        "updated_at": "2026-05-05T11:30:00Z"
      }
    ],
    "cases": [...],
    "total": 42,
    "page": 1,
    "per_page": 10
  },
  "message": "Cases fetched"
}
```

**Special Rules**:
- If user is `AUTHORIZER` and no status filter provided, defaults to `PENDING_APPROVAL`
- Results ordered by most recent first

---

### 2.2 Get Single Case

**Endpoint**: `GET /api/cases/:caseId`

**Authentication**: Required (INVESTIGATOR, AUTHORIZER)

**URL Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `caseId` | UUID | Case resource ID |

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "case_number": "CASE-20260505-ABC123",
    "title": "SMS Fraud - Account Takeover",
    "description": "Suspect obtained OTP and transferred funds",
    "suspect_info": "Phone: +27123456789, Email: suspect@example.com",
    "fraud_type": "SIM_SWAP",
    "status": "OPEN",
    "incident_date": "2026-05-03",
    "assigned_to": "550e8400-e29b-41d4-a716-446655440010",
    "assigned_user_name": "Jane Investigator",
    "investigator_name": "Jane Investigator",
    "created_by_id": "550e8400-e29b-41d4-a716-446655440010",
    "created_by_name": "Jane Investigator",
    "creator_name": "Jane Investigator",
    "opened_by_user_id": "550e8400-e29b-41d4-a716-446655440010",
    "created_at": "2026-05-05T10:00:00Z",
    "updated_at": "2026-05-05T11:30:00Z",
    "evidence": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
        "evidence_tag": "EV-550E8400",
        "title": "document.pdf"
      }
    ]
  },
  "message": "Case details fetched"
}
```

---

### 2.3 Create Case

**Endpoint**: `POST /api/cases`

**Authentication**: Required (INVESTIGATOR)

**Request Body**:
```json
{
  "title": "SMS Fraud Investigation",
  "fraud_type": "SIM_SWAP",
  "description": "Optional description",
  "suspect_info": "Optional suspect details",
  "assigned_to": "550e8400-e29b-41d4-a716-446655440020"
}
```

**Behavior**:
- If `assigned_to` not provided, defaults to the creator (authenticated user)
- INVESTIGATOR-created cases start in `PENDING_APPROVAL` status
- AUTHORIZER-created cases start in `OPEN` status
- Case number auto-generated as `CASE-YYYYMMDD-XXXXXX`

**Response (201 Created)**:
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "case_number": "CASE-20260505-ABC123"
  },
  "message": "Case created",
  "status": 201
}
```

---

### 2.4 Update Case

**Endpoint**: `PUT /api/cases/:caseId`

**Authentication**: Required (INVESTIGATOR for field updates, AUTHORIZER for status)

**Request Body** (INVESTIGATOR):
```json
{
  "title": "Updated title",
  "description": "Updated description",
  "suspect_info": "Updated suspect info",
  "fraud_type": "PHISHING",
  "assigned_to": "550e8400-e29b-41d4-a716-446655440020"
}
```

**Request Body** (AUTHORIZER - for case approval):
```json
{
  "status": "OPEN",
  "reason": "Case approved for investigation"
}
```

**Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "case_number": "CASE-20260505-ABC123",
    "title": "Updated title",
    ...
  },
  "message": "Case updated"
}
```

---

## 3. Audit & Monitoring

### 3.1 Audit Logs

**Endpoint**: `GET /api/audit/logs`

**Response Format**:
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "timestamp": "2026-05-05T12:30:00Z",
        "user_name": "Jane Investigator",
        "user_role": "INVESTIGATOR",
        "action": "HASH_VERIFIED",
        "case_number": "CASE-20260505-ABC123",
        "evidence_ref": "550e8400-e29b-41d4-a716-446655440000",
        "details": "Hash verification completed",
        "hash_status": "OK",
        "hash_at_time": "abc123def456..."
      }
    ],
    "total": 234,
    "page": 1,
    "per_page": 50
  }
}
```

---

## 4. Field Reference

### Evidence Fields
- `id` (UUID) - Primary identifier
- `evidence_id` (UUID) - Alias for `id` (backward compat)
- `evidence_tag` (string) - Human-readable tag (EV-XXXXXX)
- `title` (string) - File/item name
- `description` (string) - Detailed description
- `evidence_type` (enum) - DIGITAL_FILE, SCREENSHOT, TRANSACTION_LOG, etc.
- `state`/`status` (enum) - COLLECTED, IN_TRANSIT, IN_ANALYSIS, SECURED, SUBMITTED_TO_COURT
- `sha256_hash`/`file_hash` (string) - Hash value
- `hashed_at` (ISO 8601) - When hash was computed
- `hash_status` (string) - "OK" or null
- `created_at` (ISO 8601) - When evidence was logged
- `updated_at` (ISO 8601) - Last update time

### Case Fields
- `id` (UUID) - Primary identifier
- `case_number` (string) - Human-readable case number
- `title` (string) - Case title
- `description` (string) - Case description
- `suspect_info` (string) - Suspect details
- `fraud_type` (enum) - SIM_SWAP, PHISHING, IDENTITY_THEFT, etc.
- `status` (enum) - PENDING_APPROVAL, OPEN, REJECTED, CLOSED
- `assigned_to` (UUID) - Assigned investigator ID
- `assigned_user_name` (string) - Assigned investigator name
- `created_by_id` (UUID) - Creator user ID
- `created_by_name` (string) - Creator name
- `created_at` (ISO 8601) - When case was created
- `updated_at` (ISO 8601) - Last update time

---

## 5. Error Handling

All errors return JSON with consistent format:

```json
{
  "success": false,
  "data": {},
  "message": "Descriptive error message"
}
```

**HTTP Status Codes**:
- `200 OK` - Success
- `201 Created` - Resource created
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Missing/invalid JWT
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error (logged with stack trace)

---

## 6. RBAC Summary

| Role | Evidence List | Evidence Detail | Create Case | Update Case | Approve Case | Hash Verify |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| INVESTIGATOR | Own only | Own only | ✅ | Own | ❌ | ✅ |
| AUDITOR | All | All | ❌ | ❌ | ❌ | ✅ |
| AUTHORIZER | All | All | ❌ | Status only | ✅ | ❌ |
| ADMIN | All | All | ✅ | ✅ | ✅ | ✅ |

---

## 7. Backward Compatibility

The API maintains backward compatibility:
- Evidence list returns both `items` (new) and `evidence` (canonical) keys
- Evidence detail has both `id` and `evidence_id` fields
- Cases list returns both `items` and `cases` keys
- Custody history returned as `custody_history`, `chain_of_custody`, and `custody_records`

Frontend should migrate to using the new/canonical field names.

---

## 8. Timestamps

All timestamps are in **ISO 8601 format with Z suffix** (UTC):
- `2026-05-05T12:00:00Z`
- `2026-05-05T12:30:45Z`

No timezone conversion needed - all times are UTC.

