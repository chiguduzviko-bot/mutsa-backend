# Frontend Migration Guide - Removing API Fallbacks

This guide helps frontend developers remove workaround code and use the native API contract.

---

## Before: Fallback Pattern (N+1 Queries)

```typescript
// OLD: Frontend workaround - list all cases, then get evidence per case
async function loadAllEvidence() {
  // Get all cases
  const casesResp = await fetch('/api/cases');
  const cases = casesResp.data.items;
  
  // Then loop through each and get evidence (N+1 problem!)
  const allEvidence = [];
  for (const caseItem of cases) {
    const evResp = await fetch(`/api/evidence/cases/${caseItem.id}/evidence`);
    allEvidence.push(...evResp.data.items);
  }
  
  return allEvidence;
}
```

**Problems**:
- N+1 queries (1 + number of cases)
- Slow for many cases
- Some deployments return 404
- Frontend needs to handle fallbacks
- Wasteful network usage

---

## After: Native Endpoint

```typescript
// NEW: Direct API call
async function loadAllEvidence() {
  const resp = await fetch('/api/evidence?page=1&per_page=100');
  return resp.data.evidence;  // Use 'evidence' key (canonical)
}
```

**Benefits**:
- ✅ Single efficient query
- ✅ Proper RBAC enforcement
- ✅ Consistent across deployments
- ✅ No fallback logic needed
- ✅ ~10x faster for 50+ cases

---

## Field Name Updates

### Evidence Responses

**Before**:
```javascript
{
  id: "550e8400...",
  case_id: "550e8400...",
  evidence_tag: "EV-550E8400",
  title: "document.pdf",
  // No evidence_id field
}
```

**After**:
```javascript
{
  id: "550e8400...",              // NEW: Stable UUID
  evidence_id: "550e8400...",     // NEW: Alias for id
  case_id: "550e8400...",
  evidence_tag: "EV-550E8400",
  title: "document.pdf",
  // ... plus field aliases for flexibility
  item_name: "document.pdf",      // Alias for title
  file_name: "document.pdf",      // From latest hash
  status: "SECURED",               // Alias for state
  state: "SECURED",                // Canonical
  sha256_hash: "abc123...",       // Primary hash field
  file_hash: "abc123...",         // Alias for sha256_hash
}
```

**Migration**: Use `id` or `evidence_id` interchangeably, but prefer `id` (more standard).

---

### Case Responses

**Before**:
```javascript
{
  id: "550e8400...",
  case_number: "CASE-20260505-ABC123",
  title: "SMS Fraud",
  assigned_to: "550e8400...",
  assigned_user_name: "Jane Investigator",
  // Missing: created_by_name (UI showed "—")
}
```

**After**:
```javascript
{
  id: "550e8400...",
  case_number: "CASE-20260505-ABC123",
  title: "SMS Fraud",
  assigned_to: "550e8400...",
  assigned_user_name: "Jane Investigator",
  investigator_name: "Jane Investigator",
  created_by_id: "550e8400...",          // NEW: Creator's ID
  created_by_name: "Jane Investigator",  // NEW: Creator's name (fill empty column!)
  creator_name: "Jane Investigator",     // Alias for created_by_name
  opened_by_user_id: "550e8400...",
}
```

**Migration**: 
- Remove fallback logic that uses JWT name when `assigned_user_name` is empty
- Use `created_by_name` for cases where creator ≠ assigned investigator
- No need to check both fields anymore

---

## API Endpoint Changes

### Evidence List

**Before** (fallback workaround):
```typescript
// Get cases, loop through, fetch evidence per case
const cases = await getCases();
for (const c of cases) {
  const ev = await getEvidenceByCase(c.id);
}
```

**After** (native):
```typescript
// Single call with pagination
const resp = await fetch('/api/evidence?page=1&per_page=20');
const evidence = resp.data.evidence;  // Key: "evidence" not "items"
const total = resp.data.total;
const pages = resp.data.pages;
```

**Supports**:
- `?page=1&per_page=20` - Pagination
- `?case_id=<uuid>` - Filter by case
- `?status=SECURED` - Filter by status
- RBAC: INVESTIGATOR sees only own, AUDITOR sees all

---

### Evidence by ID

**Before** (tried multiple URLs):
```typescript
try {
  return await fetch('/api/evidence/evidence/:id');
} catch (e) {
  // Fallback
  return await fetch('/api/evidence/:id');
}
```

**After** (use canonical):
```typescript
// Use this canonical URL
return await fetch('/api/evidence/evidence/:id');
// (Old URLs still work for backward compat, but use this one)
```

---

### Case List

**Before**:
```typescript
// Only worked with assigned_to filter
const cases = await fetch(`/api/cases?assigned_to=${userId}`);
// Didn't include creator, so new cases looked empty
```

**After**:
```typescript
// Multiple filter options now available
const cases = await fetch(`/api/cases?assigned_to=${userId}`);           // Show my assigned cases
const created = await fetch(`/api/cases?created_by=${userId}`);         // Show cases I created
const pending = await fetch(`/api/cases?status=PENDING_APPROVAL`);      // Awaiting authorization

// All cases now have created_by_name regardless of assigned_to
```

**Note**: New cases automatically have `assigned_to = creator`, so filtering by `assigned_to` now works.

---

### Case Creation

**Before**:
```typescript
const resp = await fetch('/api/cases', {
  method: 'POST',
  body: JSON.stringify({
    title: "Case Title",
    fraud_type: "SIM_SWAP"
    // assigned_to would be empty → case disappears from list!
  })
});
```

**After**:
```typescript
const resp = await fetch('/api/cases', {
  method: 'POST',
  body: JSON.stringify({
    title: "Case Title",
    fraud_type: "SIM_SWAP"
    // assigned_to auto-defaults to creator ✅
  })
});

// Case immediately appears in creator's case list
```

---

### Case Update

**Before**:
```typescript
// Had to check response format
const resp = await fetch(`/api/cases/${id}`, {
  method: 'PUT',
  body: JSON.stringify({ title: "New Title" })
});

// Inconsistent response format
const caseData = resp.data.case || resp.data; // ??
```

**After**:
```typescript
// Consistent format
const resp = await fetch(`/api/cases/${id}`, {
  method: 'PUT',
  body: JSON.stringify({ title: "New Title" })
});

// Always returns serialized case
const caseData = resp.data;  // Full case object
```

---

## Hash Verification

**No changes needed** - endpoints already stable:

```typescript
// GET - Retrieve metadata
const metadata = await fetch(`/api/evidence/evidence/${id}/verify-hash`);
const algorithm = metadata.data.algorithm;      // "SHA-256"
const hash = metadata.data.sha256_hash;         // or original_hash
const hashed_at = metadata.data.hashed_at;      // ISO timestamp

// POST - Verify file
const formData = new FormData();
formData.append('file', fileInput.files[0]);
const result = await fetch(`/api/evidence/evidence/${id}/verify-hash`, {
  method: 'POST',
  body: formData
});
const integrity = result.data.integrity_status;  // "INTACT" or "TAMPERED"
```

---

## Removing Fallback Code Examples

### Example 1: Investigator Column Display

**Before** (fallback):
```typescript
function displayInvestigator(caseItem) {
  // Try to get from assigned_user_name
  if (caseItem.assigned_user_name) {
    return caseItem.assigned_user_name;
  }
  // Fallback: check if it's current user
  if (caseItem.assigned_to === currentUserId && JWT.name) {
    return JWT.name;
  }
  // Give up
  return "—";
}
```

**After** (clean):
```typescript
function displayInvestigator(caseItem) {
  // Use creator if assigned_to is empty/missing
  return caseItem.created_by_name || caseItem.assigned_user_name || "—";
}
```

---

### Example 2: Evidence List Loading

**Before** (N+1 workaround):
```typescript
async function loadEvidenceList() {
  try {
    const resp = await fetch('/api/evidence');
    if (resp.ok) {
      return resp.data.evidence || resp.data.items;
    }
  } catch (e) {
    // Fallback: load cases and get evidence per case
    const cases = await fetch('/api/cases');
    const evidence = [];
    for (const c of cases.data.items) {
      const ev = await fetch(`/api/evidence/cases/${c.id}/evidence`);
      evidence.push(...ev.data.items);
    }
    return evidence;
  }
}
```

**After** (clean):
```typescript
async function loadEvidenceList() {
  const resp = await fetch('/api/evidence?page=1&per_page=50');
  return resp.data.evidence;
}
```

---

### Example 3: Creating Cases with Proper Assignment

**Before** (workaround):
```typescript
async function createCase(data) {
  const payload = {
    title: data.title,
    fraud_type: data.fraud_type,
    assigned_to: data.assigned_to || currentUserId  // Manual default
  };
  return await fetch('/api/cases', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}
```

**After** (clean):
```typescript
async function createCase(data) {
  // assigned_to auto-defaults on server
  return await fetch('/api/cases', {
    method: 'POST',
    body: JSON.stringify({
      title: data.title,
      fraud_type: data.fraud_type,
      assigned_to: data.assignedTo  // Optional - defaults to creator
    })
  });
}
```

---

## Testing the New Endpoints

### Quick Test Script

```bash
# Set your token
TOKEN="your_jwt_token_here"

# Test 1: Get global evidence list
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/evidence?page=1&per_page=10"

# Test 2: Get single evidence by ID
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/evidence/evidence/550e8400-e29b-41d4-a716-446655440000"

# Test 3: Get cases list
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/cases?page=1&per_page=10"

# Test 4: Get cases by creator
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:5000/api/cases?created_by=550e8400-e29b-41d4-a716-446655440010"

# Test 5: Create a case (should auto-assign to creator)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Case",
    "fraud_type": "PHISHING"
  }' \
  "http://localhost:5000/api/cases"
```

---

## Troubleshooting

### "evidence is empty but items has data"
- The API returns **both** keys for backward compat
- Use `resp.data.evidence` (canonical, recommended)
- Remove `resp.data.items` from code over time

### "created_by_name is null"
- Check if `opened_by_user_id` exists in case
- If user ID exists but name is null, the user may not be in database
- Fallback to displaying the UUID if name resolution fails

### "Case not appearing in my list after creation"
- Check `assigned_to` is set (should default to your user ID)
- Try filtering with `?assigned_to=<your-id>`
- Check your user role is INVESTIGATOR or ADMIN

### "Still getting 403 Forbidden on custody endpoints"
- Ensure your JWT token is valid and not expired
- Check your user role includes required permissions
- If user DB is unavailable, API now falls back to JWT role claim

---

## Migration Checklist

- [ ] Remove N+1 evidence loading loop
- [ ] Update to use `/api/evidence` with pagination
- [ ] Add `created_by_name` to investigator column display
- [ ] Remove JWT name fallback logic
- [ ] Test case creation (no explicit assigned_to needed)
- [ ] Update `GET /cases` to use `?created_by=` filter
- [ ] Update evidence detail to use both `id` and `evidence_id`
- [ ] Remove URL fallback for evidence by ID
- [ ] Test all RBAC scenarios (INVESTIGATOR vs AUDITOR views)
- [ ] Deploy and monitor error logs for issues

---

## Support

For issues or questions:
1. Check `API_CONTRACT.md` for complete endpoint documentation
2. Review error messages - they're now more descriptive JSON
3. Check server logs for 500 errors (stack traces included)
4. Ensure JWT token has required role claims

