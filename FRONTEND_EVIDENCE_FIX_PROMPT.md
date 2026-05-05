# Frontend Evidence Page Correction Prompt for Developer

## Issue Summary
The Investigator Evidence page is not properly displaying live data from the backend API. The following columns need corrections:
1. **Item Name** - Currently empty, should display evidence title
2. **Status** - Currently empty, should display evidence state
3. **Evidence Type** - Currently showing "file" for all items, should display the correct type selected by investigator

---

## Backend API Endpoint
**GET** `/evidence/cases/{caseId}/evidence`

**Response Format:**
```json
{
  "success": true,
  "data": {
    "case_id": "uuid-string",
    "items": [
      {
        "id": "evidence-uuid",
        "case_id": "case-uuid",
        "evidence_tag": "EV-ABC12345",
        "title": "John_Doe_Phone_Records.pdf",
        "item_name": "John_Doe_Phone_Records.pdf",
        "description": "Phone records recovered from suspect's device",
        "evidence_type": "DIGITAL_FILE",
        "status": "COLLECTED",
        "state": "COLLECTED",
        "source": "Mobile Device Seizure",
        "collection_date": "2026-05-05T10:30:00",
        "collected_by": "investigator-uuid",
        "notes": "Evidence collected during warrant execution",
        "storage_location": "/path/to/evidence",
        "sha256_hash": "abc123def456...",
        "file_name": "John_Doe_Phone_Records.pdf"
      },
      {
        "id": "evidence-uuid-2",
        "case_id": "case-uuid",
        "evidence_tag": "EV-XYZ67890",
        "title": "Suspect Interview Recording",
        "item_name": "Suspect Interview Recording",
        "description": "Video recording of suspect interview",
        "evidence_type": "SCREENSHOT",
        "status": "IN_ANALYSIS",
        "state": "IN_ANALYSIS",
        "source": "Interview Room Camera",
        "collection_date": "2026-05-04T15:45:00",
        "collected_by": "investigator-uuid-2",
        "notes": "Recorded with suspect consent",
        "storage_location": "/path/to/evidence2",
        "sha256_hash": "xyz789abc123...",
        "file_name": "Interview_Video_05042026.mp4"
      }
    ]
  },
  "message": "Evidence list fetched"
}
```

---

## Field Mapping for UI Columns

### Column: Item Name
- **Source Field**: `title` or `item_name`
- **Display**: Show the evidence title/name
- **Example**: "John_Doe_Phone_Records.pdf"

### Column: Status
- **Source Field**: `status` or `state`
- **Display**: Show the current evidence state
- **Possible Values**:
  - `COLLECTED` - Evidence has been collected
  - `IN_TRANSIT` - Evidence is being transported
  - `IN_ANALYSIS` - Evidence is under analysis
  - `SECURED` - Evidence is secured
  - `SUBMITTED_TO_COURT` - Evidence submitted to court

### Column: Evidence Type
- **Source Field**: `evidence_type`
- **Display**: Show the actual evidence type (NOT always "file")
- **Possible Values**:
  - `DIGITAL_FILE` - Digital files (documents, images, archives)
  - `PHYSICAL` - Physical evidence (weapons, drugs, etc.)
  - `SCREENSHOT` - Screenshots or images
  - `TRANSACTION_LOG` - Transaction logs or data exports
  - `DEVICE` - Physical devices (phones, computers, storage devices)
  - `OTHER` - Other types of evidence

---

## Current Issues in Frontend

1. **Item Name Column Not Populated**
   - ❌ Not reading `title` or `item_name` from API response
   - ✅ Should display: `response.items[i].title`

2. **Status Column Not Populated**
   - ❌ Not reading `status` or `state` from API response
   - ✅ Should display: `response.items[i].status`

3. **Evidence Type Hardcoded as "file"**
   - ❌ Showing static "file" text instead of reading from API
   - ✅ Should display: `response.items[i].evidence_type`
   - ✅ Should apply formatting/styling based on type

---

## Code Example (React/Vue/Angular)

### React Example
```jsx
const EvidenceTable = ({ caseId }) => {
  const [evidence, setEvidence] = useState([]);

  useEffect(() => {
    fetch(`/evidence/cases/${caseId}/evidence`)
      .then(res => res.json())
      .then(data => setEvidence(data.data.items));
  }, [caseId]);

  return (
    <table>
      <thead>
        <tr>
          <th>Evidence Tag</th>
          <th>Item Name</th>
          <th>Status</th>
          <th>Evidence Type</th>
          <th>Collection Date</th>
        </tr>
      </thead>
      <tbody>
        {evidence.map(item => (
          <tr key={item.id}>
            <td>{item.evidence_tag}</td>
            <td>{item.title}</td>
            <td>
              <span className={`badge badge-${item.status.toLowerCase()}`}>
                {item.status}
              </span>
            </td>
            <td>{item.evidence_type}</td>
            <td>{new Date(item.collection_date).toLocaleDateString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};
```

### Vue Example
```vue
<template>
  <table class="evidence-table">
    <thead>
      <tr>
        <th>Evidence Tag</th>
        <th>Item Name</th>
        <th>Status</th>
        <th>Evidence Type</th>
        <th>Collection Date</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="item in evidence" :key="item.id">
        <td>{{ item.evidence_tag }}</td>
        <td>{{ item.title }}</td>
        <td>
          <span :class="`status-${item.status.toLowerCase()}`">
            {{ item.status }}
          </span>
        </td>
        <td>{{ item.evidence_type }}</td>
        <td>{{ formatDate(item.collection_date) }}</td>
      </tr>
    </tbody>
  </table>
</template>

<script>
export default {
  data() {
    return {
      evidence: []
    };
  },
  async mounted() {
    const response = await fetch(`/evidence/cases/${this.$route.params.caseId}/evidence`);
    const data = await response.json();
    this.evidence = data.data.items;
  },
  methods: {
    formatDate(dateString) {
      return new Date(dateString).toLocaleDateString();
    }
  }
};
</script>
```

---

## Testing Instructions

1. **API Response Verification**
   - Call the endpoint: `GET /evidence/cases/{caseId}/evidence`
   - Verify response contains: `title`, `status`, `evidence_type` fields
   - Check that evidence has different types (not all "DIGITAL_FILE")

2. **Frontend Display Test**
   - Add evidence items with different evidence types in the database
   - Load the investigator evidence page
   - Verify:
     - ✅ Item Name column shows evidence titles
     - ✅ Status column shows actual status values (COLLECTED, IN_ANALYSIS, etc.)
     - ✅ Evidence Type column shows actual types (DIGITAL_FILE, SCREENSHOT, TRANSACTION_LOG, etc.)

3. **Sample Test Data**
   ```
   Evidence 1: title="Bank Statement.pdf", evidence_type="DIGITAL_FILE", status="COLLECTED"
   Evidence 2: title="Suspect Photo", evidence_type="SCREENSHOT", status="IN_ANALYSIS"
   Evidence 3: title="iPhone 12", evidence_type="DEVICE", status="SECURED"
   Evidence 4: title="Transaction Log Export", evidence_type="TRANSACTION_LOG", status="COLLECTED"
   ```

---

## Additional Context

- **Backend Changes**: The API has been updated to return `title`, `item_name`, `status`, `state`, and `evidence_type` fields
- **Database Fields**: Evidence data is stored in the `evidence` table with columns: `title`, `state`, `evidence_type`
- **No Frontend Breaking Changes**: The new fields are additive - existing fields still work

---

## Checklist for Frontend Developer

- [ ] Read `title` field from API response for Item Name column
- [ ] Read `status` field from API response for Status column
- [ ] Read `evidence_type` field from API response for Evidence Type column
- [ ] Remove any hardcoded "file" text
- [ ] Test with multiple evidence items of different types
- [ ] Test that statuses display correctly (COLLECTED, IN_TRANSIT, IN_ANALYSIS, SECURED, SUBMITTED_TO_COURT)
- [ ] Verify page loads evidence data on case selection
- [ ] Add appropriate styling/colors for different evidence types
- [ ] Add appropriate styling/colors for different statuses
