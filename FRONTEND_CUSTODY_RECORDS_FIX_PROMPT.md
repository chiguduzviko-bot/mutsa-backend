# Frontend Custody Records Display Correction Prompt

## Issue Summary
The Custody Records (Chain of Custody) section on the evidence page is not properly displaying:
1. **Officer/Custodian Names** - Shows "unknown" instead of actual officer names
2. **Timestamps** - Not displaying transfer dates and times

---

## Backend API Endpoint
**GET** `/evidence/evidence/{evidenceId}`

**Custody Records Response Format:**

The response now includes a `custody_history` array with complete officer information and timestamps:

```json
{
  "success": true,
  "data": {
    "id": "evidence-uuid",
    "case_id": "case-uuid",
    "evidence_tag": "EV-ABC12345",
    "title": "Suspect Phone Records",
    "custody_history": [
      {
        "id": 1,
        "from_user_id": "user-uuid-1",
        "from_user_name": "Officer John Smith",
        "from_officer": "Officer John Smith",
        "to_user_id": "user-uuid-2",
        "to_user_name": "Detective Sarah Johnson",
        "to_officer": "Detective Sarah Johnson",
        "action": "COLLECTED",
        "location": "/evidence/case-001/evidence-001",
        "notes": "Evidence collected during search warrant",
        "timestamp": "2026-05-05T10:30:00",
        "transferred_at": "2026-05-05T10:30:00",
        "transferred_date": "2026-05-05T10:30:00",
        "received_at": null,
        "created_at": "2026-05-05T10:30:00",
        "recorded_by_user_id": "user-uuid-1",
        "recorded_by_name": "Officer John Smith",
        "recorded_by": "Officer John Smith"
      },
      {
        "id": 2,
        "from_user_id": "user-uuid-2",
        "from_user_name": "Detective Sarah Johnson",
        "from_officer": "Detective Sarah Johnson",
        "to_user_id": "user-uuid-3",
        "to_user_name": "Evidence Custodian Mike Brown",
        "to_officer": "Evidence Custodian Mike Brown",
        "action": "TRANSFERRED",
        "location": "Evidence Storage Room 204",
        "notes": "Transferred to evidence storage for safekeeping",
        "timestamp": "2026-05-05T14:15:00",
        "transferred_at": "2026-05-05T14:15:00",
        "transferred_date": "2026-05-05T14:15:00",
        "received_at": "2026-05-05T14:20:00",
        "created_at": "2026-05-05T14:15:00",
        "recorded_by_user_id": "user-uuid-2",
        "recorded_by_name": "Detective Sarah Johnson",
        "recorded_by": "Detective Sarah Johnson"
      },
      {
        "id": 3,
        "from_user_id": "user-uuid-3",
        "from_user_name": "Evidence Custodian Mike Brown",
        "from_officer": "Evidence Custodian Mike Brown",
        "to_user_id": "user-uuid-1",
        "to_officer": "Officer John Smith",
        "to_user_name": "Officer John Smith",
        "action": "RECEIVED",
        "location": "Investigator Office",
        "notes": "Evidence retrieved for analysis",
        "timestamp": "2026-05-05T16:45:00",
        "transferred_at": "2026-05-05T16:45:00",
        "transferred_date": "2026-05-05T16:45:00",
        "received_at": "2026-05-05T16:50:00",
        "created_at": "2026-05-05T16:45:00",
        "recorded_by_user_id": "user-uuid-3",
        "recorded_by_name": "Evidence Custodian Mike Brown",
        "recorded_by": "Evidence Custodian Mike Brown"
      }
    ],
    "chain_of_custody": [],
    "custody_records": []
  },
  "message": "Evidence details fetched"
}
```

---

## Field Mapping for Custody Records Columns

### Column: Officer / From Officer
**Source Fields** (in priority order):
1. `from_officer` (recommended - clearest name)
2. `from_user_name`
3. Falls back to: "Unknown" if no from_user_id

**Display**: Name of the officer transferring the evidence FROM

**Example**: "Officer John Smith"

### Column: To Officer / Receiving Officer
**Source Fields** (in priority order):
1. `to_officer` (recommended - clearest name)
2. `to_user_name`
3. Falls back to: "Unknown" if no to_user_id

**Display**: Name of the officer receiving the evidence TO

**Example**: "Detective Sarah Johnson"

### Column: Recorded By / Authorized By
**Source Fields** (in priority order):
1. `recorded_by` (recommended - clearest name)
2. `recorded_by_name`
3. Falls back to: "Unknown" if no recorded_by_user_id

**Display**: Name of the officer who recorded/authorized this transfer

**Example**: "Officer John Smith"

### Column: Timestamp / Date & Time
**Source Fields** (in priority order):
1. `timestamp` (recommended - ISO format)
2. `transferred_at` (ISO format)
3. `transferred_date` (ISO format)
4. Falls back to: "Unknown" if null

**Display Format**:
- ISO Format: "2026-05-05T10:30:00"
- Display as: "May 5, 2026 at 10:30 AM" (human-readable)
- Or: "2026-05-05 10:30"

**Example**: "May 5, 2026 at 10:30 AM"

### Column: Action / Activity
**Source Field**: `action`

**Display**: The custody action performed

**Possible Values**:
- `COLLECTED` - Initial evidence collection
- `TRANSFERRED` - Evidence transferred between officers
- `RECEIVED` - Evidence received/acknowledged
- `ANALYZED` - Evidence undergoing analysis
- `SECURED` - Evidence secured in storage
- `SUBMITTED_TO_COURT` - Evidence submitted to court

### Column: Location
**Source Field**: `location`

**Display**: Where the transfer occurred

**Example**: "Evidence Storage Room 204"

### Column: Notes / Comments
**Source Field**: `notes`

**Display**: Additional details about the transfer

**Example**: "Transferred to evidence storage for safekeeping"

---

## Current Issues Fixed

1. **Officer Column Showing "Unknown"** ✅
   - Backend now queries User table and returns actual names
   - Returns `from_officer`, `to_officer`, and `recorded_by` fields
   - Falls back to "Unknown" only if user data not found

2. **Timestamp Not Populating** ✅
   - Backend now returns multiple timestamp fields:
     - `timestamp` - Primary timestamp field
     - `transferred_at` - ISO formatted transfer time
     - `transferred_date` - Human-readable transfer date
     - `received_at` - When evidence was received
     - `created_at` - When record was created
   - All in ISO 8601 format for easy parsing

3. **Additional Officer Information** ✅
   - Returns both UUID and name for each officer
   - Multiple field names for flexibility (e.g., `from_officer` and `from_user_name`)
   - Complete chain of custody data

---

## Code Examples

### React Example
```jsx
const CustodyRecordsTable = ({ evidenceId }) => {
  const [custodyRecords, setCustodyRecords] = useState([]);

  useEffect(() => {
    fetch(`/evidence/evidence/${evidenceId}`)
      .then(res => res.json())
      .then(data => {
        // Custody history is in data.data.custody_history
        setCustodyRecords(data.data.custody_history || []);
      });
  }, [evidenceId]);

  const formatDate = (isoString) => {
    if (!isoString) return "Unknown";
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <table className="custody-table">
      <thead>
        <tr>
          <th>From Officer</th>
          <th>To Officer</th>
          <th>Action</th>
          <th>Timestamp</th>
          <th>Location</th>
          <th>Recorded By</th>
          <th>Notes</th>
        </tr>
      </thead>
      <tbody>
        {custodyRecords.map((record) => (
          <tr key={record.id}>
            <td>{record.from_officer || record.from_user_name || "Unknown"}</td>
            <td>{record.to_officer || record.to_user_name || "Unknown"}</td>
            <td>
              <span className={`badge badge-${record.action.toLowerCase()}`}>
                {record.action}
              </span>
            </td>
            <td>{formatDate(record.timestamp || record.transferred_at)}</td>
            <td>{record.location}</td>
            <td>{record.recorded_by || record.recorded_by_name || "Unknown"}</td>
            <td>{record.notes}</td>
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
  <table class="custody-table">
    <thead>
      <tr>
        <th>From Officer</th>
        <th>To Officer</th>
        <th>Action</th>
        <th>Timestamp</th>
        <th>Location</th>
        <th>Recorded By</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="record in custodyRecords" :key="record.id">
        <td>{{ record.from_officer || record.from_user_name || 'Unknown' }}</td>
        <td>{{ record.to_officer || record.to_user_name || 'Unknown' }}</td>
        <td>
          <span :class="`badge badge-${record.action.toLowerCase()}`">
            {{ record.action }}
          </span>
        </td>
        <td>{{ formatDate(record.timestamp || record.transferred_at) }}</td>
        <td>{{ record.location }}</td>
        <td>{{ record.recorded_by || record.recorded_by_name || 'Unknown' }}</td>
        <td>{{ record.notes }}</td>
      </tr>
    </tbody>
  </table>
</template>

<script>
export default {
  data() {
    return {
      custodyRecords: [],
      evidenceId: null
    };
  },
  async mounted() {
    this.evidenceId = this.$route.params.evidenceId;
    const response = await fetch(`/evidence/evidence/${this.evidenceId}`);
    const data = await response.json();
    this.custodyRecords = data.data.custody_history || [];
  },
  methods: {
    formatDate(isoString) {
      if (!isoString) return "Unknown";
      const date = new Date(isoString);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    }
  }
};
</script>

<style scoped>
.custody-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 20px;
}

.custody-table th,
.custody-table td {
  border: 1px solid #ddd;
  padding: 12px;
  text-align: left;
}

.custody-table th {
  background-color: #f8f9fa;
  font-weight: 600;
}

.badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
}

.badge-collected {
  background-color: #d4edda;
  color: #155724;
}

.badge-transferred {
  background-color: #cce5ff;
  color: #004085;
}

.badge-received {
  background-color: #fff3cd;
  color: #856404;
}

.badge-analyzed {
  background-color: #d1ecf1;
  color: #0c5460;
}

.badge-secured {
  background-color: #e7d4f5;
  color: #663399;
}

.badge-submitted_to_court {
  background-color: #f8d7da;
  color: #721c24;
}
</style>
```

---

## Testing Instructions

1. **API Response Verification**
   - Call endpoint: `GET /evidence/evidence/{evidenceId}`
   - Verify `custody_history` array exists
   - Check that each record has:
     - ✅ `from_officer` or `from_user_name` (not UUIDs only)
     - ✅ `to_officer` or `to_user_name` (not UUIDs only)
     - ✅ `timestamp` or `transferred_at` (ISO formatted dates)
     - ✅ `recorded_by` or `recorded_by_name`

2. **Frontend Display Test**
   - Load evidence detail page
   - Verify in Custody Records section:
     - ✅ Officer names display correctly (not "Unknown" if officers exist)
     - ✅ Timestamps display in human-readable format
     - ✅ All columns populate with data
     - ✅ Each row represents one custody transfer

3. **Sample Test Scenario**
   ```
   1. Evidence collected by Officer John Smith (2026-05-05 10:30)
   2. Transferred to Detective Sarah Johnson (2026-05-05 14:15)
   3. Received by Evidence Custodian Mike Brown (2026-05-05 14:20)
   4. Retrieved by Officer John Smith for analysis (2026-05-05 16:45)
   ```

---

## Endpoint Details

### Get Evidence Details with Custody History
```
GET /evidence/evidence/{evidenceId}

Response includes:
- custody_history[] - Array of all custody transfer records
- chain_of_custody[] - Alias for custody_history
- custody_records[] - Alias for custody_history

Each record contains:
- Officer information with full names
- Timestamps in ISO format
- Action type
- Location details
- Notes/comments
- User IDs and names for auditing
```

---

## Checklist for Frontend Developer

- [ ] Fetch evidence details from `/evidence/evidence/{evidenceId}` endpoint
- [ ] Access custody records from `data.custody_history` array
- [ ] Display `from_officer` (or `from_user_name`) in "From Officer" column
- [ ] Display `to_officer` (or `to_user_name`) in "To Officer" column
- [ ] Display `timestamp` (or `transferred_at`) in "Timestamp" column
- [ ] Format timestamps to human-readable format (e.g., "May 5, 2026 at 10:30 AM")
- [ ] Display `action` value in "Action" column with appropriate styling
- [ ] Display `location` in "Location" column
- [ ] Display `recorded_by` (or `recorded_by_name`) in "Recorded By" column
- [ ] Display `notes` in "Notes" column
- [ ] Add color-coded badges for different actions
- [ ] Test with evidence that has multiple custody transfers
- [ ] Verify no "Unknown" values appear when officer data exists
- [ ] Sort custody records chronologically (oldest to newest)
- [ ] Handle edge cases (null timestamps, missing officers)

---

## Additional Notes

- **Backend Updated**: Custody serialization now includes full officer names and all timestamp fields
- **No Breaking Changes**: UUID fields still available for cross-references
- **Multiple Field Names**: Use `from_officer` and similar for clearest intent, but `from_user_name` and `recorded_by_name` work too
- **Timestamp Fields**: Multiple timestamp options for flexibility - use `timestamp` or `transferred_at` as primary
- **Order**: Custody records are returned in chronological order (oldest first)
