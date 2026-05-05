# Complete Evidence Page Frontend Implementation Guide

**Last Updated**: May 5, 2026

---

## Overview

This guide provides frontend developers with all necessary information to fix the Investigator Evidence page display issues. The backend API has been updated to return complete data - the frontend just needs to wire it up.

---

## Quick Reference: What Needs Fixing

| Issue | Problem | API Field | Fix |
|-------|---------|-----------|-----|
| Item Name Empty | Not displaying evidence title | `title` or `item_name` | Display `response.items[i].title` |
| Status Empty | Not displaying evidence state | `status` or `state` | Display `response.items[i].status` |
| Evidence Type All "File" | Hardcoded instead of dynamic | `evidence_type` | Display `response.items[i].evidence_type` |
| Officer Name "Unknown" | Not fetching user names | `from_officer`, `to_officer` | Display `response.custody_history[i].from_officer` |
| Timestamp Missing | Not displaying custody dates | `timestamp` or `transferred_at` | Display formatted `response.custody_history[i].timestamp` |

---

## Part 1: Evidence List Section

### API Endpoint
```
GET /evidence/cases/{caseId}/evidence
```

### Response Structure
```json
{
  "success": true,
  "data": {
    "case_id": "uuid",
    "items": [
      {
        "id": "uuid",
        "evidence_tag": "EV-ABC12345",
        "title": "Evidence Name Here",
        "item_name": "Evidence Name Here",
        "evidence_type": "DIGITAL_FILE",
        "status": "COLLECTED",
        "state": "COLLECTED",
        "collection_date": "2026-05-05T10:30:00",
        "description": "Evidence description",
        ...
      }
    ]
  }
}
```

### Evidence Type Values
- `DIGITAL_FILE` - Digital files, documents, archives
- `PHYSICAL` - Physical evidence
- `SCREENSHOT` - Screenshots, images
- `TRANSACTION_LOG` - Logs, data exports
- `DEVICE` - Physical devices
- `OTHER` - Other types

### Status/State Values
- `COLLECTED` - Initially collected
- `IN_TRANSIT` - Being transported
- `IN_ANALYSIS` - Under analysis
- `SECURED` - Secured in storage
- `SUBMITTED_TO_COURT` - Submitted to court

### Table Column Mapping

| Column Header | Display Field | Source |
|--------------|---------------|--------|
| Evidence Tag | `evidence_tag` | Direct |
| Item Name | `title` | `items[i].title` |
| Status | `status` | `items[i].status` |
| Evidence Type | `evidence_type` | `items[i].evidence_type` |
| Collection Date | Formatted date | `items[i].collection_date` |
| Source | `source` | `items[i].source` |

### React Implementation
```jsx
import { useState, useEffect } from 'react';

export const EvidenceList = ({ caseId }) => {
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchEvidence = async () => {
      try {
        const response = await fetch(`/evidence/cases/${caseId}/evidence`);
        const data = await response.json();
        setEvidence(data.data.items || []);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchEvidence();
  }, [caseId]);

  const getStatusColor = (status) => {
    const colors = {
      'COLLECTED': '#28a745',
      'IN_TRANSIT': '#ffc107',
      'IN_ANALYSIS': '#007bff',
      'SECURED': '#6f42c1',
      'SUBMITTED_TO_COURT': '#dc3545'
    };
    return colors[status] || '#6c757d';
  };

  const formatDate = (isoString) => {
    if (!isoString) return 'N/A';
    return new Date(isoString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  if (loading) return <div>Loading evidence...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div className="evidence-section">
      <h2>Evidence Items</h2>
      <table className="evidence-table">
        <thead>
          <tr>
            <th>Evidence Tag</th>
            <th>Item Name</th>
            <th>Status</th>
            <th>Evidence Type</th>
            <th>Collection Date</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {evidence.map(item => (
            <tr key={item.id}>
              <td className="badge-primary">{item.evidence_tag}</td>
              <td>{item.title}</td>
              <td>
                <span style={{
                  backgroundColor: getStatusColor(item.status),
                  color: 'white',
                  padding: '4px 8px',
                  borderRadius: '4px'
                }}>
                  {item.status}
                </span>
              </td>
              <td>{item.evidence_type}</td>
              <td>{formatDate(item.collection_date)}</td>
              <td>{item.source || 'N/A'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
```

### Vue Implementation
```vue
<template>
  <div class="evidence-section">
    <h2>Evidence Items</h2>
    <div v-if="loading">Loading evidence...</div>
    <div v-if="error" class="alert alert-danger">Error: {{ error }}</div>
    <table v-if="!loading && !error" class="evidence-table">
      <thead>
        <tr>
          <th>Evidence Tag</th>
          <th>Item Name</th>
          <th>Status</th>
          <th>Evidence Type</th>
          <th>Collection Date</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in evidence" :key="item.id">
          <td class="badge-primary">{{ item.evidence_tag }}</td>
          <td>{{ item.title }}</td>
          <td>
            <span :style="{ backgroundColor: getStatusColor(item.status) }">
              {{ item.status }}
            </span>
          </td>
          <td>{{ item.evidence_type }}</td>
          <td>{{ formatDate(item.collection_date) }}</td>
          <td>{{ item.source || 'N/A' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script>
export default {
  props: {
    caseId: {
      type: String,
      required: true
    }
  },
  data() {
    return {
      evidence: [],
      loading: true,
      error: null
    };
  },
  async mounted() {
    try {
      const response = await fetch(`/evidence/cases/${this.caseId}/evidence`);
      const data = await response.json();
      this.evidence = data.data.items || [];
    } catch (err) {
      this.error = err.message;
    } finally {
      this.loading = false;
    }
  },
  methods: {
    getStatusColor(status) {
      const colors = {
        'COLLECTED': '#28a745',
        'IN_TRANSIT': '#ffc107',
        'IN_ANALYSIS': '#007bff',
        'SECURED': '#6f42c1',
        'SUBMITTED_TO_COURT': '#dc3545'
      };
      return colors[status] || '#6c757d';
    },
    formatDate(isoString) {
      if (!isoString) return 'N/A';
      return new Date(isoString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    }
  }
};
</script>

<style scoped>
.evidence-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 20px;
}

.evidence-table th,
.evidence-table td {
  border: 1px solid #ddd;
  padding: 12px;
  text-align: left;
}

.evidence-table th {
  background-color: #f8f9fa;
  font-weight: 600;
}

.badge-primary {
  background-color: #007bff;
  color: white;
  padding: 4px 8px;
  border-radius: 4px;
}

span {
  color: white;
  padding: 4px 8px;
  border-radius: 4px;
  display: inline-block;
}
</style>
```

---

## Part 2: Custody Records Section

### API Endpoint
```
GET /evidence/evidence/{evidenceId}
```

### Response Structure (Key Section)
```json
{
  "success": true,
  "data": {
    "id": "evidence-uuid",
    "title": "Evidence Name",
    "custody_history": [
      {
        "id": 1,
        "from_officer": "Officer John Smith",
        "to_officer": "Detective Sarah Johnson",
        "action": "TRANSFERRED",
        "timestamp": "2026-05-05T10:30:00",
        "transferred_at": "2026-05-05T10:30:00",
        "location": "Evidence Storage Room 204",
        "recorded_by": "Officer John Smith",
        "notes": "Transfer notes here"
      }
    ]
  }
}
```

### Custody Action Values
- `COLLECTED` - Initial collection
- `TRANSFERRED` - Officer-to-officer transfer
- `RECEIVED` - Evidence receipt acknowledgment
- `ANALYZED` - Evidence analysis
- `SECURED` - Secured in storage
- `SUBMITTED_TO_COURT` - Court submission

### Table Column Mapping

| Column Header | Display Field | Source |
|--------------|---------------|--------|
| From Officer | `from_officer` | `custody_history[i].from_officer` |
| To Officer | `to_officer` | `custody_history[i].to_officer` |
| Action | `action` | `custody_history[i].action` |
| Timestamp | Formatted datetime | `custody_history[i].timestamp` |
| Location | `location` | `custody_history[i].location` |
| Recorded By | `recorded_by` | `custody_history[i].recorded_by` |
| Notes | `notes` | `custody_history[i].notes` |

### React Implementation
```jsx
import { useState, useEffect } from 'react';

export const CustodyRecords = ({ evidenceId }) => {
  const [custodyHistory, setCustodyHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchCustodyRecords = async () => {
      try {
        const response = await fetch(`/evidence/evidence/${evidenceId}`);
        const data = await response.json();
        setCustodyHistory(data.data.custody_history || []);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchCustodyRecords();
  }, [evidenceId]);

  const getActionColor = (action) => {
    const colors = {
      'COLLECTED': '#28a745',
      'TRANSFERRED': '#007bff',
      'RECEIVED': '#ffc107',
      'ANALYZED': '#17a2b8',
      'SECURED': '#6f42c1',
      'SUBMITTED_TO_COURT': '#dc3545'
    };
    return colors[action] || '#6c757d';
  };

  const formatDateTime = (isoString) => {
    if (!isoString) return 'Unknown';
    const date = new Date(isoString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) return <div>Loading custody records...</div>;
  if (error) return <div>Error: {error}</div>;
  if (custodyHistory.length === 0) return <div>No custody records found.</div>;

  return (
    <div className="custody-section">
      <h3>Chain of Custody</h3>
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
          {custodyHistory.map(record => (
            <tr key={record.id}>
              <td>{record.from_officer || 'Unknown'}</td>
              <td>{record.to_officer || 'Unknown'}</td>
              <td>
                <span style={{
                  backgroundColor: getActionColor(record.action),
                  color: 'white',
                  padding: '4px 8px',
                  borderRadius: '4px'
                }}>
                  {record.action}
                </span>
              </td>
              <td>{formatDateTime(record.timestamp || record.transferred_at)}</td>
              <td>{record.location}</td>
              <td>{record.recorded_by || 'Unknown'}</td>
              <td>{record.notes || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
```

### Vue Implementation
```vue
<template>
  <div class="custody-section">
    <h3>Chain of Custody</h3>
    <div v-if="loading">Loading custody records...</div>
    <div v-if="error" class="alert alert-danger">Error: {{ error }}</div>
    <div v-if="!loading && !error && custodyHistory.length === 0" class="alert alert-info">
      No custody records found.
    </div>
    <table v-if="!loading && !error && custodyHistory.length > 0" class="custody-table">
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
        <tr v-for="record in custodyHistory" :key="record.id">
          <td>{{ record.from_officer || 'Unknown' }}</td>
          <td>{{ record.to_officer || 'Unknown' }}</td>
          <td>
            <span :style="{ backgroundColor: getActionColor(record.action) }">
              {{ record.action }}
            </span>
          </td>
          <td>{{ formatDateTime(record.timestamp || record.transferred_at) }}</td>
          <td>{{ record.location }}</td>
          <td>{{ record.recorded_by || 'Unknown' }}</td>
          <td>{{ record.notes || '-' }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script>
export default {
  props: {
    evidenceId: {
      type: String,
      required: true
    }
  },
  data() {
    return {
      custodyHistory: [],
      loading: true,
      error: null
    };
  },
  async mounted() {
    try {
      const response = await fetch(`/evidence/evidence/${this.evidenceId}`);
      const data = await response.json();
      this.custodyHistory = data.data.custody_history || [];
    } catch (err) {
      this.error = err.message;
    } finally {
      this.loading = false;
    }
  },
  methods: {
    getActionColor(action) {
      const colors = {
        'COLLECTED': '#28a745',
        'TRANSFERRED': '#007bff',
        'RECEIVED': '#ffc107',
        'ANALYZED': '#17a2b8',
        'SECURED': '#6f42c1',
        'SUBMITTED_TO_COURT': '#dc3545'
      };
      return colors[action] || '#6c757d';
    },
    formatDateTime(isoString) {
      if (!isoString) return 'Unknown';
      const date = new Date(isoString);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
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

span {
  color: white;
  padding: 4px 8px;
  border-radius: 4px;
  display: inline-block;
}
</style>
```

---

## Testing Checklist

### Part 1: Evidence List
- [ ] Load evidence list for a case
- [ ] Verify Item Name column shows actual titles (not empty)
- [ ] Verify Status column shows values like "COLLECTED", "IN_ANALYSIS"
- [ ] Verify Evidence Type shows different types (DIGITAL_FILE, DEVICE, SCREENSHOT, etc.)
- [ ] Verify Collection Date formats correctly
- [ ] Test with multiple evidence items of different types
- [ ] Verify no hardcoded "Unknown" values

### Part 2: Custody Records
- [ ] Load evidence detail page
- [ ] Verify From Officer shows actual officer name (not UUID or "Unknown")
- [ ] Verify To Officer shows actual officer name
- [ ] Verify Timestamp displays in human-readable format (not ISO string)
- [ ] Verify all custody records display chronologically
- [ ] Verify Action column shows proper status badges with colors
- [ ] Test with evidence that has 3+ custody transfers
- [ ] Verify Recorded By column shows officer names
- [ ] Verify Notes column displays transfer details

---

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Officer shows "Unknown" | Check User table has full_name, verify custody_log has correct user_id references |
| Timestamp shows ISO string | Use formatDateTime/formatDate functions, don't display raw ISO format |
| Evidence Type still shows "file" | Verify API response has `evidence_type` field, update frontend to use it |
| Item Name empty | Ensure frontend uses `item.title` not custom calculations |
| No custody records appear | Verify evidence has custody_log entries, check API endpoint `/evidence/evidence/{id}` |

---

## API Error Handling

```javascript
// Handle API errors gracefully
const fetchData = async (url) => {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    const data = await response.json();
    if (!data.success) {
      throw new Error(data.message || 'Unknown error');
    }
    return data.data;
  } catch (error) {
    console.error('Fetch error:', error);
    // Display user-friendly error message
    return null;
  }
};
```

---

## Summary

The backend API is ready and returns all necessary data. Frontend developers just need to:

1. **Wire up the data** from API responses to table columns
2. **Use the provided field names** (`title`, `status`, `from_officer`, etc.)
3. **Format timestamps** to human-readable format
4. **Apply color coding** for status/action badges
5. **Handle edge cases** (null values, missing officers, etc.)

All code examples are provided in React and Vue above. Adapt to your framework as needed.

