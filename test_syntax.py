#!/usr/bin/env python
"""Quick syntax check for updated modules."""
import sys

try:
    import app.utils.audit_logger
    import app.routes.auth
    import app.routes.admin
    import app.routes.cases
    import app.routes.evidence
    import app.routes.custody
    import app.routes.audit
    print("✓ All modules imported successfully")
    sys.exit(0)
except Exception as e:
    print(f"✗ Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
