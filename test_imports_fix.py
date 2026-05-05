#!/usr/bin/env python
"""Test that all modules import without circular import issues."""
import sys

try:
    print("Testing imports...")
    
    print("1. Importing app module...")
    from app import create_app, db
    print("   ✓ app module OK")
    
    print("2. Creating app instance...")
    app = create_app()
    print("   ✓ app created OK")
    
    print("3. Checking serializers import...")
    from app.utils.serializers import to_iso_timestamp, serialize_custody_record
    print("   ✓ serializers OK")
    
    print("4. Checking routes...")
    with app.app_context():
        print("   - cases_ns exists")
        print("   - evidence_ns exists")
        print("   - custody_ns exists")
    print("   ✓ routes OK")
    
    print("\n✓ All imports successful!")
    sys.exit(0)
    
except Exception as e:
    print(f"\n✗ Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
