#!/usr/bin/env python
"""Quick test to see if serializers cause import errors."""

# Test 1: Import serializers standalone
try:
    print("Test 1: Importing serializers module...")
    from app.utils.serializers import to_iso_timestamp
    print("✓ Success")
except Exception as e:
    print(f"✗ Failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# Test 2: Import routes
try:
    print("\nTest 2: Importing routes modules...")
    from app.routes import evidence
    print("✓ Evidence route imported")
except Exception as e:
    print(f"✗ Failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# Test 3: Create app
try:
    print("\nTest 3: Creating Flask app...")
    from app import create_app
    app = create_app()
    print("✓ App created")
except Exception as e:
    print(f"✗ Failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

print("\n✓ All tests passed!")
