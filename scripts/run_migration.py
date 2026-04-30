"""Run all pending migrations in correct dependency order.

Each migration is executed in its own committed connection so that
PostgreSQL enum label additions are visible to subsequent statements.

Usage:
    python scripts/run_migration.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db

MIGRATIONS = [
    # 1) evidence_access_log table (plain SQL, no enum issues)
    "migrations/20260422_add_evidence_access_log.sql",
    # 2) Block A: add AUDITOR label to user_role_enum  (must commit alone)
    "migrations/20260422_rbac_auditor_refactor.sql",
    # 3) Block B: backfill/defaults/audit_trail/flags  (uses AUDITOR label)
    "migrations/20260422_rbac_auditor_refactor_b.sql",
]


def _run_file(app, path):
    with open(path, encoding="utf-8") as fh:
        sql = fh.read().strip()
    if not sql:
        print(f"[SKIP] {path} (empty)")
        return
    with app.app_context():
        with db.engine.connect() as conn:
            conn.execute(db.text(sql))
            conn.commit()
    print(f"[OK]   {path}")


def main():
    app = create_app()
    for migration in MIGRATIONS:
        _run_file(app, migration)
    print("\nAll migrations applied.")


if __name__ == "__main__":
    main()
