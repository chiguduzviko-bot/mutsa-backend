"""Seed script: creates admin@example.com (ADMIN) and auditor@example.com (AUDITOR).
Run from project root:
    python scripts/seed_admin_user.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models.user import User, UserRole

SEED_USERS = [
    {
        "email": "admin@example.com",
        "full_name": "System Admin",
        "employee_number": "ADM-0001",
        "password": "Admin@12345",
        "role": UserRole.ADMIN,
    },
    {
        "email": "auditor@example.com",
        "full_name": "System Auditor",
        "employee_number": "AUD-0001",
        "password": "Auditor@12345",
        "role": UserRole.AUDITOR,
    },
]


def seed():
    app = create_app()
    with app.app_context():
        for spec in SEED_USERS:
            existing = User.query.filter_by(email=spec["email"]).first()
            if existing:
                existing.role = spec["role"]
                existing.full_name = spec["full_name"]
                existing.employee_number = existing.employee_number or spec["employee_number"]
                existing.set_password(spec["password"])
                db.session.commit()
                print(f"[updated] {spec['email']}  role={spec['role'].value}")
            else:
                user = User(
                    employee_number=spec["employee_number"],
                    full_name=spec["full_name"],
                    email=spec["email"],
                    role=spec["role"],
                    is_active=True,
                )
                user.set_password(spec["password"])
                db.session.add(user)
                db.session.commit()
                print(f"[created] {spec['email']}  role={spec['role'].value}")
        print("\nSeed credentials:")
        for spec in SEED_USERS:
            print(f"  {spec['role'].value:<10}  {spec['email']}  /  {spec['password']}")


if __name__ == "__main__":
    seed()
